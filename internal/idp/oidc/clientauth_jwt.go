// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
)

// Client keys (inline jwks or an https jwks_uri) and the verification of
// client assertions (private_key_jwt, RFC 7523 and OIDC Core section 9).
//
// The key comes only from the client's registration: jwk, jku and x5u headers
// of an assertion are ignored. A jwks_uri is fetched with the SSRF-safe client
// (no redirects, destination checked at dial time, no proxy), is size and time
// limited, cached, and refetched at most once per jwksMinGap however many
// unknown key ids arrive.

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" // #nosec G101 -- RFC 7523 URN, not a credential

	caMaxAssertion = 8 << 10
	caSkew         = 60 * time.Second
	caMaxLifetime  = 10 * time.Minute // how far ahead exp may be, and exp - iat
	caMaxJTI       = 256

	jwksMaxBody    = 64 << 10
	jwksMaxKeys    = 20
	jwksMaxURI     = 2048
	jwksTTL        = 5 * time.Minute
	jwksMinGap     = 30 * time.Second // between two fetches of one jwks_uri
	jwksTimeout    = 5 * time.Second
	jwksMaxEntries = 512
)

// clientAssertionAlgs are the accepted assertion algorithms, in discovery
// order. "none" and the symmetric algorithms are never accepted.
var clientAssertionAlgs = []string{"ES256", "PS256", "RS256", "EdDSA"}

// clientKey is one usable entry of a client's key set.
type clientKey struct {
	kid, alg string
	pub      any    // *ecdsa.PublicKey | *rsa.PublicKey | ed25519.PublicKey; nil if not usable for signatures
	cert     []byte // DER of x5c[0], for self_signed_tls_client_auth; nil if absent
}

var errClientJWKS = errors.New("unusable key set")

// parseClientJWKS reads the public keys of a JWKS. private reports that some
// entry carried private key members (such an entry is never used).
func parseClientJWKS(raw []byte) (keys []clientKey, private bool, err error) {
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if len(raw) == 0 || len(raw) > jwksMaxBody || json.Unmarshal(raw, &doc) != nil {
		return nil, false, errClientJWKS
	}
	if len(doc.Keys) > jwksMaxKeys {
		doc.Keys = doc.Keys[:jwksMaxKeys]
	}
	for _, k := range doc.Keys {
		str := func(n string) string { s, _ := k[n].(string); return s }
		secret := false
		for _, m := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, has := k[m]; has {
				secret = true
			}
		}
		if secret {
			private = true
			continue
		}
		if u := str("use"); u != "" && u != "sig" {
			continue
		}
		if ops, has := k["key_ops"]; has {
			l, _ := ops.([]any)
			if !slices.Contains(l, any("verify")) {
				continue
			}
		}
		ck := clientKey{kid: str("kid"), alg: str("alg"), pub: publicFromJWK(str)}
		if chain, _ := k["x5c"].([]any); len(chain) > 0 {
			s, _ := chain[0].(string)
			if der, derr := base64.StdEncoding.DecodeString(s); derr == nil {
				if c, perr := x509.ParseCertificate(der); perr == nil && strongPublicKey(c.PublicKey) {
					ck.cert = der
				}
			}
		}
		if ck.pub != nil || ck.cert != nil {
			keys = append(keys, ck)
		}
	}
	if len(keys) == 0 {
		return nil, private, errClientJWKS
	}
	return keys, private, nil
}

// publicFromJWK returns the signature verification key of a JWK, or nil.
func publicFromJWK(str func(string) string) any {
	dec := base64.RawURLEncoding.DecodeString
	switch str("kty") {
	case "EC":
		x, e1 := dec(str("x"))
		y, e2 := dec(str("y"))
		if str("crv") != "P-256" || e1 != nil || e2 != nil || len(x) != 32 || len(y) != 32 {
			return nil
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil
		}
		return pub
	case "RSA":
		nb, e1 := dec(str("n"))
		eb, e2 := dec(str("e"))
		if e1 != nil || e2 != nil || len(nb) == 0 || nb[0] == 0 || len(eb) == 0 || len(eb) > 4 {
			return nil
		}
		n := new(big.Int).SetBytes(nb)
		e := int(new(big.Int).SetBytes(eb).Int64())
		if n.BitLen() < 2048 || n.BitLen() > 8192 || e < 3 || e%2 == 0 {
			return nil
		}
		return &rsa.PublicKey{N: n, E: e}
	case "OKP":
		x, err := dec(str("x"))
		if str("crv") != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
			return nil
		}
		return ed25519.PublicKey(x)
	}
	return nil
}

// strongPublicKey is the floor for a certificate's key.
func strongPublicKey(pub any) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048 && k.N.BitLen() <= 8192
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	}
	return false
}

// ---- jwks_uri cache ----

type jwksEntry struct {
	mu        sync.Mutex // held across a fetch: concurrent requests share it
	keys      []clientKey
	fetched   time.Time
	attempted time.Time
}

type jwksState struct {
	mu      sync.Mutex
	http    *safehttp.Client
	entries map[string]*jwksEntry
}

var jwksStates sync.Map // *Provider -> *jwksState

func (p *Provider) jwksCache() *jwksState {
	v, _ := jwksStates.LoadOrStore(p, &jwksState{entries: map[string]*jwksEntry{}})
	return v.(*jwksState)
}

func (p *Provider) allowPrivateFetch() bool {
	return p.cfg.Federation != nil && p.cfg.Federation.AllowPrivate()
}

func (s *jwksState) entry(uri string, allowPrivate bool) (*jwksEntry, *safehttp.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.http == nil {
		s.http = safehttp.New(safehttp.Options{AllowPrivate: allowPrivate, MaxBody: jwksMaxBody, Timeout: jwksTimeout})
	}
	e := s.entries[uri]
	if e == nil {
		if len(s.entries) >= jwksMaxEntries { // only registered URIs get here; keep it bounded anyway
			s.entries = map[string]*jwksEntry{}
		}
		e = &jwksEntry{}
		s.entries[uri] = e
	}
	return e, s.http
}

// clientKeys returns the client's keys. has reports whether a key set contains
// what the caller is looking for; when a cached set does not, it is refetched,
// but never more often than once per jwksMinGap. A set older than jwksTTL is
// never used: if it cannot be refreshed the call fails.
func (p *Provider) clientKeys(ctx context.Context, cfg core.ClientAuth, has func([]clientKey) bool) ([]clientKey, error) {
	switch {
	case cfg.JWKS != "" && cfg.JWKSURI == "":
		keys, _, err := parseClientJWKS([]byte(cfg.JWKS))
		return keys, err
	case cfg.JWKSURI == "" || cfg.JWKS != "":
		return nil, errClientJWKS
	}
	allowPrivate := p.allowPrivateFetch()
	if _, err := safehttp.ValidateURL(cfg.JWKSURI, allowPrivate, "jwks_uri", jwksMaxURI); err != nil {
		return nil, err
	}
	e, hc := p.jwksCache().entry(cfg.JWKSURI, allowPrivate)
	e.mu.Lock()
	defer e.mu.Unlock()
	now := p.now()
	fresh := !e.fetched.IsZero() && now.Sub(e.fetched) < jwksTTL
	if fresh && has(e.keys) {
		return e.keys, nil
	}
	if !e.attempted.IsZero() && now.Sub(e.attempted) < jwksMinGap {
		if fresh {
			return e.keys, nil
		}
		return nil, errors.New("jwks_uri was fetched too recently and has no usable copy")
	}
	e.attempted = now
	keys, err := fetchClientJWKS(ctx, hc, cfg.JWKSURI)
	if err != nil {
		if fresh {
			return e.keys, nil
		}
		return nil, err
	}
	e.keys, e.fetched = keys, now
	return keys, nil
}

func fetchClientJWKS(ctx context.Context, hc *safehttp.Client, uri string) ([]clientKey, error) {
	// A caller that goes away must not turn the shared fetch into a failure.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), jwksTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil) // #nosec G704 -- the registered jwks_uri; the client refuses non-public destinations at dial time and follows no redirects
	if err != nil {
		return nil, errors.New("bad jwks_uri")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "haven-idp-client-jwks")
	st, body, err := hc.Fetch(req)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, errors.New("jwks_uri did not answer 200") // includes refused redirects
	}
	keys, _, err := parseClientJWKS(body)
	return keys, err
}

// ---- the assertion ----

type clientAssertion struct {
	alg, kid string
	signed   []byte
	sig      []byte
	claims   map[string]any
}

// parseAssertion checks the shape of a compact JWS client assertion. Errors are
// short fixed labels for the log.
func parseAssertion(raw string) (*clientAssertion, error) {
	if raw == "" || len(raw) > caMaxAssertion {
		return nil, errors.New("assertion_size")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not_a_jws")
	}
	hb, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil || len(sig) == 0 {
		return nil, errors.New("not_a_jws")
	}
	var hdr struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Typ  string          `json:"typ"`
		Crit json.RawMessage `json:"crit"`
	}
	if json.Unmarshal(hb, &hdr) != nil || hasDupKeys(hb) || len(hdr.Crit) != 0 {
		return nil, errors.New("bad_header")
	}
	if !slices.Contains(clientAssertionAlgs, hdr.Alg) {
		return nil, errors.New("alg_not_allowed")
	}
	// Other signed JWTs a client produces (request objects, DPoP proofs) must
	// not work as credentials.
	if hdr.Typ != "" && !strings.EqualFold(hdr.Typ, "JWT") && !strings.EqualFold(hdr.Typ, "client-authentication+jwt") {
		return nil, errors.New("wrong_typ")
	}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	var c map[string]any
	if dec.Decode(&c) != nil || c == nil || dec.More() || hasDupKeys(pb) {
		return nil, errors.New("bad_claims")
	}
	return &clientAssertion{alg: hdr.Alg, kid: hdr.Kid, signed: []byte(parts[0] + "." + parts[1]), sig: sig, claims: c}, nil
}

func (a *clientAssertion) str(k string) string { s, _ := a.claims[k].(string); return s }

// candidates are the keys that could have signed the assertion: the right key
// type for the alg, a compatible "alg", and the kid when the header names one.
func (a *clientAssertion) candidates(keys []clientKey) []clientKey {
	var out []clientKey
	for _, k := range keys {
		var fits bool
		switch k.pub.(type) {
		case *ecdsa.PublicKey:
			fits = a.alg == "ES256"
		case *rsa.PublicKey:
			fits = a.alg == "PS256" || a.alg == "RS256"
		case ed25519.PublicKey:
			fits = a.alg == "EdDSA"
		}
		if !fits || (k.alg != "" && k.alg != a.alg) || (a.kid != "" && k.kid != a.kid) {
			continue
		}
		out = append(out, k)
	}
	return out
}

// verify checks the signature. Without a kid exactly one key may fit.
func (a *clientAssertion) verify(keys []clientKey) bool {
	c := a.candidates(keys)
	if len(c) == 0 || (a.kid == "" && len(c) != 1) {
		return false
	}
	for _, k := range c {
		if verifyAssertionSig(a.alg, k.pub, a.signed, a.sig) {
			return true
		}
	}
	return false
}

func verifyAssertionSig(alg string, pub any, signed, sig []byte) bool {
	h := sha256.Sum256(signed)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 {
			return false
		}
		return ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case *rsa.PublicKey:
		switch alg {
		case "PS256":
			return rsa.VerifyPSS(k, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		case "RS256":
			return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
		}
	case ed25519.PublicKey:
		return alg == "EdDSA" && ed25519.Verify(k, signed, sig)
	}
	return false
}

// checkClaims enforces the claim rules and returns the jti and expiry.
func (a *clientAssertion) checkClaims(clientID string, auds []string, now time.Time) (jti string, exp time.Time, err error) {
	bad := func(s string) (string, time.Time, error) { return "", time.Time{}, errors.New(s) }
	if clientID == "" || a.str("iss") != clientID || a.str("sub") != clientID {
		return bad("iss_sub")
	}
	// Every audience value must name this server: an assertion that is also
	// addressed to someone else could be replayed to us by them.
	switch v := a.claims["aud"].(type) {
	case string:
		if !slices.Contains(auds, v) {
			return bad("aud")
		}
	case []any:
		if len(v) == 0 {
			return bad("aud")
		}
		for _, x := range v {
			if s, ok := x.(string); !ok || !slices.Contains(auds, s) {
				return bad("aud")
			}
		}
	default:
		return bad("aud")
	}
	exp, ok := jarTime(a.claims["exp"])
	if !ok {
		return bad("no_exp")
	}
	if !now.Before(exp.Add(caSkew)) {
		return bad("expired")
	}
	if exp.After(now.Add(caMaxLifetime + caSkew)) {
		return bad("lifetime_too_long")
	}
	for _, k := range []string{"iat", "nbf"} {
		v, has := a.claims[k]
		if !has {
			continue
		}
		t, ok := jarTime(v)
		if !ok || t.After(now.Add(caSkew)) {
			return bad(k)
		}
		if k == "iat" && exp.Sub(t) > caMaxLifetime {
			return bad("lifetime_too_long")
		}
	}
	jti = a.str("jti")
	if jti == "" || len(jti) > caMaxJTI {
		return bad("jti")
	}
	for _, k := range []string{"response_type", "redirect_uri", "request", "htm", "htu"} {
		if _, has := a.claims[k]; has {
			return bad("not_a_client_assertion")
		}
	}
	return jti, exp, nil
}
