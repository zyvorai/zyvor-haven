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
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// DPoP: Demonstrating Proof of Possession (RFC 9449). See docs/dpop.md.
//
// A client proves possession of a key by sending a "DPoP" header with every
// token request and every resource request. The token endpoint binds the
// access token (cnf.jkt) and, for public clients, the refresh token to the
// proof key. Everything here fails closed: a proof that is malformed, replayed,
// stale, for another method/URL or signed by a weak key is rejected, a DPoP
// header on a realm whose store cannot remember proofs is rejected, and a
// bound token presented without a matching proof is rejected.

const (
	dpopSkew        = 60 * time.Second // accepted |now - iat|
	dpopMaxHeader   = 4096             // bytes of the DPoP header value
	dpopMaxJTI      = 256
	dpopNonceBucket = 300 // seconds a server nonce stays current (previous one also accepted)
	dpopRatePerIP   = 1200
)

// dpopAlgs are the accepted proof algorithms, in discovery order.
var dpopAlgs = []string{"ES256", "RS256", "EdDSA"}

func init() {
	registerDiscovery(func(p *Provider, realm string, doc map[string]any) {
		if _, ok := p.dpopStore(); ok {
			doc["dpop_signing_alg_values_supported"] = dpopAlgs
		}
	})
}

func (p *Provider) dpopStore() (core.DPoPStore, bool) {
	return core.StoreAs[core.DPoPStore](p.cfg.Store)
}

type dpopErr struct {
	code   string // invalid_dpop_proof | use_dpop_nonce | server_error
	desc   string
	nonce  string // fresh nonce to send with use_dpop_nonce
	status int
}

func badProof(desc string) *dpopErr { return &dpopErr{code: "invalid_dpop_proof", desc: desc} }

type dpopCtxKey struct{}

// dpopJKT is the thumbprint of the key the current token request proved
// possession of; empty when the request carried no DPoP proof.
func dpopJKT(ctx context.Context) string {
	s, _ := ctx.Value(dpopCtxKey{}).(string)
	return s
}

// ---- proof parsing ----

type dpopProof struct {
	jkt   string
	jti   string
	nonce string
}

func dpopB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// jwkThumbprint is the RFC 7638 SHA-256 thumbprint (base64url).
func jwkThumbprint(kty string, members map[string]string) string {
	var order []string
	switch kty {
	case "EC":
		order = []string{"crv", "kty", "x", "y"}
	case "RSA":
		order = []string{"e", "kty", "n"}
	default: // OKP
		order = []string{"crv", "kty", "x"}
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range order {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(members[k])
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
	}
	buf.WriteByte('}')
	sum := sha256.Sum256(buf.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// dpopKey turns the proof's jwk into a verifier. alg and key type must agree.
func dpopKey(alg string, raw json.RawMessage) (verify func(signed, sig []byte) bool, jkt string, err *dpopErr) {
	var jwk map[string]any
	if e := json.Unmarshal(raw, &jwk); e != nil || jwk == nil {
		return nil, "", badProof("jwk is not an object")
	}
	for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, has := jwk[priv]; has {
			return nil, "", badProof("jwk must be a public key")
		}
	}
	str := func(k string) string { s, _ := jwk[k].(string); return s }
	kty := str("kty")
	switch {
	case kty == "EC" && alg == "ES256":
		x, e1 := dpopB64(str("x"))
		y, e2 := dpopB64(str("y"))
		if str("crv") != "P-256" || e1 != nil || e2 != nil || len(x) != 32 || len(y) != 32 {
			return nil, "", badProof("unsupported EC key")
		}
		pub, perr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if perr != nil {
			return nil, "", badProof("EC key is not on the curve")
		}
		jkt = jwkThumbprint("EC", map[string]string{"crv": "P-256", "kty": "EC", "x": str("x"), "y": str("y")})
		return func(signed, sig []byte) bool {
			if len(sig) != 64 {
				return false
			}
			h := sha256.Sum256(signed)
			return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		}, jkt, nil
	case kty == "RSA" && alg == "RS256":
		nb, e1 := dpopB64(str("n"))
		eb, e2 := dpopB64(str("e"))
		if e1 != nil || e2 != nil || len(nb) == 0 || nb[0] == 0 || len(eb) == 0 || len(eb) > 4 {
			return nil, "", badProof("unsupported RSA key")
		}
		n := new(big.Int).SetBytes(nb)
		e := int(new(big.Int).SetBytes(eb).Int64())
		if n.BitLen() < 2048 || n.BitLen() > 8192 || e < 3 || e%2 == 0 {
			return nil, "", badProof("RSA key is too small or malformed")
		}
		pub := &rsa.PublicKey{N: n, E: e}
		jkt = jwkThumbprint("RSA", map[string]string{"e": str("e"), "kty": "RSA", "n": str("n")})
		return func(signed, sig []byte) bool {
			h := sha256.Sum256(signed)
			return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil
		}, jkt, nil
	case kty == "OKP" && alg == "EdDSA":
		x, e1 := dpopB64(str("x"))
		if str("crv") != "Ed25519" || e1 != nil || len(x) != ed25519.PublicKeySize {
			return nil, "", badProof("unsupported OKP key")
		}
		pub := ed25519.PublicKey(x)
		jkt = jwkThumbprint("OKP", map[string]string{"crv": "Ed25519", "kty": "OKP", "x": str("x")})
		return func(signed, sig []byte) bool { return ed25519.Verify(pub, signed, sig) }, jkt, nil
	}
	return nil, "", badProof("jwk does not match alg")
}

// dpopURL normalises a URL for the htu comparison: scheme and host lowercase,
// no query, no fragment. ok is false for anything with userinfo or no host.
func dpopURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", false
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.EscapedPath(), true
}

// dpopNonce is a stateless server nonce (HMAC of realm and a 5 minute bucket).
func (p *Provider) dpopNonce(realm string, bucket int64) string {
	m := hmac.New(sha256.New, p.csrfKey)
	m.Write([]byte("dpop-nonce|" + realm + "|" + strconv.FormatInt(bucket, 10)))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

func (p *Provider) currentDPoPNonce(realm string) string {
	return p.dpopNonce(realm, p.now().Unix()/dpopNonceBucket)
}

func (p *Provider) validDPoPNonce(realm, got string) bool {
	b := p.now().Unix() / dpopNonceBucket
	ok := 0
	for _, c := range []int64{b, b - 1} {
		ok |= subtle.ConstantTimeCompare([]byte(got), []byte(p.dpopNonce(realm, c)))
	}
	return ok == 1
}

// checkDPoP validates the request's DPoP proof for htu (the absolute URL of
// the endpoint being called). When accessToken is non-empty the proof must
// carry the matching ath (resource requests). The proof is remembered so it
// works once.
func (p *Provider) checkDPoP(r *http.Request, realm, htu, accessToken string) (dpopProof, *dpopErr) {
	var out dpopProof
	st, ok := p.dpopStore()
	if !ok {
		return out, badProof("DPoP is not available")
	}
	vals := r.Header.Values("DPoP")
	if len(vals) != 1 || vals[0] == "" || len(vals[0]) > dpopMaxHeader {
		return out, badProof("exactly one DPoP proof is required")
	}
	parts := strings.Split(vals[0], ".")
	if len(parts) != 3 {
		return out, badProof("proof is not a compact JWS")
	}
	hb, e1 := dpopB64(parts[0])
	pb, e2 := dpopB64(parts[1])
	sig, e3 := dpopB64(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return out, badProof("proof is not base64url")
	}
	var hdr struct {
		Typ  string          `json:"typ"`
		Alg  string          `json:"alg"`
		JWK  json.RawMessage `json:"jwk"`
		Crit json.RawMessage `json:"crit"`
	}
	if json.Unmarshal(hb, &hdr) != nil || hdr.Typ != "dpop+jwt" || len(hdr.JWK) == 0 || len(hdr.Crit) != 0 {
		return out, badProof("proof header is invalid")
	}
	algOK := false
	for _, a := range dpopAlgs {
		algOK = algOK || a == hdr.Alg
	}
	if !algOK {
		return out, badProof("proof alg is not supported")
	}
	verify, jkt, derr := dpopKey(hdr.Alg, hdr.JWK)
	if derr != nil {
		return out, derr
	}
	if !verify([]byte(parts[0]+"."+parts[1]), sig) {
		return out, badProof("proof signature is invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	var c struct {
		JTI   string      `json:"jti"`
		HTM   string      `json:"htm"`
		HTU   string      `json:"htu"`
		IAT   json.Number `json:"iat"`
		Ath   string      `json:"ath"`
		Nonce string      `json:"nonce"`
	}
	if dec.Decode(&c) != nil {
		return out, badProof("proof claims are invalid")
	}
	if c.JTI == "" || len(c.JTI) > dpopMaxJTI {
		return out, badProof("jti is missing or too long")
	}
	if c.HTM != r.Method {
		return out, badProof("htm does not match the request method")
	}
	want, _ := dpopURL(htu)
	if got, ok := dpopURL(c.HTU); !ok || want == "" || got != want {
		return out, badProof("htu does not match the request URL")
	}
	iat, err := c.IAT.Float64()
	if err != nil || c.IAT == "" {
		return out, badProof("iat is missing")
	}
	d := p.now().Sub(time.Unix(int64(iat), 0))
	if d > dpopSkew || d < -dpopSkew {
		return out, badProof("iat is outside the accepted window")
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if subtle.ConstantTimeCompare([]byte(c.Ath), []byte(base64.RawURLEncoding.EncodeToString(sum[:]))) != 1 {
			return out, badProof("ath does not match the access token")
		}
	}
	if p.cfg.DPoPNonce && !p.validDPoPNonce(realm, c.Nonce) {
		return out, &dpopErr{code: "use_dpop_nonce", desc: "the server requires a DPoP nonce", nonce: p.currentDPoPNonce(realm)}
	}
	// The signature is good: now it may cost storage. Cap how many proofs one
	// address may have remembered per window (fail closed on a limiter error).
	allowed, err := p.hitLimit(r.Context(), "dpop", realm, p.clientIP(r), dpopRatePerIP)
	if err != nil {
		p.cfg.Logger.Error("oidc: dpop rate limit", "err", err)
		return out, &dpopErr{code: "server_error", desc: "temporary error", status: http.StatusInternalServerError}
	}
	if !allowed {
		return out, &dpopErr{code: "invalid_dpop_proof", desc: "too many proofs", status: http.StatusTooManyRequests}
	}
	h := sha256.Sum256([]byte(jkt + "|" + c.JTI))
	switch err := st.RememberDPoPProof(r.Context(), realm, hex.EncodeToString(h[:]), p.now(), p.now().Add(2*dpopSkew+time.Second)); {
	case err == nil:
	case errors.Is(err, idp.ErrConflict):
		return out, badProof("proof was already used")
	default:
		p.cfg.Logger.Error("oidc: dpop remember proof", "err", err)
		return out, &dpopErr{code: "server_error", desc: "temporary error", status: http.StatusInternalServerError}
	}
	return dpopProof{jkt: jkt, jti: c.JTI, nonce: c.Nonce}, nil
}

// ---- token endpoint ----

func (e *dpopErr) tokenErr(w http.ResponseWriter) *tokenErr {
	if e.nonce != "" {
		w.Header().Set("DPoP-Nonce", e.nonce)
	}
	st := e.status
	if st == 0 {
		st = http.StatusBadRequest
	}
	return &tokenErr{st, e.code, e.desc}
}

// dpopToken runs at the token endpoint after client authentication. With a
// proof it validates it and returns a request whose context carries the key
// thumbprint (issue() then binds the access token). A refresh token that is
// bound to a key is only redeemed with a proof from that same key.
func (p *Provider) dpopToken(w http.ResponseWriter, r *http.Request, rl core.Realm) (*http.Request, *tokenErr) {
	hasProof := len(r.Header.Values("DPoP")) > 0
	grant := r.PostForm.Get("grant_type")
	var jkt string
	if hasProof {
		pr, derr := p.checkDPoP(r, rl.Name, p.endpoint(rl.Name, "token"), "")
		if derr != nil {
			return r, derr.tokenErr(w)
		}
		jkt = pr.jkt
		r = r.WithContext(context.WithValue(r.Context(), dpopCtxKey{}, jkt))
	}
	if grant != "refresh_token" {
		return r, nil
	}
	st, ok := p.dpopStore()
	if !ok {
		return r, nil // nothing can be bound without a store
	}
	raw := r.PostForm.Get("refresh_token")
	if raw == "" {
		return r, nil // grantRefresh reports the missing parameter
	}
	bound, err := st.RefreshTokenBinding(r.Context(), HashSecret(raw), p.now())
	switch {
	case errors.Is(err, idp.ErrNotFound):
		return r, nil
	case err != nil:
		p.cfg.Logger.Error("oidc: dpop refresh binding", "err", err)
		return r, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	if jkt == "" {
		return r, badProof("this refresh token is DPoP-bound: a proof is required").tokenErr(w)
	}
	if subtle.ConstantTimeCompare([]byte(bound), []byte(jkt)) != 1 {
		return r, badProof("the proof key does not match the refresh token binding").tokenErr(w)
	}
	return r, nil
}

// dpopTokenDone runs after a successful grant: it binds the refresh token of a
// public client to the proof key (failing the request if that cannot be
// stored, so an unbound refresh token is never handed out) and answers the
// next nonce when nonces are on.
func (p *Provider) dpopTokenDone(w http.ResponseWriter, r *http.Request, rl core.Realm, cl core.Client, resp map[string]any) *tokenErr {
	jkt := dpopJKT(r.Context())
	if jkt == "" {
		return nil
	}
	if p.cfg.DPoPNonce {
		w.Header().Set("DPoP-Nonce", p.currentDPoPNonce(rl.Name))
	}
	rt, _ := resp["refresh_token"].(string)
	if rt == "" || !cl.Public {
		return nil
	}
	st, ok := p.dpopStore()
	if !ok {
		return &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	ttl := defaultRefresh
	if n, ok := resp["refresh_expires_in"].(int); ok && n > 0 {
		ttl = time.Duration(n) * time.Second
	}
	if err := st.BindRefreshToken(r.Context(), HashSecret(rt), jkt, p.now().Add(ttl+time.Hour)); err != nil {
		p.cfg.Logger.Error("oidc: dpop bind refresh", "err", err)
		delete(resp, "refresh_token")
		delete(resp, "refresh_expires_in")
		return &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	return nil
}

// dpopBindClaims adds cnf.jkt to access token claims when the request proved
// a key, and makes the response say token_type DPoP.
func dpopBindClaims(ctx context.Context, claims core.Claims) {
	if jkt := dpopJKT(ctx); jkt != "" {
		claims["cnf"] = map[string]any{"jkt": jkt}
	}
}

func dpopTokenType(ctx context.Context, resp map[string]any) {
	if dpopJKT(ctx) != "" {
		resp["token_type"] = "DPoP"
	}
}

// ---- resource requests (userinfo) ----

// dpopWWW answers a failed DPoP-protected resource request.
func (p *Provider) dpopWWW(w http.ResponseWriter, status int, code string, nonce string) {
	if nonce != "" {
		w.Header().Set("DPoP-Nonce", nonce)
	}
	w.Header().Add("WWW-Authenticate", `DPoP error="`+code+`", algs="`+strings.Join(dpopAlgs, " ")+`"`)
	writeJSON(w, status, map[string]string{"error": code})
}

// dpopResource enforces sender constraint for an access token that already
// passed verifyAccess. It returns false after writing the response. A token
// with cnf must arrive with the DPoP scheme and a proof (with ath) from the
// bound key; a token without cnf must not use the DPoP scheme.
func (p *Provider) dpopResource(w http.ResponseWriter, r *http.Request, realm string, c core.Claims, scheme, tok, htu string) bool {
	isDPoP := strings.EqualFold(scheme, "DPoP")
	cnfRaw, hasCnf := c["cnf"]
	if !hasCnf {
		if isDPoP {
			p.dpopWWW(w, http.StatusUnauthorized, "invalid_token", "")
			return false
		}
		return true
	}
	var want string
	if m, ok := cnfRaw.(map[string]any); ok {
		want, _ = m["jkt"].(string)
	}
	if want == "" { // a cnf we cannot interpret is never ignored
		p.dpopWWW(w, http.StatusUnauthorized, "invalid_token", "")
		return false
	}
	if !isDPoP {
		p.dpopWWW(w, http.StatusUnauthorized, "invalid_token", "")
		return false
	}
	pr, derr := p.checkDPoP(r, realm, htu, tok)
	if derr != nil {
		st := http.StatusUnauthorized
		if derr.status != 0 {
			st = derr.status
		}
		p.dpopWWW(w, st, derr.code, derr.nonce)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(pr.jkt), []byte(want)) != 1 {
		p.dpopWWW(w, http.StatusUnauthorized, "invalid_token", "")
		return false
	}
	return true
}

// dpopRefreshCnf is the cnf member of a bound refresh token for introspection
// (nil when the token is not bound; an error when the store cannot say, which
// introspection answers as inactive).
func (p *Provider) dpopRefreshCnf(ctx context.Context, rawToken string) (map[string]any, error) {
	st, ok := p.dpopStore()
	if !ok {
		return nil, nil
	}
	jkt, err := st.RefreshTokenBinding(ctx, HashSecret(rawToken), p.now())
	if errors.Is(err, idp.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"jkt": jkt}, nil
}
