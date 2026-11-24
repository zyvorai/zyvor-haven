// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package upstreamtest is a fake upstream OIDC provider for tests: TLS
// discovery, JWKS with key rotation, an authorization endpoint driven by the
// test, and a token endpoint that returns really signed ID tokens, with knobs
// to produce every kind of bad token.
package upstreamtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// SignOpts tunes how the next ID tokens are signed.
type SignOpts struct {
	Alg          string // default RS256; also ES256, PS256, none, HS256
	KID          string // header kid; default the active key's
	BadSignature bool   // flip a byte of the signature
	HMACKey      []byte // HS256 secret (the attack uses the public key bytes)
}

type key struct {
	kid string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

type issued struct {
	claims      map[string]any
	challenge   string
	redirectURI string
	nonce       string
	clientID    string
}

// IdP is the fake provider. Fields marked "knob" may be changed by a test.
type IdP struct {
	Srv  *httptest.Server
	Pool *x509.CertPool

	ClientID     string
	ClientSecret string
	RedirectURIs []string

	// Knobs.
	Sign            SignOpts
	ClaimsHook      func(claims map[string]any) // edit the claims of the next token
	DiscoveryIssuer string                      // override the issuer in the discovery document
	TokenEndpoint   string                      // override token_endpoint in discovery
	TokenDelay      time.Duration               // block the token endpoint (timeout tests)
	AuthMethods     []string                    // token_endpoint_auth_methods_supported
	Now             func() time.Time            // time source for iat/exp
	TokenStatus     int                         // force this status from the token endpoint

	TokenHits, DiscoveryHits, JWKSHits atomic.Int32
	LastAuthMethod                     atomic.Value // "basic" | "post"

	mu     sync.Mutex
	keys   []*key
	active int
	codes  map[string]*issued
	done   chan struct{}
}

// New starts the provider with an RSA key "k1".
func New(t testing.TB) *IdP {
	t.Helper()
	i := &IdP{ClientID: "haven-broker", ClientSecret: "upstream-client-secret-0123456789",
		RedirectURIs: nil, Now: time.Now, codes: map[string]*issued{}, done: make(chan struct{})}
	i.AddRSAKey("k1")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", i.discovery)
	mux.HandleFunc("/jwks", i.jwks)
	mux.HandleFunc("/token", i.token)
	i.Srv = httptest.NewTLSServer(mux)
	t.Cleanup(i.Srv.Close)
	t.Cleanup(func() { close(i.done) }) // runs first: releases delayed handlers
	i.Pool = x509.NewCertPool()
	i.Pool.AddCert(i.Srv.Certificate())
	return i
}

// URL is the issuer.
func (i *IdP) URL() string { return i.Srv.URL }

// AddRSAKey adds a key and makes it the active signer.
func (i *IdP) AddRSAKey(kid string) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = append(i.keys, &key{kid: kid, rsa: k})
	i.active = len(i.keys) - 1
}

// AddECKey adds an ES256 key (not made active for RS256 signing).
func (i *IdP) AddECKey(kid string) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys = append(i.keys, &key{kid: kid, ec: k})
}

// Retire removes a key from the JWKS (key rotation: the old key disappears).
func (i *IdP) Retire(kid string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	var keep []*key
	for _, k := range i.keys {
		if k.kid != kid {
			keep = append(keep, k)
		}
	}
	i.keys = keep
	i.active = len(keep) - 1
}

// RSAPublicPEMDER returns the DER (PKIX) of the first RSA key, the bytes used
// in the HS256 key-confusion attack.
func (i *IdP) RSAPublicDER() []byte {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, k := range i.keys {
		if k.rsa != nil {
			b, _ := x509.MarshalPKIXPublicKey(&k.rsa.PublicKey)
			return b
		}
	}
	return nil
}

func (i *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	i.DiscoveryHits.Add(1)
	iss := i.Srv.URL
	if i.DiscoveryIssuer != "" {
		iss = i.DiscoveryIssuer
	}
	tok := i.Srv.URL + "/token"
	if i.TokenEndpoint != "" {
		tok = i.TokenEndpoint
	}
	doc := map[string]any{
		"issuer": iss, "authorization_endpoint": i.Srv.URL + "/authorize",
		"token_endpoint": tok, "jwks_uri": i.Srv.URL + "/jwks",
	}
	if i.AuthMethods != nil {
		doc["token_endpoint_auth_methods_supported"] = i.AuthMethods
	}
	_ = json.NewEncoder(w).Encode(doc)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (i *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	i.JWKSHits.Add(1)
	i.mu.Lock()
	defer i.mu.Unlock()
	var ks []map[string]any
	for _, k := range i.keys {
		switch {
		case k.rsa != nil:
			ks = append(ks, map[string]any{"kty": "RSA", "kid": k.kid, "use": "sig",
				"n": b64(k.rsa.N.Bytes()), "e": b64(big.NewInt(int64(k.rsa.E)).Bytes())})
		case k.ec != nil:
			ks = append(ks, map[string]any{"kty": "EC", "kid": k.kid, "use": "sig", "alg": "ES256", "crv": "P-256",
				"x": b64(pad32(k.ec.X)), "y": b64(pad32(k.ec.Y))})
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": ks})
}

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	for len(b) < 32 {
		b = append([]byte{0}, b...)
	}
	return b
}

// Authorize plays the user's visit to the upstream: it validates the broker's
// authorization request (the URL the broker redirected to), "signs the user
// in" as claims, and returns the URL the browser is redirected back to.
func (i *IdP) Authorize(authURL string, claims map[string]any) (string, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != i.ClientID {
		return "", fmt.Errorf("bad authorization request: %v", q)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		return "", fmt.Errorf("missing pkce/nonce/state: %v", q)
	}
	ru := q.Get("redirect_uri")
	ok := len(i.RedirectURIs) == 0
	for _, r := range i.RedirectURIs {
		ok = ok || r == ru
	}
	if !ok {
		return "", fmt.Errorf("redirect_uri %q not registered", ru)
	}
	code := b64(randBytes(24))
	c := map[string]any{}
	for k, v := range claims {
		c[k] = v
	}
	i.mu.Lock()
	i.codes[code] = &issued{claims: c, challenge: q.Get("code_challenge"), redirectURI: ru, nonce: q.Get("nonce"), clientID: q.Get("client_id")}
	i.mu.Unlock()
	back, _ := url.Parse(ru)
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	return back.String(), nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func (i *IdP) token(w http.ResponseWriter, r *http.Request) {
	i.TokenHits.Add(1)
	if i.TokenDelay > 0 {
		select {
		case <-time.After(i.TokenDelay):
		case <-r.Context().Done():
			return
		case <-i.done:
			return
		}
	}
	if i.TokenStatus != 0 {
		http.Error(w, `{"error":"server_error"}`, i.TokenStatus)
		return
	}
	_ = r.ParseForm()
	id, secret, basic := r.BasicAuth()
	if basic {
		i.LastAuthMethod.Store("basic")
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		i.LastAuthMethod.Store("post")
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != i.ClientID || !hmac.Equal([]byte(secret), []byte(i.ClientSecret)) {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	i.mu.Lock()
	is := i.codes[r.PostForm.Get("code")]
	delete(i.codes, r.PostForm.Get("code"))
	i.mu.Unlock()
	if is == nil || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != is.redirectURI {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if b64(sum[:]) != is.challenge {
		http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, http.StatusBadRequest)
		return
	}
	now := i.Now()
	claims := map[string]any{
		"iss": i.Srv.URL, "aud": i.ClientID, "sub": "up-sub-1", "nonce": is.nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range is.claims {
		claims[k] = v
	}
	if i.ClaimsHook != nil {
		i.ClaimsHook(claims)
	}
	tok := i.mint(claims)
	// #nosec G101 -- test IdP answering with a throwaway opaque token
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "opaque-upstream-access", "token_type": "Bearer", "id_token": tok})
}

// Mint signs claims with the current SignOpts (exported for unit tests).
func (i *IdP) Mint(claims map[string]any) string { return i.mint(claims) }

func (i *IdP) mint(claims map[string]any) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	alg := i.Sign.Alg
	if alg == "" {
		alg = "RS256"
	}
	var k *key
	for _, c := range i.keys {
		if (alg == "ES256") == (c.ec != nil) && (k == nil || c == i.keys[i.active]) {
			k = c
		}
	}
	kid := i.Sign.KID
	if kid == "" && k != nil {
		kid = k.kid
	}
	hdr := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signed := b64(hb) + "." + b64(cb)
	var sig []byte
	h := sha256.Sum256([]byte(signed))
	switch alg {
	case "none":
	case "HS256":
		m := hmac.New(sha256.New, i.Sign.HMACKey)
		m.Write([]byte(signed))
		sig = m.Sum(nil)
	case "RS256":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, h[:])
	case "PS256":
		sig, _ = rsa.SignPSS(rand.Reader, k.rsa, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, k.ec, h[:])
		sig = append(pad32(r), pad32(s)...)
	}
	if i.Sign.BadSignature && len(sig) > 0 {
		sig[len(sig)/2] ^= 0xff
	}
	return signed + "." + b64(sig)
}
