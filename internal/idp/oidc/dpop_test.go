// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// ---- proof builder ----

type dkey struct {
	alg  string
	priv any
	jwk  map[string]any
	jkt  string
}

func padTo(b []byte, n int) []byte { return append(make([]byte, n-len(b)), b...) }

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newES(t *testing.T) *dkey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := b64u(padTo(k.X.Bytes(), 32)), b64u(padTo(k.Y.Bytes(), 32))
	return &dkey{"ES256", k, map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y},
		jwkThumbprint("EC", map[string]string{"crv": "P-256", "kty": "EC", "x": x, "y": y})}
}

func newRS(t *testing.T, bits int) *dkey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	n, e := b64u(k.N.Bytes()), b64u(big.NewInt(int64(k.E)).Bytes())
	return &dkey{"RS256", k, map[string]any{"kty": "RSA", "n": n, "e": e},
		jwkThumbprint("RSA", map[string]string{"e": e, "kty": "RSA", "n": n})}
}

func newEd(t *testing.T) *dkey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := b64u(pub)
	return &dkey{"EdDSA", priv, map[string]any{"kty": "OKP", "crv": "Ed25519", "x": x},
		jwkThumbprint("OKP", map[string]string{"crv": "Ed25519", "kty": "OKP", "x": x})}
}

// pOpt overrides parts of a proof; zero values mean "valid default".
type pOpt struct {
	htm, htu, jti, ath, nonce string
	iat                       *int64
	typ, alg                  string
	jwk                       map[string]any // header jwk override
	dropJTI, dropHTM          bool
	signWith                  *dkey // sign with another key than k
	badSig                    bool
}

const tokenURL = idpBase + "/realms/r/protocol/openid-connect/token"

func (e *denv) proof(t *testing.T, k *dkey, o pOpt) string {
	t.Helper()
	hdr := map[string]any{"typ": "dpop+jwt", "alg": k.alg, "jwk": k.jwk}
	if o.typ != "" {
		hdr["typ"] = o.typ
	}
	if o.alg != "" {
		hdr["alg"] = o.alg
	}
	if o.jwk != nil {
		hdr["jwk"] = o.jwk
	}
	iat := e.now.Unix()
	if o.iat != nil {
		iat = *o.iat
	}
	cl := map[string]any{"jti": fmt.Sprintf("jti-%d", proofCtr.Add(1)), "htm": "POST", "htu": tokenURL, "iat": iat}
	if o.jti != "" {
		cl["jti"] = o.jti
	}
	if o.htm != "" {
		cl["htm"] = o.htm
	}
	if o.htu != "" {
		cl["htu"] = o.htu
	}
	if o.ath != "" {
		cl["ath"] = o.ath
	}
	if o.nonce != "" {
		cl["nonce"] = o.nonce
	}
	if o.dropJTI {
		delete(cl, "jti")
	}
	if o.dropHTM {
		delete(cl, "htm")
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(cl)
	signed := b64u(hb) + "." + b64u(cb)
	sk := k
	if o.signWith != nil {
		sk = o.signWith
	}
	var sig []byte
	switch priv := sk.priv.(type) {
	case *ecdsa.PrivateKey:
		h := sha256.Sum256([]byte(signed))
		r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = append(padTo(r.Bytes(), 32), padTo(s.Bytes(), 32)...)
	case *rsa.PrivateKey:
		h := sha256.Sum256([]byte(signed))
		var err error
		if sig, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:]); err != nil {
			t.Fatal(err)
		}
	case ed25519.PrivateKey:
		sig = ed25519.Sign(priv, []byte(signed))
	}
	if o.badSig {
		sig[0] ^= 0xff
	}
	return signed + "." + b64u(sig)
}

var proofCtr atomic.Int64

func atHash(at string) string { s := sha256.Sum256([]byte(at)); return b64u(s[:]) }

// ---- request helpers ----

func (e *denv) addSvc() {
	e.t.Helper()
	if err := e.st.CreateClient(context.Background(), core.Client{Realm: "r", ClientID: "svc", Enabled: true,
		SecretHash: HashSecret("s3cret"), ServiceAccount: true}); err != nil {
		e.t.Fatal(err)
	}
}

// tok posts to the token endpoint with the given DPoP header values.
func (e *denv) tok(form url.Values, user, pass string, proofs ...string) (int, map[string]any, http.Header) {
	req := httptest.NewRequest("POST", "/realms/r/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	req.RemoteAddr = "203.0.113.7:1"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Header()
}

func (e *denv) cc(proofs ...string) (int, map[string]any, http.Header) {
	return e.tok(url.Values{"grant_type": {"client_credentials"}}, "svc", "s3cret", proofs...)
}

// putCode stores an auth code for the public client "app" and returns the form to redeem it.
func (e *denv) putCode(t *testing.T, scope string) url.Values {
	t.Helper()
	code := fmt.Sprintf("code-%d", proofCtr.Add(1))
	err := e.st.PutAuthCode(context.Background(), core.AuthCode{CodeHash: HashSecret(code), Realm: "r", ClientID: "app",
		UserID: "u1", RedirectURI: cb, Scope: scope, CodeChallenge: challenge(verifier), ChallengeMeth: "S256",
		AuthTime: e.now, ExpiresAt: e.now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb},
		"client_id": {"app"}, "code_verifier": {verifier}}
}

func (e *denv) codeTok(t *testing.T, scope string, proofs ...string) (int, map[string]any, http.Header) {
	return e.tok(e.putCode(t, scope), "", "", proofs...)
}

func (e *denv) refresh(rt string, proofs ...string) (int, map[string]any, http.Header) {
	return e.tok(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"app"}}, "", "", proofs...)
}

func (e *denv) userinfo(scheme, at string, proofs ...string) (int, http.Header) {
	req := httptest.NewRequest("GET", "/realms/r/protocol/openid-connect/userinfo", nil)
	req.Header.Set("Authorization", scheme+" "+at)
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	req.RemoteAddr = "203.0.113.7:1"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w.Code, w.Header()
}

const userinfoURL = idpBase + "/realms/r/protocol/openid-connect/userinfo"

func cnfJKT(t *testing.T, at string) string {
	t.Helper()
	cnf, _ := claimsOf(t, at)["cnf"].(map[string]any)
	s, _ := cnf["jkt"].(string)
	return s
}

// ---- tests ----

func TestDPoPBindsAccessToken(t *testing.T) {
	for _, mk := range []func(*testing.T) *dkey{newES, func(t *testing.T) *dkey { return newRS(t, 2048) }, newEd} {
		k := mk(t)
		t.Run(k.alg, func(t *testing.T) {
			e := newDEnv(t, devOpts{})
			e.addSvc()
			code, out, _ := e.cc(e.proof(t, k, pOpt{}))
			if code != 200 || out["token_type"] != "DPoP" {
				t.Fatalf("%d %v", code, out)
			}
			at := out["access_token"].(string)
			if got := cnfJKT(t, at); got != k.jkt || got == "" {
				t.Fatalf("cnf.jkt = %q, want %q", got, k.jkt)
			}
			// Without a proof the token is an ordinary bearer token.
			code, out, _ = e.cc()
			if code != 200 || out["token_type"] != "Bearer" {
				t.Fatalf("%d %v", code, out)
			}
			if _, has := claimsOf(t, out["access_token"].(string))["cnf"]; has {
				t.Fatal("unproven token carries cnf")
			}
		})
	}
}

func TestDPoPProofRejections(t *testing.T) {
	es := newES(t)
	other := newES(t)
	rs1024 := newRS(t, 1024)
	e := newDEnv(t, devOpts{})
	e.addSvc()
	old, future := e.now.Unix()-120, e.now.Unix()+120
	privJWK := map[string]any{}
	for k, v := range es.jwk {
		privJWK[k] = v
	}
	privJWK["d"] = b64u(make([]byte, 32))
	mismatchJWK := newRS(t, 2048).jwk

	cases := []struct {
		name string
		p    func() string
	}{
		{"wrong htm", func() string { return e.proof(t, es, pOpt{htm: "GET"}) }},
		{"missing htm", func() string { return e.proof(t, es, pOpt{dropHTM: true}) }},
		{"wrong htu path", func() string {
			return e.proof(t, es, pOpt{htu: idpBase + "/realms/r/protocol/openid-connect/userinfo"})
		}},
		{"wrong htu host", func() string {
			return e.proof(t, es, pOpt{htu: "https://evil.example/realms/r/protocol/openid-connect/token"})
		}},
		{"wrong htu scheme", func() string {
			return e.proof(t, es, pOpt{htu: "http://idp.example/realms/r/protocol/openid-connect/token"})
		}},
		{"stale iat", func() string { return e.proof(t, es, pOpt{iat: &old}) }},
		{"future iat", func() string { return e.proof(t, es, pOpt{iat: &future}) }},
		{"missing jti", func() string { return e.proof(t, es, pOpt{dropJTI: true}) }},
		{"wrong typ", func() string { return e.proof(t, es, pOpt{typ: "JWT"}) }},
		{"alg none", func() string { return e.proof(t, es, pOpt{alg: "none"}) }},
		{"alg HS256", func() string { return e.proof(t, es, pOpt{alg: "HS256"}) }},
		{"alg ES384", func() string { return e.proof(t, es, pOpt{alg: "ES384"}) }},
		{"alg/key mismatch", func() string { return e.proof(t, es, pOpt{alg: "RS256"}) }},
		{"jwk is another key type", func() string { return e.proof(t, es, pOpt{jwk: mismatchJWK}) }},
		{"signed by another key", func() string { return e.proof(t, es, pOpt{signWith: other}) }},
		{"corrupt signature", func() string { return e.proof(t, es, pOpt{badSig: true}) }},
		{"private jwk", func() string { return e.proof(t, es, pOpt{jwk: privJWK}) }},
		{"rsa 1024", func() string { return e.proof(t, rs1024, pOpt{}) }},
		{"not a jwt", func() string { return "garbage" }},
		{"empty", func() string { return "" }},
		{"oversized", func() string { return strings.Repeat("a", dpopMaxHeader+1) }},
		{"jti too long", func() string { return e.proof(t, es, pOpt{jti: strings.Repeat("j", dpopMaxJTI+1)}) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, _ := e.cc(c.p())
			if code != 400 || out["error"] != "invalid_dpop_proof" || out["access_token"] != nil {
				t.Fatalf("%d %v", code, out)
			}
		})
	}
	t.Run("two headers", func(t *testing.T) {
		code, out, _ := e.cc(e.proof(t, es, pOpt{}), e.proof(t, es, pOpt{}))
		if code != 400 || out["error"] != "invalid_dpop_proof" {
			t.Fatalf("%d %v", code, out)
		}
	})
	t.Run("htu query is ignored", func(t *testing.T) {
		code, out, _ := e.cc(e.proof(t, es, pOpt{htu: tokenURL + "?x=1#frag"}))
		if code != 200 {
			t.Fatalf("%d %v", code, out)
		}
	})
	t.Run("iat edges", func(t *testing.T) {
		in1, in2 := e.now.Unix()-59, e.now.Unix()+59
		for _, v := range []*int64{&in1, &in2} {
			if code, out, _ := e.cc(e.proof(t, es, pOpt{iat: v})); code != 200 {
				t.Fatalf("%d %v", code, out)
			}
		}
	})
}

func TestDPoPReplay(t *testing.T) {
	e := newDEnv(t, devOpts{})
	e.addSvc()
	k := newES(t)
	p := e.proof(t, k, pOpt{})
	if code, out, _ := e.cc(p); code != 200 {
		t.Fatalf("first: %d %v", code, out)
	}
	code, out, _ := e.cc(p)
	if code != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("replay: %d %v", code, out)
	}
	// The same jti from another key is a different proof; the same key with
	// a fresh jti works.
	if code, _, _ := e.cc(e.proof(t, newES(t), pOpt{jti: "shared"})); code != 200 {
		t.Fatal("other key, jti A")
	}
	if code, _, _ := e.cc(e.proof(t, k, pOpt{jti: "shared"})); code != 200 {
		t.Fatal("jti collision across keys must not block")
	}
	// After the window the cache may forget, but then iat is stale anyway.
	e.advance(10 * time.Minute)
	if code, out, _ := e.cc(p); code != 400 {
		t.Fatalf("replay after expiry: %d %v", code, out)
	}
}

func TestDPoPFailsClosedWithoutStoreSupport(t *testing.T) {
	e := newDEnv(t, devOpts{store: func(s core.Store) core.Store { return struct{ core.Store }{s} }})
	e.addSvc()
	k := newES(t)
	code, out, _ := e.cc(e.proof(t, k, pOpt{}))
	if code != 400 || out["error"] != "invalid_dpop_proof" || out["access_token"] != nil {
		t.Fatalf("DPoP without a store must not mint a token: %d %v", code, out)
	}
	if code, _, _ := e.cc(); code != 200 { // plain bearer flows are unaffected
		t.Fatal("bearer flow broke")
	}
	w := e.browser().do("GET", "/realms/r/.well-known/openid-configuration", nil)
	if strings.Contains(w.Body.String(), "dpop_signing_alg_values_supported") {
		t.Fatal("discovery advertises DPoP without store support")
	}
}

type failingDPoP struct {
	core.Store
	core.DPoPStore
}

func (f failingDPoP) Unwrap() core.Store { return f.Store }
func (failingDPoP) RememberDPoPProof(context.Context, string, string, time.Time, time.Time) error {
	return errors.New("db down")
}

func TestDPoPStoreErrorFailsClosed(t *testing.T) {
	e := newDEnv(t, devOpts{store: func(s core.Store) core.Store {
		ds, _ := core.StoreAs[core.DPoPStore](s)
		return failingDPoP{s, ds}
	}})
	e.addSvc()
	code, out, _ := e.cc(e.proof(t, newES(t), pOpt{}))
	if code != 500 || out["error"] != "server_error" || out["access_token"] != nil {
		t.Fatalf("%d %v", code, out)
	}
	if strings.Contains(fmt.Sprint(out), "db down") {
		t.Fatal("internal error leaked")
	}
}

func TestDPoPRateLimiterDownFailsClosed(t *testing.T) {
	e := newDEnv(t, devOpts{store: func(s core.Store) core.Store { return failLimiter{s} }})
	e.addSvc()
	code, out, _ := e.cc(e.proof(t, newES(t), pOpt{}))
	if code != 500 || out["access_token"] != nil {
		t.Fatalf("%d %v", code, out)
	}
}

func TestDPoPRateLimit(t *testing.T) {
	e := newDEnv(t, devOpts{})
	e.addSvc()
	k := newES(t)
	var last int
	for i := 0; i < dpopRatePerIP+2; i++ {
		last, _, _ = e.cc(e.proof(t, k, pOpt{}))
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after %d proofs: %d", dpopRatePerIP+2, last)
	}
}

func TestDPoPRefreshTokenBinding(t *testing.T) {
	e := newDEnv(t, devOpts{})
	a, b := newES(t), newEd(t)
	code, out, _ := e.codeTok(t, "openid offline_access", e.proof(t, a, pOpt{}))
	if code != 200 || out["token_type"] != "DPoP" || cnfJKT(t, out["access_token"].(string)) != a.jkt {
		t.Fatalf("code exchange: %d %v", code, out)
	}
	rt := out["refresh_token"].(string)

	// No proof, or a proof from another key: refused, and the token survives.
	if code, out, _ := e.refresh(rt); code != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("no proof: %d %v", code, out)
	}
	if code, out, _ := e.refresh(rt, e.proof(t, b, pOpt{})); code != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("other key: %d %v", code, out)
	}
	// Presenting it as a plain bearer refresh token must also fail.
	code, out, _ = e.refresh(rt, e.proof(t, a, pOpt{}))
	if code != 200 || out["token_type"] != "DPoP" || cnfJKT(t, out["access_token"].(string)) != a.jkt {
		t.Fatalf("legit refresh: %d %v", code, out)
	}
	rt2 := out["refresh_token"].(string)
	if rt2 == rt {
		t.Fatal("rotation expected")
	}
	// The rotated token is bound to the same key too.
	if code, out, _ := e.refresh(rt2); code != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("rotated token without proof: %d %v", code, out)
	}
	if code, out, _ := e.refresh(rt2, e.proof(t, b, pOpt{})); code != 400 {
		t.Fatalf("rotated token with other key: %d %v", code, out)
	}
	if code, out, _ := e.refresh(rt2, e.proof(t, a, pOpt{})); code != 200 {
		t.Fatalf("rotated token with its key: %d %v", code, out)
	}
}

func TestDPoPRefreshBindingStoredHashed(t *testing.T) {
	e := newDEnv(t, devOpts{})
	a := newES(t)
	_, out, _ := e.codeTok(t, "openid offline_access", e.proof(t, a, pOpt{}))
	ds, _ := core.StoreAs[core.DPoPStore](e.st)
	if _, err := ds.RefreshTokenBinding(context.Background(), out["refresh_token"].(string), e.now); err == nil {
		t.Fatal("binding is keyed by the raw token")
	}
	if got, err := ds.RefreshTokenBinding(context.Background(), HashSecret(out["refresh_token"].(string)), e.now); err != nil || got != a.jkt {
		t.Fatalf("binding by hash: %q %v", got, err)
	}
}

func TestDPoPUnboundRefreshStillBearer(t *testing.T) {
	e := newDEnv(t, devOpts{})
	_, out, _ := e.codeTok(t, "openid offline_access")
	if out["token_type"] != "Bearer" {
		t.Fatal(out)
	}
	if code, out, _ := e.refresh(out["refresh_token"].(string)); code != 200 || out["token_type"] != "Bearer" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestDPoPUserinfo(t *testing.T) {
	e := newDEnv(t, devOpts{})
	k, other := newES(t), newEd(t)
	_, out, _ := e.codeTok(t, "openid", e.proof(t, k, pOpt{}))
	at := out["access_token"].(string)
	res := func(o pOpt, kk *dkey) string {
		if o.htu == "" {
			o.htu = userinfoURL
		}
		if o.htm == "" {
			o.htm = "GET"
		}
		if o.ath == "" {
			o.ath = atHash(at)
		}
		return e.proof(t, kk, o)
	}
	for _, c := range []struct {
		name   string
		scheme string
		proofs []string
	}{
		{"bearer scheme", "Bearer", nil},
		{"bearer scheme with proof", "Bearer", []string{res(pOpt{}, k)}},
		{"dpop scheme no proof", "DPoP", nil},
		{"no ath", "DPoP", []string{e.proof(t, k, pOpt{htu: userinfoURL, htm: "GET"})}},
		{"wrong ath", "DPoP", []string{res(pOpt{ath: atHash("x")}, k)}},
		{"other key", "DPoP", []string{res(pOpt{}, other)}},
		{"wrong htu", "DPoP", []string{res(pOpt{htu: idpBase + "/realms/r/x"}, k)}},
		{"wrong htm", "DPoP", []string{res(pOpt{htm: "POST"}, k)}},
		{"stale", "DPoP", []string{res(pOpt{iat: new(int64)}, k)}},
		{"two proofs", "DPoP", []string{res(pOpt{}, k), res(pOpt{}, k)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, h := e.userinfo(c.scheme, at, c.proofs...)
			if code != 401 || !strings.Contains(h.Get("WWW-Authenticate"), "DPoP") {
				t.Fatalf("%d %v", code, h)
			}
		})
	}
	good := res(pOpt{}, k)
	if code, _ := e.userinfo("DPoP", at, good); code != 200 {
		t.Fatalf("valid: %d", code)
	}
	if code, _ := e.userinfo("DPoP", at, good); code != 401 { // replay
		t.Fatalf("replayed resource proof: %d", code)
	}
	if code, _ := e.userinfo("dpop", at, res(pOpt{}, k)); code != 200 { // scheme is case-insensitive
		t.Fatalf("lower-case scheme: %d", code)
	}
}

func TestDPoPUserinfoUnboundToken(t *testing.T) {
	e := newDEnv(t, devOpts{})
	k := newES(t)
	_, out, _ := e.codeTok(t, "openid")
	at := out["access_token"].(string)
	if code, _ := e.userinfo("Bearer", at); code != 200 {
		t.Fatalf("bearer: %d", code)
	}
	p := e.proof(t, k, pOpt{htu: userinfoURL, htm: "GET", ath: atHash(at)})
	if code, _ := e.userinfo("DPoP", at, p); code != 401 {
		t.Fatalf("an unbound token must not be accepted under the DPoP scheme: %d", code)
	}
}

func TestDPoPUnreadableCnfRejected(t *testing.T) {
	e := newDEnv(t, devOpts{})
	_, out, _ := e.codeTok(t, "openid")
	c := claimsOf(t, out["access_token"].(string))
	for _, cnf := range []any{"x", map[string]any{}, map[string]any{"jkt": 5}, map[string]any{"jwk": 1}} {
		c["cnf"] = cnf
		b, _ := json.Marshal(c)
		forged := "h." + b64u(b) + ".r"
		if code, _ := e.userinfo("Bearer", forged); code != 401 {
			t.Fatalf("cnf %v accepted as bearer: %d", cnf, code)
		}
	}
}

func TestDPoPIntrospection(t *testing.T) {
	e := newDEnv(t, devOpts{})
	e.addSvc()
	k := newES(t)
	_, out, _ := e.codeTok(t, "openid offline_access", e.proof(t, k, pOpt{}))
	intro := func(tok string) map[string]any {
		req := httptest.NewRequest("POST", "/realms/r/protocol/openid-connect/token/introspect", strings.NewReader(url.Values{"token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("svc", "s3cret")
		req.RemoteAddr = "203.0.113.7:1"
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}
	m := intro(out["access_token"].(string))
	cnf, _ := m["cnf"].(map[string]any)
	if m["active"] != true || m["token_type"] != "DPoP" || cnf["jkt"] != k.jkt {
		t.Fatalf("access token: %v", m)
	}
	m = intro(out["refresh_token"].(string))
	cnf, _ = m["cnf"].(map[string]any)
	if m["active"] != true || cnf["jkt"] != k.jkt {
		t.Fatalf("refresh token: %v", m)
	}
	// Unbound tokens show no cnf.
	_, plain, _ := e.codeTok(t, "openid offline_access")
	for _, tk := range []string{plain["access_token"].(string), plain["refresh_token"].(string)} {
		if m := intro(tk); m["cnf"] != nil || m["token_type"] == "DPoP" {
			t.Fatalf("unbound: %v", m)
		}
	}
}

func TestDPoPDiscovery(t *testing.T) {
	e := newDEnv(t, devOpts{})
	w := e.browser().do("GET", "/realms/r/.well-known/openid-configuration", nil)
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(doc["dpop_signing_alg_values_supported"]) != "[ES256 RS256 EdDSA]" {
		t.Fatalf("%v", doc["dpop_signing_alg_values_supported"])
	}
}

func TestDPoPNonce(t *testing.T) {
	e := newDEnv(t, devOpts{})
	e.h.cfg.DPoPNonce = true
	e.addSvc()
	k := newES(t)
	code, out, h := e.cc(e.proof(t, k, pOpt{}))
	nonce := h.Get("DPoP-Nonce")
	if code != 400 || out["error"] != "use_dpop_nonce" || nonce == "" {
		t.Fatalf("%d %v %q", code, out, nonce)
	}
	if code, out, _ := e.cc(e.proof(t, k, pOpt{nonce: "forged"})); out["error"] != "use_dpop_nonce" {
		t.Fatalf("forged nonce: %d %v", code, out)
	}
	code, out, h = e.cc(e.proof(t, k, pOpt{nonce: nonce}))
	if code != 200 || h.Get("DPoP-Nonce") == "" {
		t.Fatalf("with nonce: %d %v %v", code, out, h)
	}
	// A nonce is realm bound and expires.
	if e.h.validDPoPNonce("other", nonce) {
		t.Fatal("nonce valid in another realm")
	}
	e.advance(11 * time.Minute)
	if code, out, _ := e.cc(e.proof(t, k, pOpt{nonce: nonce})); out["error"] != "use_dpop_nonce" {
		t.Fatalf("stale nonce: %d %v", code, out)
	}
	// The resource endpoint asks for it as well.
	_, out, _ = e.cc(e.proof(t, k, pOpt{nonce: e.h.currentDPoPNonce("r")}))
	at := out["access_token"].(string)
	req := httptest.NewRequest("GET", "/realms/r/protocol/openid-connect/userinfo", nil)
	req.Header.Set("Authorization", "DPoP "+at)
	req.Header.Set("DPoP", e.proof(t, k, pOpt{htu: userinfoURL, htm: "GET", ath: atHash(at)}))
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != 401 || w.Header().Get("DPoP-Nonce") == "" || !strings.Contains(w.Header().Get("WWW-Authenticate"), "use_dpop_nonce") {
		// client_credentials tokens have no openid scope, but the nonce check precedes that
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}

func TestDPoPConfidentialRefreshNotBound(t *testing.T) {
	// Confidential clients authenticate themselves: their refresh tokens are
	// not key-bound (RFC 9449 section 5), their access tokens are.
	e := newDEnv(t, devOpts{})
	if err := e.st.CreateClient(context.Background(), core.Client{Realm: "r", ClientID: "web", Enabled: true,
		SecretHash: HashSecret("w3b"), AuthCodeFlow: true, RedirectURIs: []string{cb}}); err != nil {
		t.Fatal(err)
	}
	code := "wcode"
	_ = e.st.PutAuthCode(context.Background(), core.AuthCode{CodeHash: HashSecret(code), Realm: "r", ClientID: "web", UserID: "u1",
		RedirectURI: cb, Scope: "openid offline_access", AuthTime: e.now, ExpiresAt: e.now.Add(time.Minute)})
	k := newES(t)
	st, out, _ := e.tok(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb}}, "web", "w3b", e.proof(t, k, pOpt{}))
	if st != 200 || out["token_type"] != "DPoP" {
		t.Fatalf("%d %v", st, out)
	}
	ds, _ := core.StoreAs[core.DPoPStore](e.st)
	if _, err := ds.RefreshTokenBinding(context.Background(), HashSecret(out["refresh_token"].(string)), e.now); err == nil {
		t.Fatal("confidential client refresh token was bound")
	}
	if st, out, _ := e.tok(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {out["refresh_token"].(string)}}, "web", "w3b"); st != 200 {
		t.Fatalf("%d %v", st, out)
	}
}
