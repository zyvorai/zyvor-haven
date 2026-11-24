// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

// ---- environment ----

type fenv struct {
	*denv
	cl   core.Client // confidential client "fapi"
	es   *ecdsa.PrivateKey
	rsa  *rsa.PrivateKey
	jwks string
}

const parURL = idpBase + "/realms/r/protocol/openid-connect/par"

func newFEnv(t *testing.T, mut func(*core.ClientFAPI), o devOpts) *fenv {
	t.Helper()
	e := newDEnv(t, o)
	f := &fenv{denv: e}
	c := context.Background()
	if err := e.st.CreateClient(c, core.Client{Realm: "r", ClientID: "fapi", Enabled: true, AuthCodeFlow: true,
		SecretHash: HashSecret("s3cret"), RedirectURIs: []string{cb}, RequirePKCE: true}); err != nil {
		t.Fatal(err)
	}
	var err error
	if f.cl, err = e.st.GetClientByClientID(c, "r", "fapi"); err != nil {
		t.Fatal(err)
	}
	f.es, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.rsa, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.jwks = mustJSON(map[string]any{"keys": []any{
		map[string]any{"kty": "EC", "crv": "P-256", "kid": "es1", "use": "sig", "x": b64u(padTo(f.es.X.Bytes(), 32)), "y": b64u(padTo(f.es.Y.Bytes(), 32))},
		map[string]any{"kty": "RSA", "kid": "ps1", "use": "sig", "n": b64u(f.rsa.N.Bytes()), "e": b64u(big.NewInt(int64(f.rsa.E)).Bytes())},
	}})
	cfg := core.ClientFAPI{Realm: "r", ClientRef: f.cl.ID, JWKS: f.jwks, AuthzDetailTypes: []string{"payment_initiation", "account_information"}}
	if mut != nil {
		mut(&cfg)
	}
	if err := e.st.PutClientFAPI(c, cfg); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fenv) setCfg(mut func(*core.ClientFAPI)) {
	f.t.Helper()
	cfg, err := f.st.GetClientFAPI(context.Background(), "r", f.cl.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	mut(&cfg)
	if err := f.st.PutClientFAPI(context.Background(), cfg); err != nil {
		f.t.Fatal(err)
	}
}

func pkce() url.Values {
	return url.Values{"redirect_uri": {cb}, "response_type": {"code"}, "state": {"st8"}, "scope": {"openid offline_access"},
		"nonce": {"n"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
}

// parReq posts to /par with basic auth (user "" = none).
func (f *fenv) parReq(form url.Values, user, pass string, hdr map[string]string) (int, map[string]any) {
	f.t.Helper()
	req := httptest.NewRequest("POST", "/realms/r/protocol/openid-connect/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.RemoteAddr = "203.0.113.9:1"
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (f *fenv) push(form url.Values) (int, map[string]any) {
	return f.parReq(form, "fapi", "s3cret", nil)
}

func (f *fenv) pushOK(form url.Values) string {
	f.t.Helper()
	code, out := f.push(form)
	if code != 201 {
		f.t.Fatalf("PAR: %d %v", code, out)
	}
	return out["request_uri"].(string)
}

var actionRe = regexp.MustCompile(`<form method="post" action="([^"]+)"`)

// authorize drives /auth with query q: follows the PAR redirect and logs alice
// in. It returns the final response (a 302 with a code on success).
func (f *fenv) authorize(b *browser, q url.Values) *httptest.ResponseRecorder {
	f.t.Helper()
	w := b.do("GET", base+"auth?"+q.Encode(), nil)
	if w.Code == 302 && strings.Contains(w.Header().Get("Location"), fapiCtxParam+"=") {
		w = b.do("GET", w.Header().Get("Location"), nil)
	}
	if w.Code != 200 {
		return w // an error page, a redirect with an error, or an SSO code
	}
	m := csrfRe.FindStringSubmatch(w.Body.String())
	am := actionRe.FindStringSubmatch(w.Body.String())
	if m == nil || am == nil {
		f.t.Fatalf("no login form: %s", w.Body)
	}
	return b.do("POST", html.UnescapeString(am[1]), url.Values{"username": {"alice"}, "password": {"pw"}, "csrf": {m[1]}})
}

func codeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != 302 {
		t.Fatalf("want a redirect with a code, got %d: %s", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "" || loc.Query().Get("code") == "" {
		t.Fatalf("no code: %s", loc)
	}
	return loc.Query().Get("code")
}

func (f *fenv) redeem(code string, proofs ...string) (int, map[string]any, http.Header) {
	return f.tok(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb},
		"code_verifier": {verifier}}, "fapi", "s3cret", proofs...)
}

func (f *fenv) pushedCode(q url.Values) string {
	f.t.Helper()
	ru := f.pushOK(q)
	return codeOf(f.t, f.authorize(f.browser(), url.Values{"client_id": {"fapi"}, "request_uri": {ru}}))
}

// ---- JAR signing ----

func (f *fenv) jar(t *testing.T, alg string, claims map[string]any, mut func(hdr map[string]any)) string {
	t.Helper()
	hdr := map[string]any{"alg": alg, "typ": "oauth-authz-req+jwt"}
	switch alg {
	case "ES256":
		hdr["kid"] = "es1"
	case "PS256":
		hdr["kid"] = "ps1"
	}
	if mut != nil {
		mut(hdr)
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signed := b64u(hb) + "." + b64u(cb)
	h := sha256.Sum256([]byte(signed))
	var sig []byte
	switch alg {
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, f.es, h[:])
		sig = append(padTo(r.Bytes(), 32), padTo(s.Bytes(), 32)...)
	case "PS256":
		sig, _ = rsa.SignPSS(rand.Reader, f.rsa, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "RS256":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, f.rsa, crypto.SHA256, h[:])
	case "HS256":
		m := hmac.New(sha256.New, []byte("s3cret"))
		m.Write([]byte(signed))
		sig = m.Sum(nil)
	case "none":
	}
	return signed + "." + b64u(sig)
}

func (f *fenv) objClaims(over map[string]any) map[string]any {
	now := f.now.Unix()
	c := map[string]any{"iss": "fapi", "aud": idpBase + "/realms/r", "client_id": "fapi", "exp": now + 300, "nbf": now - 5,
		"redirect_uri": cb, "response_type": "code", "state": "st8", "scope": "openid offline_access", "nonce": "n",
		"code_challenge": challenge(verifier), "code_challenge_method": "S256"}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

// ---- PAR ----

func TestPARFlowEndToEnd(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	q := pkce()
	ru := f.pushOK(q)
	if !strings.HasPrefix(ru, parURIPrefix) || len(ru) < len(parURIPrefix)+40 {
		t.Fatalf("request_uri %q", ru)
	}
	// Only a hash is stored: the raw request_uri is not an identifier anywhere.
	fs, _ := core.StoreAs[core.FAPIStore](f.st)
	if _, err := fs.GetFAPIRequest(context.Background(), "r", core.FAPIKindPAR, ru, f.now); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("request_uri stored in the clear: %v", err)
	}
	if _, err := fs.GetFAPIRequest(context.Background(), "r", core.FAPIKindPAR, HashSecret(ru), f.now); err != nil {
		t.Fatalf("hashed record missing: %v", err)
	}
	b := f.browser()
	// Only client_id and request_uri on the front channel.
	w := f.authorize(b, url.Values{"client_id": {"fapi"}, "request_uri": {ru}})
	code := codeOf(t, w)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("state") != "st8" {
		t.Fatalf("state from the pushed request not used: %s", loc)
	}
	status, tok, _ := f.redeem(code)
	if status != 200 || tok["id_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("token: %d %v", status, tok)
	}
	if idc := claimsOf(t, tok["id_token"].(string)); idc["nonce"] != "n" {
		t.Fatalf("nonce from the pushed request lost: %v", idc)
	}
}

func TestPARRequestURISingleUse(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	ru := f.pushOK(pkce())
	b := f.browser()
	w := b.do("GET", base+"auth?"+url.Values{"client_id": {"fapi"}, "request_uri": {ru}}.Encode(), nil)
	if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), fapiCtxParam+"=") {
		t.Fatalf("first use: %d %s", w.Code, w.Header().Get("Location"))
	}
	if strings.Contains(w.Header().Get("Location"), ru) || strings.Contains(w.Header().Get("Location"), "state=") {
		t.Fatalf("redirect leaks the pushed request: %s", w.Header().Get("Location"))
	}
	again := f.browser().do("GET", base+"auth?"+url.Values{"client_id": {"fapi"}, "request_uri": {ru}}.Encode(), nil)
	if again.Code != 400 {
		t.Fatalf("second use of a request_uri: %d", again.Code)
	}
}

func TestPARRequestURIConcurrentRedeem(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	ru := f.pushOK(pkce())
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", base+"auth?"+url.Values{"client_id": {"fapi"}, "request_uri": {ru}}.Encode(), nil)
			req.RemoteAddr = "198.51.100.1:1"
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, req)
			if w.Code == 302 {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent redemptions succeeded, want exactly 1", wins)
	}
}

func TestPARRequestURIExpires(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	ru := f.pushOK(pkce())
	f.advance(parTTL + time.Second)
	if w := f.browser().do("GET", base+"auth?"+url.Values{"client_id": {"fapi"}, "request_uri": {ru}}.Encode(), nil); w.Code != 400 {
		t.Fatalf("expired request_uri: %d", w.Code)
	}
	// The login context after redemption has its own, longer, life.
	ru = f.pushOK(pkce())
	b := f.browser()
	w := b.do("GET", base+"auth?"+url.Values{"client_id": {"fapi"}, "request_uri": {ru}}.Encode(), nil)
	f.advance(fapiCtxTTL + time.Second)
	if w2 := b.do("GET", w.Header().Get("Location"), nil); w2.Code != 400 {
		t.Fatalf("expired login context: %d", w2.Code)
	}
}

func TestPARRequestURIBoundToClient(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	ru := f.pushOK(pkce())
	// Another client presenting someone else's request_uri gets nothing, and the
	// pushed request is gone (it was single use).
	w := f.browser().do("GET", base+"auth?"+url.Values{"client_id": {"app"}, "request_uri": {ru}}.Encode(), nil)
	if w.Code != 400 {
		t.Fatalf("foreign client redeemed the request_uri: %d %s", w.Code, w.Header().Get("Location"))
	}
	// A login context handle only works for the client it was made for.
	ru = f.pushOK(pkce())
	b := f.browser()
	loc := b.do("GET", base+"auth?"+url.Values{"client_id": {"fapi"}, "request_uri": {ru}}.Encode(), nil).Header().Get("Location")
	u, _ := url.Parse(loc)
	h := u.Query().Get(fapiCtxParam)
	if w := b.do("GET", base+"auth?"+url.Values{"client_id": {"app"}, fapiCtxParam: {h}}.Encode(), nil); w.Code != 400 {
		t.Fatalf("foreign client used the login context: %d", w.Code)
	}
}

func TestPARClientAuthRequired(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	q := pkce()
	q.Set("client_id", "fapi")
	for name, c := range map[string]struct{ user, pass string }{
		"no credentials": {"", ""}, "wrong secret": {"fapi", "nope"}, "public client": {"app", ""}, "unknown client": {"ghost", "x"},
	} {
		code, out := f.parReq(q, c.user, c.pass, nil)
		if code != 401 || out["error"] != "invalid_client" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	// client_secret_post works.
	post := url.Values{"client_id": {"fapi"}, "client_secret": {"s3cret"}}
	for k, v := range pkce() {
		post[k] = v
	}
	if code, out := f.parReq(post, "", "", nil); code != 201 {
		t.Errorf("client_secret_post: %d %v", code, out)
	}
	// A disabled client is refused.
	cl := f.cl
	cl.Enabled = false
	if err := f.st.UpdateClient(context.Background(), cl); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.push(pkce()); code != 401 {
		t.Errorf("disabled client: %d", code)
	}
}

func TestPARRejectsBadRequests(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	cases := map[string]func(url.Values){
		"request_uri sent to PAR":  func(q url.Values) { q.Set("request_uri", parURIPrefix+"x") },
		"unregistered redirect":    func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"no redirect":              func(q url.Values) { q.Del("redirect_uri") },
		"response_type token":      func(q url.Values) { q.Set("response_type", "token") },
		"bad dpop_jkt":             func(q url.Values) { q.Set("dpop_jkt", "short") },
		"huge parameter":           func(q url.Values) { q.Set("scope", strings.Repeat("a", jarMaxValue+1)) },
		"details, wrong type":      func(q url.Values) { q.Set("authorization_details", `[{"type":"evil"}]`) },
		"details, not an array":    func(q url.Values) { q.Set("authorization_details", `{"type":"payment_initiation"}`) },
		"details, duplicate type":  func(q url.Values) { q.Set("authorization_details", `[{"type":"evil","type":"payment_initiation"}]`) },
		"details, empty":           func(q url.Values) { q.Set("authorization_details", `[]`) },
		"details, trailing data":   func(q url.Values) { q.Set("authorization_details", `[{"type":"payment_initiation"}] x`) },
		"details, typeless entry":  func(q url.Values) { q.Set("authorization_details", `[{"actions":["a"]}]`) },
		"details, type not string": func(q url.Values) { q.Set("authorization_details", `[{"type":1}]`) },
	}
	for name, mut := range cases {
		q := pkce()
		mut(q)
		code, out := f.push(q)
		if code != 400 {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if code, out := f.push(url.Values{"redirect_uri": {cb}, "response_type": {"code"}, "authorization_details": {`[{"type":"payment_initiation"}]`}}); code != 201 {
		t.Errorf("valid details rejected: %d %v", code, out)
	}
	// Unknown details type yields the RFC 9396 error code.
	q := pkce()
	q.Set("authorization_details", `[{"type":"evil"}]`)
	if _, out := f.push(q); out["error"] != "invalid_authorization_details" {
		t.Errorf("error code: %v", out)
	}
}

func TestPARMethod(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, httptest.NewRequest("GET", "/realms/r/protocol/openid-connect/par", nil))
	if w.Code != 405 {
		t.Errorf("GET /par: %d", w.Code)
	}
}

func TestPARRateLimited(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	var last int
	for i := 0; i < parRateLimit+1; i++ {
		last, _ = f.push(pkce())
	}
	if last != 429 {
		t.Fatalf("request %d: %d", parRateLimit+1, last)
	}
}

// ---- require PAR ----

func TestRequirePAR(t *testing.T) {
	f := newFEnv(t, func(c *core.ClientFAPI) { c.RequirePAR = true }, devOpts{})
	plain := pkce()
	plain.Set("client_id", "fapi")
	if w := f.browser().do("GET", base+"auth?"+plain.Encode(), nil); w.Code != 400 {
		t.Fatalf("plain request on a require-PAR client: %d", w.Code)
	}
	if w := f.browser().do("POST", base+"auth?"+plain.Encode(), url.Values{"username": {"alice"}, "password": {"pw"}, "csrf": {"x"}}); w.Code != 400 {
		t.Fatalf("plain POST on a require-PAR client: %d", w.Code)
	}
	// A request object by value is not PAR either.
	obj := f.jar(t, "ES256", f.objClaims(nil), nil)
	if w := f.browser().do("GET", base+"auth?"+url.Values{"client_id": {"fapi"}, "request": {obj}}.Encode(), nil); w.Code != 400 {
		t.Fatalf("JAR by value on a require-PAR client: %d", w.Code)
	}
	// Through PAR it works.
	codeOf(t, f.authorize(f.browser(), url.Values{"client_id": {"fapi"}, "request_uri": {f.pushOK(pkce())}}))
	// Other clients are unaffected.
	q := authQuery(nil)
	if w := f.browser().do("GET", base+"auth?"+q.Encode(), nil); w.Code != 200 {
		t.Fatalf("unrelated client: %d", w.Code)
	}
}

func TestRequirePARBlocksBrokeredEntry(t *testing.T) {
	f := newFEnv(t, func(c *core.ClientFAPI) { c.RequirePAR = true }, devOpts{})
	rl, _ := f.st.GetRealm(context.Background(), "r")
	q := pkce()
	q.Set("client_id", "fapi")
	if ar, msg := f.h.parseAuthzQuery(context.Background(), rl, q); ar != nil || msg == "" {
		t.Fatalf("identity brokering rebuilt a require-PAR client's request from a plain query: %v %q", ar, msg)
	}
	f.setCfg(func(c *core.ClientFAPI) { c.RequirePAR = false })
	if ar, msg := f.h.parseAuthzQuery(context.Background(), rl, q); ar == nil || msg != "" {
		t.Fatalf("plain client refused: %q", msg)
	}
	q.Set("dpop_jkt", challenge("x"))
	if ar, _ := f.h.parseAuthzQuery(context.Background(), rl, q); ar != nil {
		t.Fatal("brokering silently dropped dpop_jkt")
	}
}

// ---- JAR ----

func TestJARViaPARSucceeds(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	for _, alg := range []string{"ES256", "PS256"} {
		obj := f.jar(t, alg, f.objClaims(nil), nil)
		// Parameters outside the object are ignored: the object is the request.
		ru := f.pushOK(url.Values{"request": {obj}, "state": {"evil"}, "redirect_uri": {"https://evil.example/cb"}})
		w := f.authorize(f.browser(), url.Values{"client_id": {"fapi"}, "request_uri": {ru}})
		code := codeOf(t, w)
		if loc, _ := url.Parse(w.Header().Get("Location")); loc.Query().Get("state") != "st8" || loc.Host == "evil.example" {
			t.Fatalf("%s: values outside the request object were honoured: %s", alg, loc)
		}
		if status, _, _ := f.redeem(code); status != 200 {
			t.Fatalf("%s: token %d", alg, status)
		}
	}
}

func TestJARByValueAtAuthorize(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	obj := f.jar(t, "ES256", f.objClaims(nil), nil)
	w := f.authorize(f.browser(), url.Values{"client_id": {"fapi"}, "request": {obj}, "state": {"evil"}, "redirect_uri": {"https://evil.example/cb"}})
	codeOf(t, w)
	if loc, _ := url.Parse(w.Header().Get("Location")); loc.Query().Get("state") != "st8" || loc.Host == "evil.example" {
		t.Fatalf("outer parameters honoured: %s", loc)
	}
}

func TestJARRejected(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	now := f.now.Unix()
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	type tc struct {
		name string
		obj  func() string
	}
	signed := func(alg string, over map[string]any, mut func(map[string]any)) func() string {
		return func() string { return f.jar(t, alg, f.objClaims(over), mut) }
	}
	cases := []tc{
		{"alg none", signed("none", nil, nil)},
		{"alg HS256 keyed with the client secret", signed("HS256", nil, nil)},
		{"alg RS256", signed("RS256", nil, func(h map[string]any) { h["kid"] = "ps1" })},
		{"expired", signed("ES256", map[string]any{"exp": now - 120, "nbf": now - 600}, nil)},
		{"no exp", signed("ES256", map[string]any{"exp": nil}, nil)},
		{"no nbf", signed("ES256", map[string]any{"nbf": nil}, nil)},
		{"nbf in the future", signed("ES256", map[string]any{"nbf": now + 600, "exp": now + 900}, nil)},
		{"lifetime too long", signed("ES256", map[string]any{"nbf": now - 5, "exp": now + 7200}, nil)},
		{"exp not after nbf", signed("ES256", map[string]any{"nbf": now, "exp": now}, nil)},
		{"iss is another client", signed("ES256", map[string]any{"iss": "app"}, nil)},
		{"client_id member differs", signed("ES256", map[string]any{"client_id": "app"}, nil)},
		{"wrong audience", signed("ES256", map[string]any{"aud": "https://other.example/realms/r"}, nil)},
		{"no audience", signed("ES256", map[string]any{"aud": nil}, nil)},
		{"request_uri inside", signed("ES256", map[string]any{"request_uri": parURIPrefix + "x"}, nil)},
		{"request inside", signed("ES256", map[string]any{"request": "x"}, nil)},
		{"unknown kid", signed("ES256", nil, func(h map[string]any) { h["kid"] = "nope" })},
		{"wrong typ", signed("ES256", nil, func(h map[string]any) { h["typ"] = "JWT" })},
		{"crit header", signed("ES256", nil, func(h map[string]any) { h["crit"] = []string{"x"} })},
		{"array where a string is due", signed("ES256", map[string]any{"scope": []string{"openid"}}, nil)},
		{"signed by an unregistered key", func() string {
			g := *f
			g.es = other
			return g.jar(t, "ES256", f.objClaims(nil), nil)
		}},
		{"tampered payload", func() string {
			p := strings.Split(f.jar(t, "ES256", f.objClaims(nil), nil), ".")
			c := f.objClaims(map[string]any{"redirect_uri": "https://evil.example/cb"})
			b, _ := json.Marshal(c)
			return p[0] + "." + b64u(b) + "." + p[2]
		}},
		{"three-part garbage", func() string { return "a.b.c" }},
		{"not a JWS", func() string { return "garbage" }},
		{"duplicate claim", func() string {
			hb, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": "es1"})
			cb := fmt.Sprintf(`{"iss":"fapi","aud":%q,"exp":%d,"nbf":%d,"redirect_uri":%q,"redirect_uri":"https://evil.example/cb","response_type":"code"}`,
				idpBase+"/realms/r", now+300, now-5, cb)
			s := b64u(hb) + "." + b64u([]byte(cb))
			h := sha256.Sum256([]byte(s))
			r, ss, _ := ecdsa.Sign(rand.Reader, f.es, h[:])
			return s + "." + b64u(append(padTo(r.Bytes(), 32), padTo(ss.Bytes(), 32)...))
		}},
	}
	for _, c := range cases {
		code, out := f.push(url.Values{"request": {c.obj()}})
		if code != 400 || out["error"] != "invalid_request_object" {
			t.Errorf("%s at /par: %d %v", c.name, code, out)
		}
		w := f.browser().do("GET", base+"auth?"+url.Values{"client_id": {"fapi"}, "request": {c.obj()}}.Encode(), nil)
		if w.Code != 400 {
			t.Errorf("%s at /auth: %d", c.name, w.Code)
		}
	}
}

func TestJARNeedsRegisteredKeys(t *testing.T) {
	f := newFEnv(t, func(c *core.ClientFAPI) { c.JWKS = "" }, devOpts{})
	obj := f.jar(t, "ES256", f.objClaims(nil), nil)
	if code, _ := f.push(url.Values{"request": {obj}}); code != 400 {
		t.Fatalf("object accepted for a client without keys: %d", code)
	}
	// A client with a JWKS that only holds a private key (unusable) is the same.
	f.setCfg(func(c *core.ClientFAPI) {
		c.JWKS = mustJSON(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256",
			"x": b64u(padTo(f.es.X.Bytes(), 32)), "y": b64u(padTo(f.es.Y.Bytes(), 32)), "d": b64u(f.es.D.Bytes())}}})
	})
	if code, _ := f.push(url.Values{"request": {obj}}); code != 400 {
		t.Fatalf("private-key JWKS used: %d", code)
	}
	// A kid-less object needs exactly one candidate key.
	f.setCfg(func(c *core.ClientFAPI) { c.JWKS = f.jwks })
	noKid := f.jar(t, "ES256", f.objClaims(nil), func(h map[string]any) { delete(h, "kid") })
	if code, out := f.push(url.Values{"request": {noKid}}); code != 201 {
		t.Fatalf("one EC key and no kid: %d %v", code, out)
	}
}

func TestRequireSignedRequest(t *testing.T) {
	f := newFEnv(t, func(c *core.ClientFAPI) { c.RequireSignedRequest = true }, devOpts{})
	if code, _ := f.push(pkce()); code != 400 {
		t.Fatalf("unsigned PAR accepted: %d", code)
	}
	plain := pkce()
	plain.Set("client_id", "fapi")
	if w := f.browser().do("GET", base+"auth?"+plain.Encode(), nil); w.Code != 400 {
		t.Fatalf("unsigned /auth accepted: %d", w.Code)
	}
	if code, out := f.push(url.Values{"request": {f.jar(t, "ES256", f.objClaims(nil), nil)}}); code != 201 {
		t.Fatalf("signed PAR refused: %d %v", code, out)
	}
}

// ---- RAR ----

const payDetails = `[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]`

func introspect(t *testing.T, f *fenv, tok string) map[string]any {
	t.Helper()
	req := httptest.NewRequest("POST", "/realms/r/protocol/openid-connect/token/introspect", strings.NewReader(url.Values{"token": {tok}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("fapi", "s3cret")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestRARCarriedToTokensAndIntrospection(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	q := pkce()
	q.Set("authorization_details", payDetails)
	code := f.pushedCode(q)
	status, tok, _ := f.redeem(code)
	if status != 200 {
		t.Fatalf("%d %v", status, tok)
	}
	want := func(v any, what string) {
		t.Helper()
		arr, _ := v.([]any)
		if len(arr) != 1 {
			t.Fatalf("%s: authorization_details = %v", what, v)
		}
		e, _ := arr[0].(map[string]any)
		amt, _ := e["instructedAmount"].(map[string]any)
		if e["type"] != "payment_initiation" || amt["amount"] != "123.50" {
			t.Fatalf("%s: entry mangled: %v", what, e)
		}
	}
	want(tok["authorization_details"], "token response")
	at := tok["access_token"].(string)
	want(claimsOf(t, at)["authorization_details"], "access token claim")
	in := introspect(t, f, at)
	if in["active"] != true {
		t.Fatalf("introspection: %v", in)
	}
	want(in["authorization_details"], "introspection")
	// The id token does not carry them.
	if _, has := claimsOf(t, tok["id_token"].(string))["authorization_details"]; has {
		t.Error("id token carries authorization_details")
	}
	// Refresh keeps them (bound to the refresh token), and so does rotation.
	rt := tok["refresh_token"].(string)
	want(introspect(t, f, rt)["authorization_details"], "refresh token introspection")
	for i := 0; i < 2; i++ {
		status, tok, _ = f.tok(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, "fapi", "s3cret")
		if status != 200 {
			t.Fatalf("refresh %d: %d %v", i, status, tok)
		}
		want(tok["authorization_details"], "refresh response")
		want(claimsOf(t, tok["access_token"].(string))["authorization_details"], "refreshed access token")
		rt = tok["refresh_token"].(string)
	}
	// Only hashes are stored.
	fs, _ := core.StoreAs[core.FAPIStore](f.st)
	if _, err := fs.GetFAPIBinding(context.Background(), core.FAPIKindCode, code, f.now); !errors.Is(err, idp.ErrNotFound) {
		t.Errorf("code binding keyed by the raw code: %v", err)
	}
	if _, err := fs.GetFAPIBinding(context.Background(), core.FAPIKindRefresh, rt, f.now); !errors.Is(err, idp.ErrNotFound) {
		t.Errorf("refresh binding keyed by the raw token: %v", err)
	}
}

func TestRARNotCarriedWithoutRequest(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	status, tok, _ := f.redeem(f.pushedCode(pkce()))
	if status != 200 {
		t.Fatal(status)
	}
	if _, has := tok["authorization_details"]; has {
		t.Error("response invents authorization_details")
	}
	if _, has := claimsOf(t, tok["access_token"].(string))["authorization_details"]; has {
		t.Error("access token invents authorization_details")
	}
}

func TestRARPlainAuthorizeValidated(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	q := authQuery(map[string]string{"client_id": "fapi", "authorization_details": `[{"type":"evil"}]`})
	w := f.browser().do("GET", base+"auth?"+q.Encode(), nil)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || loc.Query().Get("error") != "invalid_authorization_details" || loc.Query().Get("state") != "st8" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
	// A client with no registered types may not send any.
	f.setCfg(func(c *core.ClientFAPI) { c.AuthzDetailTypes = nil })
	q.Set("authorization_details", payDetails)
	w = f.browser().do("GET", base+"auth?"+q.Encode(), nil)
	if loc, _ = url.Parse(w.Header().Get("Location")); w.Code != 302 || loc.Query().Get("error") != "invalid_authorization_details" {
		t.Fatalf("client without types: %d %s", w.Code, w.Header().Get("Location"))
	}
	// Not a trusted redirect target: no redirect, an error page.
	q.Set("redirect_uri", "https://evil.example/cb")
	if w = f.browser().do("GET", base+"auth?"+q.Encode(), nil); w.Code != 400 {
		t.Fatalf("untrusted redirect_uri: %d", w.Code)
	}
}

func TestRARNotAcceptedAtTokenEndpoint(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	code := f.pushedCode(pkce())
	status, out, _ := f.tok(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb},
		"code_verifier": {verifier}, "authorization_details": {payDetails}}, "fapi", "s3cret")
	if status != 400 || out["error"] != "invalid_request" {
		t.Fatalf("%d %v", status, out)
	}
	// The refusal happened before the code was consumed.
	if status, _, _ := f.redeem(code); status != 200 {
		t.Fatalf("code was burnt by the refused request: %d", status)
	}
}

func TestValidateAuthzDetails(t *testing.T) {
	allowed := []string{"a", "b.c/d"}
	ok := []string{`[{"type":"a"}]`, `[{"type":"a"},{"type":"b.c/d","x":{"y":[1,2,{"z":null}]}}]`, ` [ {"type" : "a" } ] `}
	for _, s := range ok {
		if _, err := validateAuthzDetails(s, allowed); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bads := []string{"", `null`, `[]`, `{}`, `"a"`, `[1]`, `[null]`, `[{}]`, `[{"type":""}]`, `[{"type":"c"}]`, `[{"type":"A"}]`,
		`[{"type":"a","type":"a"}]`, `[{"type":"a"}] []`, `[{"type":"a"}`, `[{"type":["a"]}]`, `[{"type":"a","x":{"x":1,"x":2}}]`,
		`[{"type":"a","d":` + strings.Repeat(`{"d":`, 9) + `1` + strings.Repeat(`}`, 9) + `}]`,
		`[` + strings.Repeat(`{"type":"a"},`, 10) + `{"type":"a"}]`,
		`[{"type":"a","pad":"` + strings.Repeat("x", rarMaxBytes) + `"}]`}
	for _, s := range bads {
		if out, err := validateAuthzDetails(s, allowed); err == nil {
			t.Errorf("%.60q accepted as %q", s, out)
		}
	}
	if _, err := validateAuthzDetails(`[{"type":"a"}]`, nil); err == nil {
		t.Error("accepted for a client with no allowed types")
	}
	out, _ := validateAuthzDetails(`[{"z":1,"type":"a","a":12345678901234567890}]`, allowed)
	if out != `[{"a":12345678901234567890,"type":"a","z":1}]` {
		t.Errorf("canonical form / number precision: %s", out)
	}
}

// ---- require DPoP and dpop_jkt ----

func TestRequireDPoP(t *testing.T) {
	f := newFEnv(t, func(c *core.ClientFAPI) { c.RequireDPoP = true }, devOpts{})
	k := newES(t)
	tokProof := func() string { return f.proof(t, k, pOpt{}) }

	// Authorization code without a proof: refused and the code survives.
	code := f.pushedCode(pkce())
	status, out, _ := f.redeem(code)
	if status != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("code without proof: %d %v", status, out)
	}
	status, out, _ = f.redeem(code, tokProof())
	if status != 200 || out["token_type"] != "DPoP" || cnfJKT(t, out["access_token"].(string)) != k.jkt {
		t.Fatalf("code with proof: %d %v", status, out)
	}
	// Refresh without a proof (a confidential client's refresh token is not key-bound by DPoP itself).
	rt := out["refresh_token"].(string)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	if status, out, _ = f.tok(form, "fapi", "s3cret"); status != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("refresh without proof: %d %v", status, out)
	}
	if status, out, _ = f.tok(form, "fapi", "s3cret", tokProof()); status != 200 || out["token_type"] != "DPoP" {
		t.Fatalf("refresh with proof: %d %v", status, out)
	}
	// Other clients are not affected.
	if status, _, _ := f.codeTok(t, "openid"); status != 200 {
		t.Fatalf("unrelated client: %d", status)
	}
	// Switch off: bearer again.
	f.setCfg(func(c *core.ClientFAPI) { c.RequireDPoP = false })
	if status, out, _ = f.redeem(f.pushedCode(pkce())); status != 200 || out["token_type"] != "Bearer" {
		t.Fatalf("after switching off: %d %v", status, out)
	}
}

func TestRequireDPoPCoversEveryGrant(t *testing.T) {
	f := newFEnv(t, func(c *core.ClientFAPI) { c.RequireDPoP = true }, devOpts{})
	c := context.Background()
	if err := f.st.CreateClient(c, core.Client{Realm: "r", ClientID: "svc", Enabled: true, ServiceAccount: true, SecretHash: HashSecret("s3cret")}); err != nil {
		t.Fatal(err)
	}
	svc, _ := f.st.GetClientByClientID(c, "r", "svc")
	if err := f.st.PutClientFAPI(c, core.ClientFAPI{Realm: "r", ClientRef: svc.ID, RequireDPoP: true}); err != nil {
		t.Fatal(err)
	}
	status, out, _ := f.tok(url.Values{"grant_type": {"client_credentials"}}, "svc", "s3cret")
	if status != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("client_credentials without proof: %d %v", status, out)
	}
	k := newES(t)
	status, out, _ = f.tok(url.Values{"grant_type": {"client_credentials"}}, "svc", "s3cret", f.proof(t, k, pOpt{}))
	if status != 200 || cnfJKT(t, out["access_token"].(string)) != k.jkt {
		t.Fatalf("client_credentials with proof: %d %v", status, out)
	}
	// An unknown grant type does not slip past the check either.
	status, out, _ = f.tok(url.Values{"grant_type": {"urn:x"}}, "svc", "s3cret")
	if out["error"] != "invalid_dpop_proof" {
		t.Fatalf("unknown grant without proof: %d %v", status, out)
	}
}

func TestDPoPJKTAtAuthorize(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	a, b := newES(t), newES(t)
	q := pkce()
	q.Set("dpop_jkt", a.jkt)
	code := f.pushedCode(q)
	if status, out, _ := f.redeem(code); status != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("no proof for a key-bound code: %d %v", status, out)
	}
	if status, out, _ := f.redeem(code, f.proof(t, b, pOpt{})); status != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("another key: %d %v", status, out)
	}
	status, out, _ := f.redeem(code, f.proof(t, a, pOpt{}))
	if status != 200 || cnfJKT(t, out["access_token"].(string)) != a.jkt {
		t.Fatalf("right key (the code must have survived the refusals): %d %v", status, out)
	}
	// Plain /auth (a client that does not require PAR) honours dpop_jkt too.
	plain := authQuery(map[string]string{"client_id": "fapi", "dpop_jkt": a.jkt})
	code = codeOf(t, f.authorize(f.browser(), plain))
	if status, _, _ := f.redeem(code, f.proof(t, b, pOpt{})); status != 400 {
		t.Fatalf("plain /auth: another key accepted: %d", status)
	}
	// Malformed.
	plain.Set("dpop_jkt", "nope")
	if w := f.browser().do("GET", base+"auth?"+plain.Encode(), nil); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "error=invalid_request") {
		t.Fatalf("malformed dpop_jkt: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestDPoPAtPARBindsRequest(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	a, b := newES(t), newES(t)
	hdr := func(k *dkey, o pOpt) map[string]string {
		o.htu = parURL
		return map[string]string{"DPoP": f.proof(t, k, o)}
	}
	// The proof at PAR sets dpop_jkt.
	code, out := f.parReq(pkce(), "fapi", "s3cret", hdr(a, pOpt{}))
	if code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	ru := out["request_uri"].(string)
	authCode := codeOf(t, f.authorize(f.browser(), url.Values{"client_id": {"fapi"}, "request_uri": {ru}}))
	if status, _, _ := f.redeem(authCode, f.proof(t, b, pOpt{})); status != 400 {
		t.Fatalf("code redeemed with another key: %d", status)
	}
	if status, _, _ := f.redeem(authCode, f.proof(t, a, pOpt{})); status != 200 {
		t.Fatalf("right key refused: %d", status)
	}
	// A dpop_jkt that disagrees with the proof is refused.
	q := pkce()
	q.Set("dpop_jkt", b.jkt)
	if code, out = f.parReq(q, "fapi", "s3cret", hdr(a, pOpt{})); code != 400 || out["error"] != "invalid_dpop_proof" {
		t.Fatalf("mismatch: %d %v", code, out)
	}
	// A proof for the token endpoint (wrong htu) is refused, and so is a replay.
	if code, _ = f.parReq(pkce(), "fapi", "s3cret", map[string]string{"DPoP": f.proof(t, a, pOpt{})}); code != 400 {
		t.Fatalf("token-endpoint proof accepted at PAR: %d", code)
	}
	h := hdr(a, pOpt{jti: "same-jti"})
	if code, _ = f.parReq(pkce(), "fapi", "s3cret", h); code != 201 {
		t.Fatalf("first use: %d", code)
	}
	if code, _ = f.parReq(pkce(), "fapi", "s3cret", h); code != 400 {
		t.Fatalf("replayed proof: %d", code)
	}
}

// ---- login context ----

func TestLoginContextSpentWhenCodeIssued(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	ru := f.pushOK(pkce())
	b := f.browser()
	loc := b.do("GET", base+"auth?"+url.Values{"client_id": {"fapi"}, "request_uri": {ru}}.Encode(), nil).Header().Get("Location")
	login := b.do("GET", loc, nil)
	m, am := csrfRe.FindStringSubmatch(login.Body.String()), actionRe.FindStringSubmatch(login.Body.String())
	if m == nil || am == nil || !strings.Contains(html.UnescapeString(am[1]), fapiCtxParam+"=") || strings.Contains(am[1], "request_uri") {
		t.Fatalf("login form does not continue from the context: %v", am)
	}
	// A wrong password does not spend it (the page comes back with a fresh CSRF token).
	bad := b.do("POST", html.UnescapeString(am[1]), url.Values{"username": {"alice"}, "password": {"bad"}, "csrf": {m[1]}})
	if bad.Code != 200 {
		t.Fatalf("bad password: %d", bad.Code)
	}
	m = csrfRe.FindStringSubmatch(bad.Body.String())
	codeOf(t, b.do("POST", html.UnescapeString(am[1]), url.Values{"username": {"alice"}, "password": {"pw"}, "csrf": {m[1]}}))
	// The browser URL replayed (with the SSO session at hand) does not mint a second code.
	if w := b.do("GET", loc, nil); w.Code != 400 {
		t.Fatalf("login context reusable after the code was issued: %d", w.Code)
	}
}

func TestPARWithSSOReuse(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	b := f.browser()
	q := pkce()
	q.Set("authorization_details", payDetails)
	codeOf(t, f.authorize(b, url.Values{"client_id": {"fapi"}, "request_uri": {f.pushOK(q)}})) // logs in
	// Second pushed request, same browser: the session issues the code silently.
	w := f.authorize(b, url.Values{"client_id": {"fapi"}, "request_uri": {f.pushOK(q)}})
	code := codeOf(t, w)
	status, tok, _ := f.redeem(code)
	if status != 200 || tok["authorization_details"] == nil {
		t.Fatalf("%d %v", status, tok)
	}
}

// ---- discovery and fail-closed behaviour ----

func discoveryOf(t *testing.T, f *denv) map[string]any {
	t.Helper()
	w := f.browser().do("GET", "/realms/r/.well-known/openid-configuration", nil)
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestFAPIDiscovery(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	doc := discoveryOf(t, f.denv)
	if doc["pushed_authorization_request_endpoint"] != parURL {
		t.Errorf("par endpoint: %v", doc["pushed_authorization_request_endpoint"])
	}
	if doc["request_parameter_supported"] != true || doc["request_uri_parameter_supported"] != true ||
		doc["require_pushed_authorization_requests"] != false || doc["require_request_uri_registration"] != false {
		t.Errorf("request flags: %v", doc)
	}
	if got := fmt.Sprint(doc["request_object_signing_alg_values_supported"]); got != "[ES256 PS256]" {
		t.Errorf("request object algs: %s", got)
	}
	if doc["authorization_details_supported"] != true {
		t.Errorf("authorization_details_supported: %v", doc["authorization_details_supported"])
	}
}

// plainStore hides every optional store interface (Unwrap is deliberately absent).
type plainStore struct{ core.Store }

func TestFeatureOffWithoutStore(t *testing.T) {
	e := newDEnv(t, devOpts{store: func(s core.Store) core.Store { return plainStore{s} }})
	doc := discoveryOf(t, e)
	for _, k := range []string{"pushed_authorization_request_endpoint", "request_object_signing_alg_values_supported", "authorization_details_supported"} {
		if _, has := doc[k]; has {
			t.Errorf("discovery advertises %s without a store", k)
		}
	}
	req := httptest.NewRequest("POST", "/realms/r/protocol/openid-connect/par", strings.NewReader("client_id=app"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != 501 {
		t.Errorf("/par without a store: %d", w.Code)
	}
	b := e.browser()
	for name, q := range map[string]url.Values{
		"request_uri":           authQuery(map[string]string{"request_uri": parURIPrefix + "x"}),
		"request":               authQuery(map[string]string{"request": "a.b.c"}),
		"authorization_details": authQuery(map[string]string{"authorization_details": payDetails}),
		"dpop_jkt":              authQuery(map[string]string{"dpop_jkt": challenge("k")}),
		"fapi_ctx":              authQuery(map[string]string{fapiCtxParam: "x"}),
	} {
		w := b.do("GET", base+"auth?"+q.Encode(), nil)
		if w.Code == 200 {
			t.Errorf("%s accepted without a store (login page shown)", name)
		}
	}
	// And a token request that carries authorization_details is not silently served.
	status, out, _ := e.tok(url.Values{"grant_type": {"authorization_code"}, "authorization_details": {payDetails}, "client_id": {"app"}}, "", "")
	if status != 400 || out["error"] != "invalid_request" {
		t.Errorf("token request with authorization_details: %d %v", status, out)
	}
}

// brokenFAPI is a FAPIStore whose client settings cannot be read.
type brokenFAPI struct{ *memstore.Store }

func (brokenFAPI) GetClientFAPI(context.Context, string, string) (core.ClientFAPI, error) {
	return core.ClientFAPI{}, errors.New("db down")
}

func TestFailClosedWhenSettingsUnreadable(t *testing.T) {
	var st brokenFAPI
	e := newDEnv(t, devOpts{store: func(s core.Store) core.Store { st = brokenFAPI{s.(*memstore.Store)}; return st }})
	f := &fenv{denv: e}
	if err := e.st.CreateClient(context.Background(), core.Client{Realm: "r", ClientID: "fapi", Enabled: true, AuthCodeFlow: true,
		SecretHash: HashSecret("s3cret"), RedirectURIs: []string{cb}}); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.push(pkce()); code != 500 {
		t.Errorf("/par with unreadable settings: %d", code)
	}
	q := authQuery(map[string]string{"client_id": "fapi"})
	if w := e.browser().do("GET", base+"auth?"+q.Encode(), nil); w.Code != 500 {
		t.Errorf("/auth with unreadable settings: %d (a require-PAR client must not be served plain)", w.Code)
	}
	status, out, _ := e.tok(url.Values{"grant_type": {"client_credentials"}}, "fapi", "s3cret")
	if status != 500 {
		t.Errorf("token with unreadable settings: %d %v", status, out)
	}
	rl, _ := e.st.GetRealm(context.Background(), "r")
	cl, _ := e.st.GetClientByClientID(context.Background(), "r", "fapi")
	if msg := e.h.fapiParseCheck(context.Background(), rl, cl, url.Values{}); msg == "" {
		t.Error("brokering guard passes when settings are unreadable")
	}
}

func TestSettingsDieWithClient(t *testing.T) {
	f := newFEnv(t, func(c *core.ClientFAPI) { c.RequirePAR = true }, devOpts{})
	c := context.Background()
	if err := f.st.DeleteClient(c, "r", f.cl.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.st.CreateClient(c, core.Client{Realm: "r", ClientID: "fapi", Enabled: true, AuthCodeFlow: true,
		SecretHash: HashSecret("s3cret"), RedirectURIs: []string{cb}}); err != nil {
		t.Fatal(err)
	}
	// The new client of the same client_id must not inherit the old keys or switches.
	if code, out := f.push(url.Values{"request": {f.jar(t, "ES256", f.objClaims(nil), nil)}}); code != 400 {
		t.Fatalf("keys of a deleted client still verify: %d %v", code, out)
	}
	q := authQuery(map[string]string{"client_id": "fapi"})
	if w := f.browser().do("GET", base+"auth?"+q.Encode(), nil); w.Code != 200 {
		t.Fatalf("re-created client inherited require-PAR: %d", w.Code)
	}
}

func TestPARResponseHeaders(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	req := httptest.NewRequest("POST", "/realms/r/protocol/openid-connect/par", strings.NewReader(pkce().Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("fapi", "s3cret")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["expires_in"] != float64(60) {
		t.Fatalf("expires_in: %v", out["expires_in"])
	}
}
