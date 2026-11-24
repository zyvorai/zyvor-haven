// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
)

// ---- fakes ----

type fakeStore struct {
	core.Store
	mu      sync.Mutex
	realms  map[string]core.Realm
	users   map[string]core.User // by id
	clients map[string]core.Client
	codes   map[string]core.AuthCode
	refresh map[string]core.RefreshToken
	events  []core.Event
	sess    map[string]core.Session // SSO sessions by id (methods in sso_test.go)
}

func (s *fakeStore) GetRealm(_ context.Context, n string) (core.Realm, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.realms[n]; ok {
		return r, nil
	}
	return core.Realm{}, idp.ErrNotFound
}
func (s *fakeStore) GetClientByClientID(_ context.Context, realm, id string) (core.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.clients {
		if c.Realm == realm && c.ClientID == id {
			return c, nil
		}
	}
	return core.Client{}, idp.ErrNotFound
}
func (s *fakeStore) GetUser(_ context.Context, realm, id string) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[id]; ok && u.Realm == realm {
		return u, nil
	}
	return core.User{}, idp.ErrNotFound
}
func (s *fakeStore) GetUserByUsername(_ context.Context, realm, name string) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Realm == realm && strings.EqualFold(u.Username, name) {
			return u, nil
		}
	}
	return core.User{}, idp.ErrNotFound
}
func (s *fakeStore) UpdateUser(_ context.Context, u core.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.ID] = u
	return nil
}
func (s *fakeStore) PutAuthCode(_ context.Context, c core.AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[c.CodeHash] = c
	return nil
}
func (s *fakeStore) ConsumeAuthCode(_ context.Context, h string) (core.AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[h]
	if !ok {
		return core.AuthCode{}, idp.ErrNotFound
	}
	delete(s.codes, h)
	return c, nil
}
func (s *fakeStore) PutRefreshToken(_ context.Context, t core.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[t.TokenHash] = t
	return nil
}
func (s *fakeStore) GetRefreshToken(_ context.Context, h string) (core.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.refresh[h]; ok {
		return t, nil
	}
	return core.RefreshToken{}, idp.ErrNotFound
}
func (s *fakeStore) MarkRefreshUsed(_ context.Context, h string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[h]
	if !ok {
		return idp.ErrNotFound
	}
	if t.Used {
		return idp.ErrConflict
	}
	t.Used = true
	s.refresh[h] = t
	return nil
}
func (s *fakeStore) RevokeRefreshFamily(_ context.Context, f string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, t := range s.refresh {
		if t.FamilyID == f {
			t.Revoked = true
			s.refresh[h] = t
		}
	}
	return nil
}
func (s *fakeStore) AppendEvent(_ context.Context, e core.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

type fakeSigner struct{ now func() time.Time }

func (fakeSigner) EnsureKey(context.Context, string) error { return nil }
func (fakeSigner) Rotate(context.Context, string) error    { return nil }
func (fakeSigner) JWKS(context.Context, string) ([]byte, error) {
	return []byte(`{"keys":[]}`), nil
}
func (fakeSigner) Sign(_ context.Context, realm string, c core.Claims) (string, error) {
	b, _ := json.Marshal(c)
	return "h." + base64.RawURLEncoding.EncodeToString(b) + "." + realm, nil
}
func (f fakeSigner) Verify(_ context.Context, realm, tok string) (core.Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != "h" || parts[2] != realm {
		return nil, errors.New("bad token")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c core.Claims
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if exp, ok := c["exp"].(float64); ok && !f.now().Before(time.Unix(int64(exp), 0)) {
		return nil, errors.New("expired")
	}
	return c, nil
}

type fakeHasher struct{}

func (fakeHasher) Hash(p string) (string, error) { return "H:" + p, nil }
func (fakeHasher) Verify(p, enc string) (bool, bool) {
	if enc == "H:"+p {
		return true, false
	}
	if enc == "OLD:"+p {
		return true, true
	}
	return false, false
}

// ---- harness ----

type env struct {
	t     *testing.T
	st    *fakeStore
	h     *Provider
	now   time.Time
	realm core.Realm
}

const (
	cb       = "https://app.example/cb"
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func challenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func newEnv(t *testing.T, mut func(*core.Realm)) *env {
	e := &env{t: t, now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	e.realm = core.Realm{Name: "r", Enabled: true, BruteForceProtection: true, RefreshTokenRotation: true,
		AuthEventsLogged: true, AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour}
	if mut != nil {
		mut(&e.realm)
	}
	e.st = &fakeStore{
		realms: map[string]core.Realm{"r": e.realm},
		users: map[string]core.User{"u1": {ID: "u1", Realm: "r", Username: "alice", Email: "a@x", Enabled: true,
			EmailVerified: true, PasswordHash: "H:pw", Roles: []string{"admin"}}},
		clients: map[string]core.Client{
			"c1": {ID: "c1", Realm: "r", ClientID: "app", Enabled: true, Public: true, AuthCodeFlow: true, RedirectURIs: []string{cb}},
			"c2": {ID: "c2", Realm: "r", ClientID: "svc", Enabled: true, SecretHash: HashSecret("s3cret"),
				AuthCodeFlow: true, ServiceAccount: true, RedirectURIs: []string{"https://svc.example/cb"}},
		},
		codes: map[string]core.AuthCode{}, refresh: map[string]core.RefreshToken{},
	}
	clock := func() time.Time { return e.now }
	e.h = New(Config{Store: e.st, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{},
		BaseURL: "https://idp.example", Clock: clock, CSRFKey: []byte("0123456789abcdef0123456789abcdef")})
	return e
}

func (e *env) do(req *http.Request) *httptest.ResponseRecorder {
	req.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

const base = "/realms/r/protocol/openid-connect/"

func authQuery(over map[string]string) url.Values {
	q := url.Values{"client_id": {"app"}, "redirect_uri": {cb}, "response_type": {"code"}, "state": {"st8"},
		"scope": {"openid profile email offline_access"}, "nonce": {"n0nce"},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	for k, v := range over {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// loginForm GETs the login page and returns the csrf token and cookie.
func (e *env) loginForm(q url.Values) (string, *http.Cookie) {
	w := e.do(httptest.NewRequest("GET", base+"auth?"+q.Encode(), nil))
	if w.Code != 200 {
		e.t.Fatalf("login page status %d: %s", w.Code, w.Body)
	}
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		e.t.Fatal("no csrf field")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == csrfCookie {
			return m[1], c
		}
	}
	e.t.Fatal("no csrf cookie")
	return "", nil
}

func (e *env) postLogin(q url.Values, user, pw, csrf string, ck *http.Cookie) *httptest.ResponseRecorder {
	form := url.Values{"username": {user}, "password": {pw}, "csrf": {csrf}}
	req := httptest.NewRequest("POST", base+"auth?"+q.Encode(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if ck != nil {
		req.AddCookie(ck)
	}
	return e.do(req)
}

func (e *env) login(q url.Values, user, pw string) *httptest.ResponseRecorder {
	csrf, ck := e.loginForm(q)
	return e.postLogin(q, user, pw, csrf, ck)
}

func (e *env) getCode(q url.Values) string {
	w := e.login(q, "alice", "pw")
	if w.Code != 302 {
		e.t.Fatalf("login status %d: %s", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("state") != "st8" || loc.Query().Get("iss") != "https://idp.example/realms/r" {
		e.t.Fatalf("bad redirect %s", loc)
	}
	return loc.Query().Get("code")
}

func (e *env) tokenReq(form url.Values, basicUser, basicPass string) (int, map[string]any, http.Header) {
	req := httptest.NewRequest("POST", base+"token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	w := e.do(req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Header()
}

func codeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb},
		"client_id": {"app"}, "code_verifier": {verifier}}
}

func claimsOf(t *testing.T, tok string) map[string]any {
	parts := strings.Split(tok, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

// ---- tests ----

func TestDiscovery(t *testing.T) {
	e := newEnv(t, nil)
	w := e.do(httptest.NewRequest("GET", "/realms/r/.well-known/openid-configuration", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var d map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	if d["issuer"] != "https://idp.example/realms/r" || d["token_endpoint"] != "https://idp.example/realms/r/protocol/openid-connect/token" {
		t.Fatalf("bad doc %v", d)
	}
	if fmt.Sprint(d["code_challenge_methods_supported"]) != "[S256]" ||
		fmt.Sprint(d["id_token_signing_alg_values_supported"]) != "[ES256]" ||
		fmt.Sprint(d["grant_types_supported"]) != "[authorization_code refresh_token client_credentials]" ||
		fmt.Sprint(d["token_endpoint_auth_methods_supported"]) != "[client_secret_basic client_secret_post none]" {
		t.Fatalf("bad advertised capabilities %v", d)
	}
	if w := e.do(httptest.NewRequest("GET", "/realms/nope/.well-known/openid-configuration", nil)); w.Code != 404 {
		t.Fatalf("unknown realm: %d", w.Code)
	}
	if w := e.do(httptest.NewRequest("GET", base+"certs", nil)); w.Code != 200 || !strings.Contains(w.Body.String(), "keys") {
		t.Fatalf("certs %d", w.Code)
	}
}

func TestHappyPath(t *testing.T) {
	e := newEnv(t, nil)
	code := e.getCode(authQuery(nil))
	if len(e.st.codes) != 1 {
		t.Fatal("code not stored")
	}
	for h := range e.st.codes {
		if h == code || h != HashSecret(code) {
			t.Fatal("code must be stored hashed")
		}
	}
	status, tok, hdr := e.tokenReq(codeForm(code), "", "")
	if status != 200 {
		t.Fatalf("token status %d %v", status, tok)
	}
	if hdr.Get("Cache-Control") != "no-store" || hdr.Get("Pragma") != "no-cache" {
		t.Fatal("missing no-store headers")
	}
	at := claimsOf(t, tok["access_token"].(string))
	if at["iss"] != "https://idp.example/realms/r" || at["sub"] != "u1" || at["aud"] != "app" || at["azp"] != "app" {
		t.Fatalf("access claims %v", at)
	}
	if fmt.Sprint(at["realm_access"]) != "map[roles:[admin]]" {
		t.Fatalf("roles %v", at["realm_access"])
	}
	idc := claimsOf(t, tok["id_token"].(string))
	sum := sha256.Sum256([]byte(tok["access_token"].(string)))
	if idc["nonce"] != "n0nce" || idc["auth_time"] == nil || idc["at_hash"] != base64.RawURLEncoding.EncodeToString(sum[:16]) {
		t.Fatalf("id claims %v", idc)
	}
	if tok["refresh_token"] == nil {
		t.Fatal("expected refresh token")
	}

	// userinfo
	req := httptest.NewRequest("GET", base+"userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	w := e.do(req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"email":"a@x"`) {
		t.Fatalf("userinfo %d %s", w.Code, w.Body)
	}
	// id token is not a valid access token
	req = httptest.NewRequest("GET", base+"userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["id_token"].(string))
	if w := e.do(req); w.Code != 401 {
		t.Fatalf("id_token accepted at userinfo: %d", w.Code)
	}
	// expired
	e.now = e.now.Add(time.Hour)
	req = httptest.NewRequest("GET", base+"userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	if w := e.do(req); w.Code != 401 {
		t.Fatalf("expired token accepted: %d", w.Code)
	}
	if len(e.st.events) == 0 || e.st.events[0].Type != "LOGIN" {
		t.Fatalf("events %v", e.st.events)
	}
}

func TestLoginPageHeaders(t *testing.T) {
	e := newEnv(t, nil)
	w := e.do(httptest.NewRequest("GET", base+"auth?"+authQuery(nil).Encode(), nil))
	h := w.Header()
	if h.Get("Cache-Control") != "no-store" || h.Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		!strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("headers %v", h)
	}
	if strings.Contains(w.Body.String(), "http://") || strings.Contains(w.Body.String(), "https://") {
		t.Fatal("login page references external assets")
	}
}

func TestWrongVerifierAndReplay(t *testing.T) {
	e := newEnv(t, nil)
	code := e.getCode(authQuery(nil))
	f := codeForm(code)
	f.Set("code_verifier", strings.Repeat("a", 43))
	if status, body, _ := e.tokenReq(f, "", ""); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %v", status, body)
	}
	// code is burned even by the failed attempt
	if status, body, _ := e.tokenReq(codeForm(code), "", ""); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("burned code accepted: %d %v", status, body)
	}

	// Replay after success revokes the refresh family.
	code = e.getCode(authQuery(nil))
	status, tok, _ := e.tokenReq(codeForm(code), "", "")
	if status != 200 {
		t.Fatal(status, tok)
	}
	if status, _, _ := e.tokenReq(codeForm(code), "", ""); status != 400 {
		t.Fatal("replay accepted")
	}
	status, body, _ := e.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {"app"}}, "", "")
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("refresh token survived code replay: %d %v", status, body)
	}
}

func TestCodeBindingAndExpiry(t *testing.T) {
	e := newEnv(t, nil)
	code := e.getCode(authQuery(nil))
	f := codeForm(code)
	f.Set("redirect_uri", "https://app.example/other")
	if status, _, _ := e.tokenReq(f, "", ""); status != 400 {
		t.Fatal("redirect mismatch accepted")
	}
	code = e.getCode(authQuery(nil))
	e.now = e.now.Add(2 * time.Minute)
	if status, _, _ := e.tokenReq(codeForm(code), "", ""); status != 400 {
		t.Fatal("expired code accepted")
	}
}

func TestAuthorizeRedirectURIMismatchNeverRedirects(t *testing.T) {
	e := newEnv(t, nil)
	for _, ru := range []string{"https://evil.example/cb", cb + "/", cb + "?x=1", "https://app.example/cb#f", ""} {
		w := e.do(httptest.NewRequest("GET", base+"auth?"+authQuery(map[string]string{"redirect_uri": ru}).Encode(), nil))
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("redirect_uri %q: status %d location %q", ru, w.Code, w.Header().Get("Location"))
		}
	}
	for _, q := range []url.Values{authQuery(map[string]string{"client_id": "nope"}), authQuery(map[string]string{"client_id": ""})} {
		if w := e.do(httptest.NewRequest("GET", base+"auth?"+q.Encode(), nil)); w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("unknown client: %d", w.Code)
		}
	}
	if w := e.do(httptest.NewRequest("GET", "/realms/zzz/protocol/openid-connect/auth?"+authQuery(nil).Encode(), nil)); w.Code != 404 || w.Header().Get("Location") != "" {
		t.Fatalf("unknown realm: %d", w.Code)
	}
}

func TestAuthorizeParamErrorsRedirect(t *testing.T) {
	e := newEnv(t, nil)
	cases := map[string]map[string]string{
		"plain method":     {"code_challenge_method": "plain"},
		"missing method":   {"code_challenge_method": ""},
		"missing pkce":     {"code_challenge": "", "code_challenge_method": ""},
		"bad response":     {"response_type": "token"},
		"missing state":    {"state": ""},
		"prompt none":      {"prompt": "none"},
		"request object":   {"request": "eyJ"},
		"short challenge":  {"code_challenge": "abc"},
		"bad response_mod": {"response_mode": "fragment"},
	}
	for name, over := range cases {
		w := e.do(httptest.NewRequest("GET", base+"auth?"+authQuery(over).Encode(), nil))
		if w.Code != 302 {
			t.Fatalf("%s: status %d", name, w.Code)
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		if loc.Host != "app.example" || loc.Query().Get("error") == "" || loc.Query().Get("code") != "" {
			t.Fatalf("%s: bad redirect %s", name, loc)
		}
		if name != "missing state" && loc.Query().Get("state") != "st8" {
			t.Fatalf("%s: state not echoed", name)
		}
	}
	w := e.do(httptest.NewRequest("GET", base+"auth?"+authQuery(map[string]string{"prompt": "none"}).Encode(), nil))
	if !strings.Contains(w.Header().Get("Location"), "error=login_required") {
		t.Fatal("prompt=none must return login_required")
	}
}

func TestRequirePKCEConfidential(t *testing.T) {
	e := newEnv(t, nil)
	q := authQuery(map[string]string{"client_id": "svc", "redirect_uri": "https://svc.example/cb", "code_challenge": "", "code_challenge_method": ""})
	// confidential without RequirePKCE: allowed to show login
	if w := e.do(httptest.NewRequest("GET", base+"auth?"+q.Encode(), nil)); w.Code != 200 {
		t.Fatalf("optional pkce: %d", w.Code)
	}
	c := e.st.clients["c2"]
	c.RequirePKCE = true
	e.st.clients["c2"] = c
	if w := e.do(httptest.NewRequest("GET", base+"auth?"+q.Encode(), nil)); w.Code != 302 {
		t.Fatalf("RequirePKCE not enforced: %d", w.Code)
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t, nil)
	q := authQuery(nil)
	csrf, ck := e.loginForm(q)
	// no cookie
	if w := e.postLogin(q, "alice", "pw", csrf, nil); w.Code != 403 {
		t.Fatalf("no cookie: %d", w.Code)
	}
	// no field
	if w := e.postLogin(q, "alice", "pw", "", ck); w.Code != 403 {
		t.Fatalf("no field: %d", w.Code)
	}
	// forged
	bad := &http.Cookie{Name: csrfCookie, Value: "AAAA.BBBB"}
	if w := e.postLogin(q, "alice", "pw", "AAAA.BBBB", bad); w.Code != 403 {
		t.Fatalf("forged: %d", w.Code)
	}
	// valid MAC but mismatching cookie
	csrf2, _ := e.loginForm(q)
	if w := e.postLogin(q, "alice", "pw", csrf2, ck); w.Code != 403 {
		t.Fatalf("mismatch: %d", w.Code)
	}
	// expired
	e.now = e.now.Add(csrfTTL + time.Minute)
	if w := e.postLogin(q, "alice", "pw", csrf, ck); w.Code != 403 {
		t.Fatalf("expired: %d", w.Code)
	}
	if len(e.st.codes) != 0 {
		t.Fatal("code issued despite CSRF failure")
	}
}

func TestLoginFailuresAndLockout(t *testing.T) {
	e := newEnv(t, nil)
	q := authQuery(nil)
	for i := 0; i < 5; i++ {
		w := e.login(q, "alice", "wrong")
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Invalid username or password") {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	u := e.st.users["u1"]
	if u.FailedLogins != 5 || !u.LockedUntil.After(e.now) {
		t.Fatalf("not locked: %+v", u)
	}
	// correct password while locked is still refused, with the same message
	w := e.login(q, "alice", "pw")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Invalid username or password") {
		t.Fatalf("locked login: %d", w.Code)
	}
	// after lock expiry, success resets counters
	e.now = e.now.Add(16 * time.Minute)
	if w := e.login(q, "alice", "pw"); w.Code != 302 {
		t.Fatalf("post-lock login: %d", w.Code)
	}
	if u := e.st.users["u1"]; u.FailedLogins != 0 || !u.LockedUntil.IsZero() {
		t.Fatalf("not reset: %+v", u)
	}
	// unknown user: same message, error event, no user-specific detail
	w = e.login(q, "nobody", "x")
	if !strings.Contains(w.Body.String(), "Invalid username or password") {
		t.Fatal("unknown user message differs")
	}
	var sawErr bool
	for _, ev := range e.st.events {
		if ev.Type == "LOGIN_ERROR" {
			sawErr = true
		}
		if strings.Contains(ev.Detail, "wrong") || strings.Contains(ev.Detail, "pw") && ev.Detail != "invalid_credentials" && ev.Detail != "user_not_found" && ev.Detail != "user_temporarily_disabled" {
			t.Fatalf("event leaks: %+v", ev)
		}
	}
	if !sawErr {
		t.Fatal("no LOGIN_ERROR event")
	}
}

func TestLoginDisabledUnverifiedRehash(t *testing.T) {
	e := newEnv(t, func(r *core.Realm) { r.EmailVerificationRequired = true })
	q := authQuery(nil)
	u := e.st.users["u1"]
	u.EmailVerified = false
	e.st.users["u1"] = u
	w := e.login(q, "alice", "pw")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "not been verified") {
		t.Fatalf("unverified: %d %s", w.Code, w.Body)
	}
	u.EmailVerified, u.Enabled = true, false
	e.st.users["u1"] = u
	if w := e.login(q, "alice", "pw"); w.Code != 200 {
		t.Fatalf("disabled: %d", w.Code)
	}
	u.Enabled, u.PasswordHash = true, "OLD:pw"
	e.st.users["u1"] = u
	if w := e.login(q, "alice", "pw"); w.Code != 302 {
		t.Fatalf("rehash login: %d", w.Code)
	}
	if e.st.users["u1"].PasswordHash != "H:pw" {
		t.Fatal("password not rehashed")
	}
}

func TestLoginPageEscapesInput(t *testing.T) {
	e := newEnv(t, nil)
	c := e.st.clients["c1"]
	c.Name = `<script>alert(1)</script>`
	e.st.clients["c1"] = c
	w := e.do(httptest.NewRequest("GET", base+"auth?"+authQuery(nil).Encode(), nil))
	if strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("client name not escaped")
	}
}

func TestRefreshRotationAndReuse(t *testing.T) {
	e := newEnv(t, nil)
	_, tok, _ := e.tokenReq(codeForm(e.getCode(authQuery(nil))), "", "")
	r1 := tok["refresh_token"].(string)
	rf := func(r string) (int, map[string]any) {
		s, b, _ := e.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r}, "client_id": {"app"}}, "", "")
		return s, b
	}
	s, b := rf(r1)
	if s != 200 || b["refresh_token"] == nil || b["refresh_token"] == r1 || b["access_token"] == nil {
		t.Fatalf("rotation: %d %v", s, b)
	}
	r2 := b["refresh_token"].(string)
	if e.st.refresh[HashSecret(r2)].FamilyID != e.st.refresh[HashSecret(r1)].FamilyID {
		t.Fatal("family changed on rotation")
	}
	// reuse of r1 revokes the family, killing r2
	if s, b := rf(r1); s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", s, b)
	}
	if s, b := rf(r2); s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("family survived reuse: %d %v", s, b)
	}
	// another client cannot use the token
	_, tok, _ = e.tokenReq(codeForm(e.getCode(authQuery(nil))), "", "")
	s, _, _ = e.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}}, "svc", "s3cret")
	if s != 400 {
		t.Fatalf("cross-client refresh: %d", s)
	}
}

func TestClientAuthAndCredentialsGrant(t *testing.T) {
	e := newEnv(t, nil)
	form := url.Values{"grant_type": {"client_credentials"}}
	s, b, h := e.tokenReq(form, "svc", "wrong")
	if s != 401 || b["error"] != "invalid_client" || h.Get("WWW-Authenticate") == "" {
		t.Fatalf("bad secret: %d %v", s, b)
	}
	s, b, _ = e.tokenReq(form, "svc", "s3cret")
	if s != 200 || b["id_token"] != nil || b["refresh_token"] != nil {
		t.Fatalf("basic cc: %d %v", s, b)
	}
	if c := claimsOf(t, b["access_token"].(string)); c["sub"] != "service-account-svc" {
		t.Fatalf("claims %v", c)
	}
	post := url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"s3cret"}}
	if s, _, _ := e.tokenReq(post, "", ""); s != 200 {
		t.Fatalf("post auth: %d", s)
	}
	// public clients cannot use client_credentials
	if s, b, _ := e.tokenReq(url.Values{"grant_type": {"client_credentials"}, "client_id": {"app"}}, "", ""); s != 400 || b["error"] != "unauthorized_client" {
		t.Fatalf("public cc: %d %v", s, b)
	}
	// no ServiceAccount
	c := e.st.clients["c2"]
	c.ServiceAccount = false
	e.st.clients["c2"] = c
	if s, _, _ := e.tokenReq(form, "svc", "s3cret"); s != 400 {
		t.Fatalf("cc without service account: %d", s)
	}
	// password grant is not implemented
	if s, b, _ := e.tokenReq(url.Values{"grant_type": {"password"}, "username": {"alice"}, "password": {"pw"}}, "svc", "s3cret"); s != 400 || b["error"] != "unsupported_grant_type" {
		t.Fatalf("password grant: %d %v", s, b)
	}
}

func TestIntrospectionAndRevoke(t *testing.T) {
	e := newEnv(t, nil)
	_, tok, _ := e.tokenReq(codeForm(e.getCode(authQuery(nil))), "", "")
	at := tok["access_token"].(string)
	intro := func(user, pass, token string, extra url.Values) (int, map[string]any) {
		f := url.Values{"token": {token}}
		for k, v := range extra {
			f[k] = v
		}
		req := httptest.NewRequest("POST", base+"token/introspect", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		w := e.do(req)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	if s, _ := intro("", "", at, nil); s != 401 {
		t.Fatalf("anonymous introspection: %d", s)
	}
	if s, _ := intro("", "", at, url.Values{"client_id": {"app"}}); s != 401 {
		t.Fatalf("public client introspection: %d", s)
	}
	if s, _ := intro("svc", "bad", at, nil); s != 401 {
		t.Fatalf("bad secret introspection: %d", s)
	}
	s, m := intro("svc", "s3cret", at, nil)
	if s != 200 || m["active"] != true || m["client_id"] != "app" || m["sub"] != "u1" {
		t.Fatalf("introspect: %d %v", s, m)
	}
	if _, m := intro("svc", "s3cret", "garbage", nil); m["active"] != false {
		t.Fatalf("garbage active: %v", m)
	}
	rt := tok["refresh_token"].(string)
	if _, m := intro("svc", "s3cret", rt, nil); m["active"] != true {
		t.Fatalf("refresh inactive: %v", m)
	}
	// revoke as the owning public client
	req := httptest.NewRequest("POST", base+"revoke", strings.NewReader(url.Values{"token": {rt}, "client_id": {"app"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if w := e.do(req); w.Code != 200 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if _, m := intro("svc", "s3cret", rt, nil); m["active"] != false {
		t.Fatalf("revoked token still active: %v", m)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t, nil)
	_, tok, _ := e.tokenReq(codeForm(e.getCode(authQuery(nil))), "", "")
	idt := tok["id_token"].(string)
	// the fake id_token has typ ID; logout only needs a verifiable token
	q := url.Values{"id_token_hint": {idt}, "post_logout_redirect_uri": {cb}, "state": {"xyz"}}
	w := e.do(httptest.NewRequest("GET", base+"logout?"+q.Encode(), nil))
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), cb+"?state=xyz") {
		t.Fatalf("logout: %d %s", w.Code, w.Header().Get("Location"))
	}
	q.Set("post_logout_redirect_uri", "https://evil.example/")
	if w := e.do(httptest.NewRequest("GET", base+"logout?"+q.Encode(), nil)); w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("evil logout redirect: %d", w.Code)
	}
	q = url.Values{"post_logout_redirect_uri": {cb}}
	if w := e.do(httptest.NewRequest("GET", base+"logout?"+q.Encode(), nil)); w.Code != 400 {
		t.Fatalf("redirect without client: %d", w.Code)
	}
	if w := e.do(httptest.NewRequest("GET", base+"logout", nil)); w.Code != 200 {
		t.Fatalf("plain logout: %d", w.Code)
	}
}

func TestBodyLimitAndProxyTrust(t *testing.T) {
	e := newEnv(t, nil)
	big := strings.NewReader("grant_type=authorization_code&code=" + strings.Repeat("a", 70<<10))
	req := httptest.NewRequest("POST", base+"token", big)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if w := e.do(req); w.Code != 400 {
		t.Fatalf("oversize body: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.1:1"
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	if ip := e.h.clientIP(r); ip != "192.0.2.1" {
		t.Fatalf("XFF trusted by default: %s", ip)
	}
	e.h.cfg.TrustProxy = true
	if ip := e.h.clientIP(r); ip != "6.6.6.6" {
		t.Fatalf("XFF ignored when trusted: %s", ip)
	}
}
