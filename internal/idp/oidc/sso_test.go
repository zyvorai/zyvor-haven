// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
)

// ---- fakeStore session methods ----

func (s *fakeStore) PutSession(_ context.Context, x core.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess == nil {
		s.sess = map[string]core.Session{}
	}
	s.sess[x.ID] = x
	return nil
}

func (s *fakeStore) GetSession(_ context.Context, realm, id string) (core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.sess[id]; ok && x.Realm == realm {
		return x, nil
	}
	return core.Session{}, idp.ErrNotFound
}

func (s *fakeStore) GetSessionByCookie(_ context.Context, realm, hash string) (core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.sess {
		if x.Realm == realm && x.CookieHash == hash {
			return x, nil
		}
	}
	return core.Session{}, idp.ErrNotFound
}

func (s *fakeStore) TouchSession(_ context.Context, realm, id string, seen, idle time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sess[id]
	if !ok || x.Realm != realm {
		return idp.ErrNotFound
	}
	x.LastSeen, x.IdleExpires = seen, idle
	s.sess[id] = x
	return nil
}

func (s *fakeStore) AddSessionClient(_ context.Context, realm, id, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sess[id]
	if !ok || x.Realm != realm {
		return idp.ErrNotFound
	}
	if !slices.Contains(x.Clients, clientID) {
		x.Clients = append(slices.Clone(x.Clients), clientID)
		s.sess[id] = x
	}
	return nil
}

func (s *fakeStore) TakeSession(_ context.Context, realm, id string) (core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sess[id]
	if !ok || x.Realm != realm {
		return core.Session{}, idp.ErrNotFound
	}
	delete(s.sess, id)
	return x, nil
}

func (s *fakeStore) TakeUserSessions(_ context.Context, realm, userID string) ([]core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []core.Session
	for k, x := range s.sess {
		if x.Realm == realm && x.UserID == userID {
			out = append(out, x)
			delete(s.sess, k)
		}
	}
	return out, nil
}

func (s *fakeStore) RevokeSessionRefreshTokens(_ context.Context, realm, sid string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for h, t := range s.refresh {
		if t.Realm == realm && t.SessionID == sid && !t.Revoked && !slices.Contains(strings.Fields(t.Scope), "offline_access") {
			t.Revoked = true
			s.refresh[h] = t
			n++
		}
	}
	return n, nil
}

// ---- helpers ----

func ssoCookieOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == ssoCookie && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func (e *env) authGet(q url.Values, ck *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", base+"auth?"+q.Encode(), nil)
	if ck != nil {
		req.AddCookie(ck)
	}
	return e.do(req)
}

// ssoLogin signs in with the form and returns the SSO cookie.
func (e *env) ssoLogin(q url.Values) (*http.Cookie, *httptest.ResponseRecorder) {
	e.t.Helper()
	w := e.login(q, "alice", "pw")
	if w.Code != 302 {
		e.t.Fatalf("login status %d: %s", w.Code, w.Body)
	}
	ck := ssoCookieOf(w)
	if ck == nil {
		e.t.Fatal("no SSO cookie set")
	}
	return ck, w
}

func locOf(t *testing.T, w *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if w.Code != 302 {
		t.Fatalf("want redirect, got %d: %s", w.Code, w.Body)
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func (e *env) onlySession() core.Session {
	e.t.Helper()
	e.st.mu.Lock()
	defer e.st.mu.Unlock()
	if len(e.st.sess) != 1 {
		e.t.Fatalf("want exactly one session, have %d", len(e.st.sess))
	}
	for _, s := range e.st.sess {
		return s
	}
	return core.Session{}
}

func (e *env) sessionCount() int {
	e.st.mu.Lock()
	defer e.st.mu.Unlock()
	return len(e.st.sess)
}

func (e *env) wantCode(w *httptest.ResponseRecorder, what string) string {
	e.t.Helper()
	q := locOf(e.t, w)
	if q.Get("code") == "" || q.Get("state") != "st8" {
		e.t.Fatalf("%s: want a code redirect, got %v", what, q)
	}
	return q.Get("code")
}

func (e *env) wantForm(w *httptest.ResponseRecorder, what string) {
	e.t.Helper()
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="csrf"`) {
		e.t.Fatalf("%s: want login form, got %d %s", what, w.Code, w.Header().Get("Location"))
	}
}

func (e *env) wantErr(w *httptest.ResponseRecorder, code, what string) {
	e.t.Helper()
	q := locOf(e.t, w)
	if q.Get("error") != code || q.Get("code") != "" {
		e.t.Fatalf("%s: want error=%s, got %v", what, code, q)
	}
}

// ---- tests ----

func TestSSOCookieAttributesAndHashOnly(t *testing.T) {
	e := newEnv(t, nil)
	ck, w := e.ssoLogin(authQuery(nil))
	if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/realms/r" || !ck.Secure {
		t.Fatalf("cookie attributes: %+v", ck)
	}
	if ck.Expires.IsZero() {
		t.Error("cookie has no expiry")
	}
	s := e.onlySession()
	if s.CookieHash == ck.Value || s.CookieHash != actions.Hash(ck.Value) {
		t.Fatalf("session must store only sha256(cookie): %q", s.CookieHash)
	}
	if strings.Contains(s.ID, ck.Value) || s.ID == "" || s.UserID != "u1" || s.Realm != "r" {
		t.Fatalf("session %+v", s)
	}
	if !s.AuthTime.Equal(e.now) || !s.IdleExpires.Equal(e.now.Add(defaultIdle)) || !s.ExpiresAt.Equal(e.now.Add(maxSessionLife)) {
		t.Fatalf("session times %+v", s)
	}
	if !slices.Contains(s.Clients, "app") {
		t.Fatalf("client not recorded: %v", s.Clients)
	}
	code := locOf(t, w).Get("code")
	if e.st.codes[HashSecret(code)].SessionID != s.ID {
		t.Fatal("auth code does not carry the session id")
	}

	// A plain-http base URL must not mark the cookie Secure.
	e2 := newEnv(t, nil)
	clock := func() time.Time { return e2.now }
	e2.h = New(Config{Store: e2.st, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{},
		BaseURL: "http://idp.local", Clock: clock, CSRFKey: []byte("0123456789abcdef0123456789abcdef")})
	ck2, _ := e2.ssoLogin(authQuery(nil))
	if ck2.Secure {
		t.Error("cookie is Secure on an http base URL")
	}
}

func TestSSOReuseIssuesCodeWithoutForm(t *testing.T) {
	e := newEnv(t, nil)
	ck, _ := e.ssoLogin(authQuery(nil))
	s0 := e.onlySession()
	e.now = e.now.Add(10 * time.Minute)
	w := e.authGet(authQuery(nil), ck)
	code := e.wantCode(w, "second /auth")
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "iss=") {
		t.Errorf("missing iss: %s", loc)
	}
	s1 := e.onlySession()
	if s1.ID != s0.ID {
		t.Fatal("SSO reuse must not create a new session")
	}
	if !s1.LastSeen.Equal(e.now) || !s1.IdleExpires.Equal(e.now.Add(defaultIdle)) {
		t.Fatalf("session not touched: %+v", s1)
	}
	last := e.st.events[len(e.st.events)-1]
	if last.Type != "LOGIN" || last.Detail != "sso" || last.UserID != "u1" || last.ClientID != "app" {
		t.Fatalf("event %+v", last)
	}
	// The SSO code redeems like any other and carries sid and the TRUE auth_time.
	status, tok, _ := e.tokenReq(codeForm(code), "", "")
	if status != 200 {
		t.Fatalf("token: %d %v", status, tok)
	}
	idc, at := claimsOf(t, tok["id_token"].(string)), claimsOf(t, tok["access_token"].(string))
	if idc["sid"] != s0.ID || at["sid"] != s0.ID {
		t.Fatalf("sid claims: id=%v at=%v want %s", idc["sid"], at["sid"], s0.ID)
	}
	if int64(idc["auth_time"].(float64)) != s0.AuthTime.Unix() || s0.AuthTime.Equal(e.now) {
		t.Fatalf("auth_time %v want %d (not now %d)", idc["auth_time"], s0.AuthTime.Unix(), e.now.Unix())
	}
	if e.st.refresh[HashSecret(tok["refresh_token"].(string))].SessionID != s0.ID {
		t.Fatal("refresh token does not carry the session id")
	}
}

func TestPromptNone(t *testing.T) {
	e := newEnv(t, nil)
	q := authQuery(map[string]string{"prompt": "none"})
	e.wantErr(e.authGet(q, nil), "login_required", "no session")
	if e.sessionCount() != 0 {
		t.Fatal("prompt=none without a session created one")
	}
	ck, _ := e.ssoLogin(authQuery(nil))
	e.wantCode(e.authGet(q, ck), "prompt=none with session")
	// Expired session behaves as none.
	e.now = e.now.Add(defaultIdle + time.Minute)
	e.wantErr(e.authGet(q, ck), "login_required", "idle-expired session")
	// none + login is a contradiction.
	e.wantErr(e.authGet(authQuery(map[string]string{"prompt": "none login"}), ck), "invalid_request", "none login")
	e.wantErr(e.authGet(authQuery(map[string]string{"prompt": "login none"}), ck), "invalid_request", "login none")
}

func TestPromptLoginForcesForm(t *testing.T) {
	e := newEnv(t, nil)
	ck, _ := e.ssoLogin(authQuery(nil))
	old := e.onlySession()
	q := authQuery(map[string]string{"prompt": "login"})
	e.wantForm(e.authGet(q, ck), "prompt=login")
	// A successful login with the old cookie replaces the session.
	csrf, cc := e.loginForm(q)
	req := httptest.NewRequest("POST", base+"auth?"+q.Encode(),
		strings.NewReader(url.Values{"username": {"alice"}, "password": {"pw"}, "csrf": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cc)
	req.AddCookie(ck)
	w := e.do(req)
	e.wantCode(w, "re-login")
	nck := ssoCookieOf(w)
	if nck == nil || nck.Value == ck.Value {
		t.Fatal("re-login must set a fresh cookie")
	}
	if cur := e.onlySession(); cur.ID == old.ID {
		t.Fatal("re-login must replace the session")
	}
}

func TestMaxAge(t *testing.T) {
	e := newEnv(t, nil)
	ck, _ := e.ssoLogin(authQuery(nil))
	e.now = e.now.Add(5 * time.Minute)
	e.wantCode(e.authGet(authQuery(map[string]string{"max_age": "600"}), ck), "max_age ok")
	e.wantForm(e.authGet(authQuery(map[string]string{"max_age": "60"}), ck), "max_age exceeded")
	e.wantForm(e.authGet(authQuery(map[string]string{"max_age": "0"}), ck), "max_age=0")
	e.wantErr(e.authGet(authQuery(map[string]string{"max_age": "60", "prompt": "none"}), ck), "login_required", "none+max_age exceeded")
	e.wantCode(e.authGet(authQuery(map[string]string{"max_age": "600", "prompt": "none"}), ck), "none+max_age ok")
	for _, bad := range []string{"abc", "-1", "1.5", ""} {
		q := authQuery(nil)
		q.Set("max_age", bad)
		e.wantErr(e.authGet(q, ck), "invalid_request", "max_age="+bad)
	}
}

func TestSSODisabledUserEndsSession(t *testing.T) {
	e := newEnv(t, nil)
	ck, _ := e.ssoLogin(authQuery(nil))
	u := e.st.users["u1"]
	u.Enabled = false
	e.st.users["u1"] = u
	e.wantForm(e.authGet(authQuery(nil), ck), "disabled user")
	if e.sessionCount() != 0 {
		t.Fatal("session of a disabled user must be ended")
	}
	u.Enabled = true
	e.st.users["u1"] = u
	ck, _ = e.ssoLogin(authQuery(nil))
	u.Enabled = false
	e.st.users["u1"] = u
	e.wantErr(e.authGet(authQuery(map[string]string{"prompt": "none"}), ck), "login_required", "disabled+none")

	// Deleted user.
	u.Enabled = true
	e.st.users["u1"] = u
	ck, _ = e.ssoLogin(authQuery(nil))
	delete(e.st.users, "u1")
	e.wantForm(e.authGet(authQuery(nil), ck), "deleted user")
}

func TestSSOUnverifiedEmailNoReuse(t *testing.T) {
	e := newEnv(t, func(r *core.Realm) { r.EmailVerificationRequired = true })
	ck, _ := e.ssoLogin(authQuery(nil))
	u := e.st.users["u1"]
	u.EmailVerified = false
	e.st.users["u1"] = u
	e.wantForm(e.authGet(authQuery(nil), ck), "unverified")
}

func TestSSOIdleAndAbsoluteExpiry(t *testing.T) {
	e := newEnv(t, nil)
	ck, _ := e.ssoLogin(authQuery(nil))
	e.now = e.now.Add(defaultIdle - time.Minute)
	e.wantCode(e.authGet(authQuery(nil), ck), "within idle") // slides the window
	e.now = e.now.Add(defaultIdle - time.Minute)
	e.wantCode(e.authGet(authQuery(nil), ck), "idle window slid")
	e.now = e.now.Add(defaultIdle + time.Minute)
	e.wantForm(e.authGet(authQuery(nil), ck), "idle expired")

	// Absolute lifetime: an idle TTL longer than the cap, so only the cap can end it.
	e2 := newEnv(t, func(r *core.Realm) { r.SessionIdleTTL = 20 * time.Hour })
	ck2, _ := e2.ssoLogin(authQuery(nil))
	e2.now = e2.now.Add(maxSessionLife - time.Minute)
	e2.wantCode(e2.authGet(authQuery(nil), ck2), "before absolute cap")
	e2.now = e2.now.Add(2 * time.Minute)
	e2.wantForm(e2.authGet(authQuery(nil), ck2), "after absolute cap")
}

func TestSSONeverWeakensRedirectOrPKCE(t *testing.T) {
	e := newEnv(t, nil)
	ck, _ := e.ssoLogin(authQuery(nil))
	// Unregistered redirect_uri: error page, no redirect at all.
	for _, p := range []string{"none", ""} {
		q := authQuery(map[string]string{"redirect_uri": "https://evil.example/cb", "prompt": p})
		w := e.authGet(q, ck)
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("redirect_uri mismatch (prompt=%q): %d %s", p, w.Code, w.Header().Get("Location"))
		}
	}
	for name, over := range map[string]map[string]string{
		"plain method":   {"code_challenge_method": "plain"},
		"missing pkce":   {"code_challenge": "", "code_challenge_method": ""},
		"short pkce":     {"code_challenge": "abc"},
		"bad state":      {"state": ""},
		"bad response":   {"response_type": "token"},
		"none and login": {"prompt": "none login"},
	} {
		w := e.authGet(authQuery(over), ck)
		q := locOf(t, w)
		if q.Get("error") == "" || q.Get("code") != "" {
			t.Fatalf("%s: SSO issued a code or no error: %v", name, q)
		}
	}
}

func TestSSOCookieIsRealmScoped(t *testing.T) {
	e := newEnv(t, nil)
	ck, _ := e.ssoLogin(authQuery(nil))
	if ck.Path != "/realms/r" {
		t.Fatalf("cookie path %q", ck.Path)
	}
	e.st.realms["r2"] = core.Realm{Name: "r2", Enabled: true, AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour}
	e.st.clients["c3"] = core.Client{ID: "c3", Realm: "r2", ClientID: "app", Enabled: true, Public: true,
		AuthCodeFlow: true, RedirectURIs: []string{cb}}
	req := httptest.NewRequest("GET", "/realms/r2/protocol/openid-connect/auth?"+authQuery(nil).Encode(), nil)
	req.AddCookie(ck)
	w := e.do(req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="csrf"`) {
		t.Fatalf("realm A cookie accepted in realm B: %d %s", w.Code, w.Header().Get("Location"))
	}
	req = httptest.NewRequest("GET", "/realms/r2/protocol/openid-connect/auth?"+authQuery(map[string]string{"prompt": "none"}).Encode(), nil)
	req.AddCookie(ck)
	if q := locOf(t, e.do(req)); q.Get("error") != "login_required" {
		t.Fatalf("prompt=none in realm B: %v", q)
	}
	// Store lookups are realm-scoped even when the user would exist in realm B:
	// a realm-A session row for a user that also lives in B must not log into B.
	e.st.users["u9"] = core.User{ID: "u9", Realm: "r2", Username: "bob", Enabled: true, EmailVerified: true}
	_ = e.st.PutSession(context.Background(), core.Session{ID: "sA", CookieHash: actions.Hash("rawA"), Realm: "r", UserID: "u9",
		AuthTime: e.now, LastSeen: e.now, IdleExpires: e.now.Add(time.Hour), ExpiresAt: e.now.Add(2 * time.Hour)})
	req = httptest.NewRequest("GET", "/realms/r2/protocol/openid-connect/auth?"+authQuery(nil).Encode(), nil)
	req.AddCookie(&http.Cookie{Name: ssoCookie, Value: "rawA"})
	if w := e.do(req); w.Code != 200 {
		t.Fatalf("realm A session row accepted in realm B: %d %s", w.Code, w.Header().Get("Location"))
	}
	// Realm B must not even see (let alone end) realm A's session.
	if e.sessionCount() != 2 {
		t.Fatal("realm B request touched realm A's session")
	}
}

func TestRefreshRequiresLiveSession(t *testing.T) {
	e := newEnv(t, nil)
	online := func() (string, string) {
		q := authQuery(map[string]string{"scope": "openid profile"})
		ck, w := e.ssoLogin(q)
		_ = ck
		_, tok, _ := e.tokenReq(codeForm(locOf(t, w).Get("code")), "", "")
		return tok["refresh_token"].(string), e.sidOfRefresh(tok["refresh_token"].(string))
	}
	rf := func(r string) (int, map[string]any) {
		s, b, _ := e.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r}, "client_id": {"app"}}, "", "")
		return s, b
	}

	// 1. Live session: refresh works and slides the idle window.
	r1, sid := online()
	e.now = e.now.Add(20 * time.Minute)
	if s, b := rf(r1); s != 200 {
		t.Fatalf("refresh with live session: %d %v", s, b)
	}
	got, _ := e.st.GetSession(context.Background(), "r", sid)
	if !got.IdleExpires.Equal(e.now.Add(defaultIdle)) {
		t.Fatalf("refresh did not touch the session: %v", got.IdleExpires)
	}

	// 2. Session removed WITHOUT revoking tokens: the session check itself must refuse and revoke the family.
	r2, sid2 := online()
	if _, err := e.st.TakeSession(context.Background(), "r", sid2); err != nil {
		t.Fatal(err)
	}
	if s, b := rf(r2); s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("refresh after session gone: %d %v", s, b)
	}
	if !e.st.refresh[HashSecret(r2)].Revoked {
		t.Fatal("family not revoked after dead-session refresh")
	}

	// 3. Ended through the sessions service (revokes online tokens).
	r3, sid3 := online()
	if _, err := e.h.sessions().End(context.Background(), "r", sid3); err != nil {
		t.Fatal(err)
	}
	if s, b := rf(r3); s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("refresh after End: %d %v", s, b)
	}

	// 4. Idle expiry also kills online tokens.
	r4, _ := online()
	e.now = e.now.Add(defaultIdle + time.Minute)
	if s, b := rf(r4); s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("refresh after idle expiry: %d %v", s, b)
	}
}

func (e *env) sidOfRefresh(raw string) string {
	e.t.Helper()
	sid := e.st.refresh[HashSecret(raw)].SessionID
	if sid == "" {
		e.t.Fatal("refresh token has no session id")
	}
	return sid
}

func TestOfflineRefreshSurvivesSession(t *testing.T) {
	e := newEnv(t, nil)
	_, w := e.ssoLogin(authQuery(nil)) // scope includes offline_access
	_, tok, _ := e.tokenReq(codeForm(locOf(t, w).Get("code")), "", "")
	rt := tok["refresh_token"].(string)
	sid := e.sidOfRefresh(rt)
	if _, err := e.h.sessions().End(context.Background(), "r", sid); err != nil {
		t.Fatal(err)
	}
	s, b, _ := e.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"app"}}, "", "")
	if s != 200 || b["access_token"] == nil {
		t.Fatalf("offline refresh after logout: %d %v", s, b)
	}
	if _, has := claimsOf(t, b["access_token"].(string))["sid"]; has {
		t.Error("access token must not carry a dead sid")
	}
	// And the dead-session token set would not even have worked.
	e.now = e.now.Add(time.Minute)
	nrt := b["refresh_token"].(string)
	if s, _, _ := e.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {nrt}, "client_id": {"app"}}, "", ""); s != 200 {
		t.Fatalf("second offline refresh: %d", s)
	}
}

func TestClientCredentialsHaveNoSID(t *testing.T) {
	e := newEnv(t, nil)
	s, tok, _ := e.tokenReq(url.Values{"grant_type": {"client_credentials"}}, "svc", "s3cret")
	if s != 200 {
		t.Fatalf("client_credentials: %d %v", s, tok)
	}
	if _, has := claimsOf(t, tok["access_token"].(string))["sid"]; has {
		t.Fatal("client_credentials token has sid")
	}
	// And such tokens keep working for introspection when sessions are gone.
	form := url.Values{"token": {tok["access_token"].(string)}}
	req := httptest.NewRequest("POST", base+"token/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc", "s3cret")
	if w := e.do(req); !strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatalf("introspect: %s", w.Body)
	}
}

func TestIntrospectAndUserinfoRejectEndedSession(t *testing.T) {
	e := newEnv(t, nil)
	_, w := e.ssoLogin(authQuery(nil))
	_, tok, _ := e.tokenReq(codeForm(locOf(t, w).Get("code")), "", "")
	at := tok["access_token"].(string)
	sid := e.onlySession().ID
	if claimsOf(t, at)["sid"] != sid {
		t.Fatal("sid claim missing")
	}
	userinfo := func() int {
		req := httptest.NewRequest("GET", base+"userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+at)
		return e.do(req).Code
	}
	introspect := func() string {
		req := httptest.NewRequest("POST", base+"token/introspect", strings.NewReader(url.Values{"token": {at}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("svc", "s3cret")
		return e.do(req).Body.String()
	}
	if userinfo() != 200 || !strings.Contains(introspect(), `"active":true`) {
		t.Fatal("token should be valid while the session lives")
	}
	if _, err := e.h.sessions().End(context.Background(), "r", sid); err != nil {
		t.Fatal(err)
	}
	if c := userinfo(); c != 401 {
		t.Fatalf("userinfo after session end: %d", c)
	}
	if b := introspect(); !strings.Contains(b, `"active":false`) {
		t.Fatalf("introspect after session end: %s", b)
	}
}

func TestCodeDiesWithSession(t *testing.T) {
	e := newEnv(t, nil)
	_, w := e.ssoLogin(authQuery(nil))
	code := locOf(t, w).Get("code")
	_, _ = e.h.sessions().End(context.Background(), "r", e.onlySession().ID)
	if s, b, _ := e.tokenReq(codeForm(code), "", ""); s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("code of an ended session redeemed: %d %v", s, b)
	}
}

func TestSessionFailureIssuesNoCode(t *testing.T) {
	e := newEnv(t, nil)
	csrf, cc := e.loginForm(authQuery(nil))
	e.h.cfg.Store = failSessStore{e.st}
	w := e.postLogin(authQuery(nil), "alice", "pw", csrf, cc)
	if w.Code != 500 || w.Header().Get("Location") != "" || len(e.st.codes) != 0 {
		t.Fatalf("session failure: %d codes=%d", w.Code, len(e.st.codes))
	}
}

type failSessStore struct{ *fakeStore }

func (failSessStore) PutSession(context.Context, core.Session) error { return idp.ErrConflict }

func TestDiscoveryAdvertisesBackchannel(t *testing.T) {
	e := newEnv(t, nil)
	w := e.do(httptest.NewRequest("GET", "/realms/r/.well-known/openid-configuration", nil))
	b := w.Body.String()
	for _, want := range []string{`"backchannel_logout_supported":true`, `"backchannel_logout_session_supported":true`, `"sid"`} {
		if !strings.Contains(b, want) {
			t.Errorf("discovery lacks %s", want)
		}
	}
}

func TestPasswordResetEndsSessions(t *testing.T) {
	e := newAEnv(t, true)
	ctx := context.Background()
	mk := func(id, user, hash string) {
		if err := e.st.PutSession(ctx, core.Session{ID: id, CookieHash: hash, Realm: "r", UserID: user,
			AuthTime: e.now, LastSeen: e.now, IdleExpires: e.now.Add(time.Hour), ExpiresAt: e.now.Add(5 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	mk("s1", "u1", "h1")
	mk("s2", "u1", "h2")
	mk("s3", "u2", "h3")
	e.forgot("alice")
	if w := e.reset(e.lastLink(), "newpassword1", "newpassword1"); w.Code != 200 {
		t.Fatalf("reset: %d %s", w.Code, w.Body)
	}
	for _, id := range []string{"s1", "s2"} {
		if _, err := e.st.GetSession(ctx, "r", id); err == nil {
			t.Errorf("session %s survived the password reset", id)
		}
	}
	if _, err := e.st.GetSession(ctx, "r", "s3"); err != nil {
		t.Error("another user's session was ended")
	}
}
