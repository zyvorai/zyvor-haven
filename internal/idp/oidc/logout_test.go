// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/sessions"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type recNotifier struct {
	mu    sync.Mutex
	calls map[string]int // realm/sid/client
}

func (n *recNotifier) Notify(_ context.Context, realm string, s core.Session) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.calls == nil {
		n.calls = map[string]int{}
	}
	for _, c := range s.Clients {
		n.calls[realm+"/"+s.ID+"/"+c]++
	}
}
func (n *recNotifier) count(sid, client string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls["r/"+sid+"/"+client]
}

// expSigner is the fake signer plus the optional expired-token verification.
type expSigner struct{ fakeSigner }

func (expSigner) VerifyAllowExpired(ctx context.Context, realm, tok string) (core.Claims, error) {
	return fakeSigner{now: func() time.Time { return time.Unix(0, 0) }}.Verify(ctx, realm, tok)
}

type lenv struct {
	t   *testing.T
	st  *memstore.Store
	h   *Provider
	rec *recNotifier
	now time.Time
}

func newLEnv(t *testing.T, sg func(func() time.Time) core.Signer) *lenv {
	t.Helper()
	e := &lenv{t: t, st: memstore.New(), rec: &recNotifier{}, now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(e.st.CreateRealm(ctx, core.Realm{Name: "r", Enabled: true, AuthEventsLogged: true, RefreshTokenRotation: true,
		AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour}))
	must(e.st.CreateRealm(ctx, core.Realm{Name: "other", Enabled: true}))
	must(e.st.CreateClient(ctx, core.Client{Realm: "r", ClientID: "app", Enabled: true, Public: true,
		AuthCodeFlow: true, RedirectURIs: []string{cb}}))
	must(e.st.CreateUser(ctx, core.User{ID: "u1", Realm: "r", Username: "alice", Enabled: true}))
	must(e.st.CreateUser(ctx, core.User{ID: "u2", Realm: "r", Username: "bob", Enabled: true}))
	clock := func() time.Time { return e.now }
	if sg == nil {
		sg = func(c func() time.Time) core.Signer { return expSigner{fakeSigner{now: c}} }
	}
	e.h = New(Config{Store: e.st, Signer: sg(clock), Hasher: fakeHasher{}, BaseURL: "https://idp.example", Clock: clock,
		CSRFKey:  []byte("0123456789abcdef0123456789abcdef"),
		Sessions: &sessions.Service{Store: e.st, Notifier: e.rec}})
	return e
}

// session creates a live session for user and returns it with its cookie.
func (e *lenv) session(id, user string, clients ...string) (core.Session, *http.Cookie) {
	e.t.Helper()
	raw := "raw-cookie-" + id
	s := core.Session{ID: id, CookieHash: actions.Hash(raw), Realm: "r", UserID: user, AuthTime: e.now, LastSeen: e.now,
		IdleExpires: e.now.Add(30 * time.Minute), ExpiresAt: e.now.Add(10 * time.Hour), Clients: clients}
	if err := e.st.PutSession(context.Background(), s); err != nil {
		e.t.Fatal(err)
	}
	return s, &http.Cookie{Name: ssoCookie, Value: raw}
}

func (e *lenv) alive(id string) bool {
	_, err := e.st.GetSession(context.Background(), "r", id)
	return err == nil
}

func (e *lenv) hint(realm string, c core.Claims) string {
	if c["iss"] == nil {
		c["iss"] = "https://idp.example/realms/" + realm
	}
	if c["typ"] == nil {
		c["typ"] = "ID"
	}
	if c["azp"] == nil {
		c["azp"] = "app"
	}
	if c["exp"] == nil {
		c["exp"] = e.now.Add(5 * time.Minute).Unix()
	}
	tok, _ := fakeSigner{}.Sign(context.Background(), realm, c)
	return tok
}

func (e *lenv) do(method string, q url.Values, form url.Values, cks ...*http.Cookie) *httptest.ResponseRecorder {
	path := base + "logout"
	if q != nil {
		path += "?" + q.Encode()
	}
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for _, c := range cks {
		req.AddCookie(c)
	}
	req.RemoteAddr = "192.0.2.1:1"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

func (e *lenv) events(typ string) int {
	evs, _ := e.st.ListEvents(context.Background(), "r", 100)
	n := 0
	for _, ev := range evs {
		if ev.Type == typ {
			n++
		}
	}
	return n
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// confirm GETs the confirmation page and returns the csrf form value and cookie.
func (e *lenv) confirm(q url.Values, ck *http.Cookie) (string, *http.Cookie) {
	e.t.Helper()
	w := e.do("GET", q, nil, ck)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Sign out of r?") {
		e.t.Fatalf("confirmation page: %d %s", w.Code, w.Body)
	}
	m := csrfRe.FindStringSubmatch(w.Body.String())
	c := cookieNamed(w, csrfCookie)
	if m == nil || c == nil {
		e.t.Fatal("no csrf in confirmation page")
	}
	if c.Path != "/realms/r/protocol/openid-connect/logout" {
		e.t.Fatalf("csrf cookie path %q", c.Path)
	}
	return m[1], c
}

func TestLogoutCookieGETOnlyConfirms(t *testing.T) {
	e := newLEnv(t, nil)
	_, ck := e.session("s1", "u1", "app")
	w := e.do("GET", nil, nil, ck)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Sign out of r?") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !e.alive("s1") || e.rec.count("s1", "app") != 0 {
		t.Fatal("bare GET ended the session (logout CSRF)")
	}
	if c := cookieNamed(w, ssoCookie); c != nil {
		t.Fatal("bare GET touched the SSO cookie")
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "nonce-") {
		t.Fatal("no nonce'd CSP")
	}
}

func TestLogoutConfirmPOSTEndsAndClearsCookie(t *testing.T) {
	e := newLEnv(t, nil)
	_, ck := e.session("s1", "u1", "app")
	csrf, cc := e.confirm(nil, ck)
	w := e.do("POST", nil, url.Values{"csrf": {csrf}}, ck, cc)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Signed out") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if e.alive("s1") {
		t.Fatal("session survived confirmed logout")
	}
	c := cookieNamed(w, ssoCookie)
	if c == nil || c.MaxAge >= 0 || c.Path != "/realms/r" {
		t.Fatalf("sso cookie not cleared: %+v", c)
	}
	if e.rec.count("s1", "app") != 1 || e.events("LOGOUT") != 1 {
		t.Fatalf("notify=%d events=%d", e.rec.count("s1", "app"), e.events("LOGOUT"))
	}
}

func TestLogoutPOSTWithoutValidCSRFIs403(t *testing.T) {
	e := newLEnv(t, nil)
	_, ck := e.session("s1", "u1", "app")
	csrf, cc := e.confirm(nil, ck)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"no csrf":          e.do("POST", nil, url.Values{}, ck),
		"form only":        e.do("POST", nil, url.Values{"csrf": {csrf}}, ck),
		"cookie only":      e.do("POST", nil, url.Values{}, ck, cc),
		"mismatch":         e.do("POST", nil, url.Values{"csrf": {"x" + csrf}}, ck, cc),
		"forged same both": e.do("POST", nil, url.Values{"csrf": {"forged"}}, ck, &http.Cookie{Name: csrfCookie, Value: "forged"}),
	} {
		if w.Code != 403 {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	if !e.alive("s1") {
		t.Fatal("session ended despite failed CSRF")
	}
	if e.events("LOGOUT_ERROR") != 5 {
		t.Fatalf("LOGOUT_ERROR events %d", e.events("LOGOUT_ERROR"))
	}
}

func TestLogoutHintEndsSidWithoutConfirmation(t *testing.T) {
	e := newLEnv(t, nil)
	e.session("s1", "u1", "app")
	h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
	w := e.do("GET", url.Values{"id_token_hint": {h}}, nil) // no cookie at all (cross-device)
	if w.Code != 200 || strings.Contains(w.Body.String(), "Sign out of") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if e.alive("s1") || e.rec.count("s1", "app") != 1 {
		t.Fatal("hint sid not ended")
	}
}

func TestLogoutHintAlsoEndsSameUsersCookieSession(t *testing.T) {
	e := newLEnv(t, nil)
	e.session("s1", "u1", "app")
	_, ck2 := e.session("s2", "u1", "app")
	h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
	w := e.do("GET", url.Values{"id_token_hint": {h}}, nil, ck2)
	if e.alive("s1") || e.alive("s2") {
		t.Fatal("same-user sessions should both end")
	}
	if c := cookieNamed(w, ssoCookie); c == nil || c.MaxAge >= 0 {
		t.Fatal("cookie not cleared")
	}
}

func TestLogoutHintNeverEndsAnotherUsersSession(t *testing.T) {
	e := newLEnv(t, nil)
	e.session("victim", "u2", "app")
	_, ck := e.session("mine", "u1", "app")
	// valid token for u1, but claiming u2's sid
	h := e.hint("r", core.Claims{"sub": "u1", "sid": "victim"})
	w := e.do("GET", url.Values{"id_token_hint": {h}}, nil, ck)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if !e.alive("victim") || e.rec.count("victim", "app") != 0 {
		t.Fatal("another user's session was ended via foreign sid")
	}
	if e.alive("mine") {
		t.Fatal("own cookie session should end")
	}
	// hint for u2 must not end u1's cookie session, nor clear its cookie
	_, ck3 := e.session("s3", "u1", "app")
	h2 := e.hint("r", core.Claims{"sub": "u2", "sid": "nope"})
	w = e.do("GET", url.Values{"id_token_hint": {h2}}, nil, ck3)
	if !e.alive("s3") {
		t.Fatal("u2's hint ended u1's cookie session")
	}
	if cookieNamed(w, ssoCookie) != nil {
		t.Fatal("cookie of a different user was cleared")
	}
}

func TestLogoutExpiredHintAccepted(t *testing.T) {
	e := newLEnv(t, nil)
	e.session("s1", "u1", "app")
	h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1", "exp": e.now.Add(-48 * time.Hour).Unix()})
	w := e.do("GET", url.Values{"id_token_hint": {h}, "post_logout_redirect_uri": {cb}, "state": {"s t"}}, nil)
	if w.Code != 302 || e.alive("s1") {
		t.Fatalf("expired hint: %d alive=%v", w.Code, e.alive("s1"))
	}
}

func TestLogoutExpiredHintRejectedWithoutExpiredVerifier(t *testing.T) {
	e := newLEnv(t, func(c func() time.Time) core.Signer { return fakeSigner{now: c} })
	e.session("s1", "u1", "app")
	h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1", "exp": e.now.Add(-time.Hour).Unix()})
	if w := e.do("GET", url.Values{"id_token_hint": {h}}, nil); w.Code != 400 || !e.alive("s1") {
		t.Fatalf("fallback to Verify failed: %d", w.Code)
	}
}

func TestLogoutBadHintsRejected(t *testing.T) {
	e := newLEnv(t, nil)
	e.session("s1", "u1", "app")
	good := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
	parts := strings.Split(good, ".")
	cases := map[string]string{
		"other realm":    e.hint("other", core.Claims{"sub": "u1", "sid": "s1", "iss": "https://idp.example/realms/other"}),
		"wrong issuer":   e.hint("r", core.Claims{"sub": "u1", "sid": "s1", "iss": "https://evil.example/realms/r"}),
		"tampered":       parts[0] + "." + parts[1] + "." + "other",
		"garbage":        "not-a-jwt",
		"access token":   e.hint("r", core.Claims{"sub": "u1", "sid": "s1", "typ": "Bearer"}),
		"no subject":     e.hint("r", core.Claims{"sid": "s1"}),
		"foreign signer": parts[0] + "." + parts[1] + ".other",
	}
	for name, h := range cases {
		w := e.do("GET", url.Values{"id_token_hint": {h}, "post_logout_redirect_uri": {cb}}, nil)
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Errorf("%s: status %d loc %q", name, w.Code, w.Header().Get("Location"))
		}
	}
	if !e.alive("s1") {
		t.Fatal("session ended by an invalid hint")
	}
	if e.events("LOGOUT_ERROR") != len(cases) {
		t.Fatalf("LOGOUT_ERROR events %d", e.events("LOGOUT_ERROR"))
	}
}

func TestLogoutRedirectValidationAndState(t *testing.T) {
	e := newLEnv(t, nil)
	h := e.hint("r", core.Claims{"sub": "u1"})
	for _, bad := range []string{"https://evil.example/", cb + "x", "javascript:alert(1)", "http://app.example/cb"} {
		w := e.do("GET", url.Values{"id_token_hint": {h}, "post_logout_redirect_uri": {bad}}, nil)
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Errorf("%q: %d %q", bad, w.Code, w.Header().Get("Location"))
		}
	}
	// no hint and no client_id: redirect refused
	if w := e.do("GET", url.Values{"post_logout_redirect_uri": {cb}}, nil); w.Code != 400 {
		t.Fatalf("redirect without client: %d", w.Code)
	}
	// client_id mismatching the hint
	if w := e.do("GET", url.Values{"id_token_hint": {h}, "client_id": {"zzz"}, "post_logout_redirect_uri": {cb}}, nil); w.Code != 400 {
		t.Fatalf("client mismatch: %d", w.Code)
	}
	w := e.do("GET", url.Values{"id_token_hint": {h}, "post_logout_redirect_uri": {cb}, "state": {"a b&c=d"}}, nil)
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || loc == nil || loc.Query().Get("state") != "a b&c=d" || !strings.HasPrefix(loc.String(), cb+"?") {
		t.Fatalf("redirect: %d %v", w.Code, w.Header())
	}
	// no valid redirect given: "Signed out" page
	if w := e.do("GET", url.Values{"id_token_hint": {h}, "state": {"x"}}, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Signed out") {
		t.Fatalf("no redirect: %d", w.Code)
	}
}

func TestLogoutConfirmCarriesRedirectAndState(t *testing.T) {
	e := newLEnv(t, nil)
	_, ck := e.session("s1", "u1", "app")
	q := url.Values{"client_id": {"app"}, "post_logout_redirect_uri": {cb}, "state": {"st"}}
	// unregistered redirect never reaches the confirmation page
	if w := e.do("GET", url.Values{"client_id": {"app"}, "post_logout_redirect_uri": {"https://evil.example/"}}, nil, ck); w.Code != 400 {
		t.Fatalf("evil redirect: %d", w.Code)
	}
	csrf, cc := e.confirm(q, ck)
	// the POST re-validates: a tampered hidden redirect is refused and nothing is ended
	w := e.do("POST", nil, url.Values{"csrf": {csrf}, "client_id": {"app"}, "post_logout_redirect_uri": {"https://evil.example/"}}, ck, cc)
	if w.Code != 400 || !e.alive("s1") {
		t.Fatalf("tampered redirect: %d alive=%v", w.Code, e.alive("s1"))
	}
	w = e.do("POST", nil, url.Values{"csrf": {csrf}, "client_id": {"app"}, "post_logout_redirect_uri": {cb}, "state": {"st"}}, ck, cc)
	if w.Code != 302 || w.Header().Get("Location") != cb+"?state=st" || e.alive("s1") {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestLogoutIdempotentAndNeverLeaks(t *testing.T) {
	e := newLEnv(t, nil)
	e.session("s1", "u1", "app")
	h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
	first := e.do("GET", url.Values{"id_token_hint": {h}}, nil)
	second := e.do("GET", url.Values{"id_token_hint": {h}}, nil)
	if first.Code != 200 || second.Code != 200 || stripNonce(first.Body.String()) != stripNonce(second.Body.String()) {
		t.Fatalf("double logout differs: %d/%d", first.Code, second.Code)
	}
	// unknown sid answers the same
	h2 := e.hint("r", core.Claims{"sub": "u1", "sid": "never-existed"})
	if w := e.do("GET", url.Values{"id_token_hint": {h2}}, nil); w.Code != 200 || stripNonce(w.Body.String()) != stripNonce(first.Body.String()) {
		t.Fatalf("unknown sid leaked: %d", w.Code)
	}
	// stale cookie, bare GET, no session at all
	if w := e.do("GET", nil, nil, &http.Cookie{Name: ssoCookie, Value: "stale"}); w.Code != 200 || !strings.Contains(w.Body.String(), "Signed out") {
		t.Fatalf("stale cookie: %d", w.Code)
	}
	if w := e.do("GET", nil, nil); w.Code != 200 {
		t.Fatalf("no session: %d", w.Code)
	}
	if e.rec.count("s1", "app") != 1 || e.events("LOGOUT") != 1 {
		t.Fatalf("notified %d times, %d LOGOUT events", e.rec.count("s1", "app"), e.events("LOGOUT"))
	}
	// replayed confirm POST after the session is gone is harmless as well
	_, ck := e.session("s9", "u1", "app")
	csrf, cc := e.confirm(nil, ck)
	for i := 0; i < 2; i++ {
		if w := e.do("POST", nil, url.Values{"csrf": {csrf}}, ck, cc); w.Code != 200 && w.Code != 403 {
			t.Fatalf("replay %d: %d", i, w.Code)
		}
	}
	if e.rec.count("s9", "app") != 1 {
		t.Fatalf("replay notified %d times", e.rec.count("s9", "app"))
	}
}

func TestLogoutRaceNotifiesOncePerClient(t *testing.T) {
	e := newLEnv(t, nil)
	e.session("s1", "u1", "app", "svc")
	h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.do("GET", url.Values{"id_token_hint": {h}}, nil)
		}()
	}
	wg.Wait()
	if e.rec.count("s1", "app") != 1 || e.rec.count("s1", "svc") != 1 || e.events("LOGOUT") != 1 {
		t.Fatalf("app=%d svc=%d events=%d", e.rec.count("s1", "app"), e.rec.count("s1", "svc"), e.events("LOGOUT"))
	}
}

func TestLogoutExpiredCookieSessionCanBeEnded(t *testing.T) {
	e := newLEnv(t, nil)
	_, ck := e.session("s1", "u1", "app")
	csrf, cc := e.confirm(nil, ck)
	e.now = e.now.Add(24 * time.Hour) // session now expired
	w := e.do("POST", nil, url.Values{"csrf": {csrf}}, ck, cc)
	_ = w // csrf has also expired (15 min) -> 403 is correct; use a fresh page instead
	if !e.alive("s1") {
		t.Fatal("expired csrf must not end anything")
	}
	csrf, cc = e.confirm(nil, ck)
	if w := e.do("POST", nil, url.Values{"csrf": {csrf}}, ck, cc); w.Code != 200 || e.alive("s1") {
		t.Fatalf("expired session not ended: %d", w.Code)
	}
}

func TestLogoutRevokesRefreshTokensExceptOffline(t *testing.T) {
	e := newLEnv(t, nil)
	e.session("s1", "u1", "app")
	put := func(raw, scope string) {
		err := e.st.PutRefreshToken(context.Background(), core.RefreshToken{TokenHash: HashSecret(raw), FamilyID: raw, Realm: "r",
			ClientID: "app", UserID: "u1", SessionID: "s1", Scope: scope, ExpiresAt: e.now.Add(time.Hour), CreatedAt: e.now})
		if err != nil {
			t.Fatal(err)
		}
	}
	put("rt-normal", "openid profile")
	put("rt-offline", "openid offline_access")
	refresh := func(raw string) int {
		req := httptest.NewRequest("POST", base+"token", strings.NewReader(url.Values{"grant_type": {"refresh_token"},
			"refresh_token": {raw}, "client_id": {"app"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.0.2.1:1"
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		return w.Code
	}
	// sanity: the same shape of token works before logout
	put("rt-probe", "openid")
	if c := refresh("rt-probe"); c != 200 {
		t.Fatalf("probe refresh before logout: %d", c)
	}
	h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
	if w := e.do("GET", url.Values{"id_token_hint": {h}}, nil); w.Code != 200 {
		t.Fatalf("logout %d", w.Code)
	}
	if c := refresh("rt-normal"); c != 400 {
		t.Fatalf("session refresh token survived logout: %d", c)
	}
	if c := refresh("rt-offline"); c != 200 {
		t.Fatalf("offline_access refresh token must survive logout: %d", c)
	}
}

func TestLogoutUnknownRealm(t *testing.T) {
	e := newLEnv(t, nil)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, httptest.NewRequest("GET", "/realms/nope/protocol/openid-connect/logout", nil))
	if w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
}

var nonceRe = regexp.MustCompile(`nonce="[^"]*"`)

func stripNonce(s string) string { return nonceRe.ReplaceAllString(s, "") }
