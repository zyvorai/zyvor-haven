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
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type capMail struct {
	mu   sync.Mutex
	msgs []mail.Message
	err  error
}

func (c *capMail) Send(_ context.Context, m mail.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.msgs = append(c.msgs, m)
	return nil
}
func (c *capMail) all() []mail.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]mail.Message(nil), c.msgs...)
}

type aenv struct {
	t    *testing.T
	st   *memstore.Store
	h    *Provider
	mail *capMail
	now  time.Time
	ip   string
}

var linkRe = regexp.MustCompile(`https://idp\.example(/realms/[^\s"<>]+)`)

func newAEnv(t *testing.T, withMail bool) *aenv {
	t.Helper()
	e := &aenv{t: t, st: memstore.New(), mail: &capMail{}, now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), ip: "192.0.2.1:1"}
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(e.st.CreateRealm(ctx, core.Realm{Name: "r", Enabled: true, BruteForceProtection: true,
		RefreshTokenRotation: true, AuthEventsLogged: true, EmailVerificationRequired: true,
		PasswordPolicy: "length(8)", AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour}))
	must(e.st.CreateClient(ctx, core.Client{Realm: "r", ClientID: "app", Enabled: true, Public: true,
		AuthCodeFlow: true, RedirectURIs: []string{cb}}))
	must(e.st.CreateUser(ctx, core.User{ID: "u1", Realm: "r", Username: "alice", Email: "alice@example.org",
		Enabled: true, EmailVerified: false, PasswordHash: "H:oldpassword"}))
	must(e.st.CreateUser(ctx, core.User{ID: "u2", Realm: "r", Username: "dora", Email: "dora@example.org",
		Enabled: false, PasswordHash: "H:whatever1"}))
	clock := func() time.Time { return e.now }
	cfg := Config{Store: e.st, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{},
		BaseURL: "https://idp.example", Clock: clock, CSRFKey: []byte("0123456789abcdef0123456789abcdef")}
	if withMail {
		cfg.Actions = &actions.Service{Store: e.st, Mailer: e.mail, BaseURL: "https://idp.example", Clock: clock}
	}
	e.h = New(cfg)
	return e
}

func (e *aenv) do(req *http.Request) *httptest.ResponseRecorder {
	req.RemoteAddr = e.ip
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

// form GETs a login-actions page, returning body, csrf token and cookie.
func (e *aenv) form(path string) (*httptest.ResponseRecorder, string, *http.Cookie) {
	w := e.do(httptest.NewRequest("GET", path, nil))
	m := csrfRe.FindStringSubmatch(w.Body.String())
	var ck *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == csrfCookie {
			ck = c
		}
	}
	if m == nil {
		return w, "", ck
	}
	return w, m[1], ck
}

func (e *aenv) post(path string, v url.Values, ck *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if ck != nil {
		req.AddCookie(ck)
	}
	return e.do(req)
}

const fp = "/realms/r/login-actions/forgot-password"

func (e *aenv) forgot(id string) *httptest.ResponseRecorder {
	_, csrf, ck := e.form(fp)
	w := e.post(fp, url.Values{"username": {id}, "csrf": {csrf}}, ck)
	e.h.Drain()
	return w
}

// lastLink returns the path+query of the newest emailed link.
func (e *aenv) lastLink() string {
	e.t.Helper()
	ms := e.mail.all()
	if len(ms) == 0 {
		e.t.Fatal("no email was sent")
	}
	m := linkRe.FindStringSubmatch(ms[len(ms)-1].Text)
	if m == nil {
		e.t.Fatalf("no link in %q", ms[len(ms)-1].Text)
	}
	return strings.ReplaceAll(m[1], "&amp;", "&")
}

func (e *aenv) reset(link, pw, confirm string) *httptest.ResponseRecorder {
	w, csrf, ck := e.form(link)
	if csrf == "" {
		return w
	}
	u, _ := url.Parse(link)
	return e.post(u.Path, url.Values{"token": {u.Query().Get("token")}, "password": {pw},
		"confirm": {confirm}, "csrf": {csrf}}, ck)
}

func (e *aenv) user(id string) core.User {
	u, err := e.st.GetUser(context.Background(), "r", id)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func TestForgotPasswordDoesNotEnumerate(t *testing.T) {
	e := newAEnv(t, true)
	known := e.forgot("alice")
	unknown := e.forgot("nobody")
	disabled := e.forgot("dora")
	byEmail := e.forgot("ALICE@example.org")
	nonce := regexp.MustCompile(`nonce="[^"]+"`)
	norm := func(w *httptest.ResponseRecorder) string { return nonce.ReplaceAllString(w.Body.String(), "") }
	for name, w := range map[string]*httptest.ResponseRecorder{"unknown": unknown, "disabled": disabled, "email": byEmail} {
		if w.Code != known.Code || norm(w) != norm(known) {
			t.Errorf("%s response differs from known user's:\n%d %s\nvs\n%d %s", name, w.Code, w.Body, known.Code, known.Body)
		}
	}
	ms := e.mail.all()
	if len(ms) != 2 { // alice by username, alice by email (second is rate-limit-safe: 2 < 3)
		t.Fatalf("want 2 emails (alice twice), got %d", len(ms))
	}
	for _, m := range ms {
		if m.To != "alice@example.org" {
			t.Errorf("email sent to %q", m.To)
		}
	}
}

func TestResetPasswordEndToEnd(t *testing.T) {
	e := newAEnv(t, true)
	ctx := context.Background()
	// A live refresh token and a lockout that the reset must clear.
	_ = e.st.PutRefreshToken(ctx, core.RefreshToken{TokenHash: "rt1", FamilyID: "f", Realm: "r", ClientID: "app",
		UserID: "u1", ExpiresAt: e.now.Add(time.Hour)})
	u := e.user("u1")
	u.FailedLogins, u.LockedUntil = 5, e.now.Add(10*time.Minute)
	_ = e.st.UpdateUser(ctx, u)

	e.forgot("alice")
	link := e.lastLink()

	// GET (even twice) must not consume the link.
	e.form(link)
	e.form(link)
	// A mismatch and a policy violation must not burn it either.
	if w := e.reset(link, "newpassword1", "different"); !strings.Contains(w.Body.String(), "do not match") {
		t.Fatalf("mismatch not reported: %s", w.Body)
	}
	if w := e.reset(link, "short", "short"); !strings.Contains(w.Body.String(), "not allowed") {
		t.Fatalf("policy not enforced: %s", w.Body)
	}
	if e.user("u1").PasswordHash != "H:oldpassword" {
		t.Fatal("password changed by a rejected attempt")
	}

	w := e.reset(link, "newpassword1", "newpassword1")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Password updated") {
		t.Fatalf("reset failed: %d %s", w.Code, w.Body)
	}
	got := e.user("u1")
	if got.PasswordHash != "H:newpassword1" || !got.EmailVerified || got.FailedLogins != 0 || !got.LockedUntil.IsZero() {
		t.Fatalf("user after reset: %+v", got)
	}
	rt, _ := e.st.GetRefreshToken(ctx, "rt1")
	if !rt.Revoked {
		t.Error("refresh token survived a password reset")
	}
	// The link is single use.
	if w := e.reset(link, "another-pass1", "another-pass1"); w.Code != http.StatusBadRequest {
		t.Errorf("replayed link status %d", w.Code)
	}
	if e.user("u1").PasswordHash != "H:newpassword1" {
		t.Error("replayed link changed the password")
	}
	// New password signs in; old one does not.
	if w := (&env{t: t, h: e.h}).login(authQuery(nil), "alice", "newpassword1"); w.Code != 302 {
		t.Errorf("new password cannot sign in: %d %s", w.Code, w.Body)
	}
	if w := (&env{t: t, h: e.h}).login(authQuery(nil), "alice", "oldpassword"); w.Code == 302 {
		t.Error("old password still works")
	}
	if ev, _ := e.st.ListEvents(ctx, "r", 50); !hasEvent(ev, "RESET_PASSWORD") || !hasEvent(ev, "RESET_PASSWORD_REQUEST") {
		t.Errorf("events missing: %+v", ev)
	}
}

func hasEvent(ev []core.Event, typ string) bool {
	for _, x := range ev {
		if x.Type == typ {
			return true
		}
	}
	return false
}

func TestResetLinkExpiryAndEmailBinding(t *testing.T) {
	e := newAEnv(t, true)
	e.forgot("alice")
	link := e.lastLink()
	e.now = e.now.Add(actions.ResetTTL + time.Second)
	if w := e.reset(link, "newpassword1", "newpassword1"); w.Code != http.StatusBadRequest {
		t.Errorf("expired link status %d", w.Code)
	}

	e.now = e.now.Add(time.Hour) // clear the rate-limit window
	e.forgot("alice")
	link = e.lastLink()
	u := e.user("u1")
	u.Email = "attacker@example.net" // address changed after the mail went out
	_ = e.st.UpdateUser(context.Background(), u)
	if w := e.reset(link, "newpassword1", "newpassword1"); w.Code != http.StatusBadRequest {
		t.Errorf("link for the old address still works: %d", w.Code)
	}
	if e.user("u1").PasswordHash != "H:oldpassword" {
		t.Error("password changed through a stale link")
	}
}

func TestWrongPurposeAndForgedTokens(t *testing.T) {
	e := newAEnv(t, true)
	// A verify link must not work at the reset endpoint (and vice versa).
	u := e.user("u1")
	if err := e.h.cfg.Actions.Send(context.Background(), core.Realm{Name: "r"}, u, core.ActionVerifyEmail, actions.SendOpts{}); err != nil {
		t.Fatal(err)
	}
	vl := e.lastLink()
	resetURL := strings.Replace(vl, "verify-email", "reset-password", 1)
	if w := e.reset(resetURL, "newpassword1", "newpassword1"); w.Code != http.StatusBadRequest {
		t.Errorf("verify token accepted as reset token: %d", w.Code)
	}
	for _, bad := range []string{"", "nope", strings.Repeat("a", 500)} {
		l := "/realms/r/login-actions/reset-password?token=" + bad
		if w := e.reset(l, "newpassword1", "newpassword1"); w.Code != http.StatusBadRequest {
			t.Errorf("token %q status %d", bad, w.Code)
		}
	}
}

func TestVerifyEmailFlow(t *testing.T) {
	e := newAEnv(t, true)
	ev := &env{t: t, h: e.h}
	// Correct password, unverified: sign-in is refused and a link is sent.
	w := ev.login(authQuery(nil), "alice", "oldpassword")
	e.h.Drain()
	if w.Code == 302 || !strings.Contains(w.Body.String(), "sent a verification link") {
		t.Fatalf("unverified login: %d %s", w.Code, w.Body)
	}
	link := e.lastLink()
	// Opening the link (GET) must not verify: scanners do that.
	e.form(link)
	if e.user("u1").EmailVerified {
		t.Fatal("GET verified the address")
	}
	_, csrf, ck := e.form(link)
	u, _ := url.Parse(link)
	pw := e.post(u.Path, url.Values{"token": {u.Query().Get("token")}, "csrf": {csrf}}, ck)
	if pw.Code != 200 || !strings.Contains(pw.Body.String(), "confirmed") || !e.user("u1").EmailVerified {
		t.Fatalf("verify failed: %d %s", pw.Code, pw.Body)
	}
	if w := ev.login(authQuery(nil), "alice", "oldpassword"); w.Code != 302 {
		t.Errorf("verified user cannot sign in: %d", w.Code)
	}
	// Replay.
	_, csrf, ck = e.form(link)
	if w := e.post(u.Path, url.Values{"token": {u.Query().Get("token")}, "csrf": {csrf}}, ck); w.Code != http.StatusBadRequest {
		t.Errorf("replayed verify link status %d", w.Code)
	}
}

func TestWrongPasswordNeverTriggersEmail(t *testing.T) {
	e := newAEnv(t, true)
	(&env{t: t, h: e.h}).login(authQuery(nil), "alice", "wrongpassword")
	e.h.Drain()
	if n := len(e.mail.all()); n != 0 {
		t.Fatalf("a wrong password sent %d emails (would allow mail-bombing any user)", n)
	}
}

func TestEmailFlowsOffWithoutMailer(t *testing.T) {
	e := newAEnv(t, false)
	for _, p := range []string{fp, "/realms/r/login-actions/reset-password?token=x", "/realms/r/login-actions/verify-email?token=x"} {
		if w := e.do(httptest.NewRequest("GET", p, nil)); w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", p, w.Code)
		}
	}
	w := e.do(httptest.NewRequest("GET", base+"auth?"+authQuery(nil).Encode(), nil))
	if strings.Contains(w.Body.String(), "Forgot") {
		t.Error("login page advertises a reset flow that is disabled")
	}
	// Unverified login keeps the old behaviour.
	l := (&env{t: t, h: e.h}).login(authQuery(nil), "alice", "oldpassword")
	if !strings.Contains(l.Body.String(), "has not been verified") {
		t.Errorf("unexpected: %s", l.Body)
	}
}

func TestLoginPageLinksToReset(t *testing.T) {
	e := newAEnv(t, true)
	w := e.do(httptest.NewRequest("GET", base+"auth?"+authQuery(nil).Encode(), nil))
	if !strings.Contains(w.Body.String(), "/realms/r/login-actions/forgot-password") {
		t.Error("no forgot-password link")
	}
}

func TestEmailRateLimits(t *testing.T) {
	e := newAEnv(t, true)
	for i := 0; i < 8; i++ {
		e.forgot("alice")
	}
	if n := len(e.mail.all()); n != actions.MaxPerHour {
		t.Errorf("per-user limit: sent %d, want %d", n, actions.MaxPerHour)
	}
	// Per-IP limit: after forgotLimit requests nothing more is even attempted.
	e2 := newAEnv(t, true)
	for i := 0; i < forgotLimit+5; i++ {
		e2.now = e2.now.Add(time.Minute * 0) // same window
		e2.forgot("dora")                    // disabled: never mails, but still counts per IP
	}
	e2.forgot("alice")
	if n := len(e2.mail.all()); n != 0 {
		t.Errorf("request beyond the per-IP limit still sent mail (%d)", n)
	}
	e2.ip = "198.51.100.9:1" // a different client is unaffected
	e2.forgot("alice")
	if n := len(e2.mail.all()); n != 1 {
		t.Errorf("other IP blocked: %d", n)
	}
}

func TestActionPagesRequireCSRF(t *testing.T) {
	e := newAEnv(t, true)
	if w := e.post(fp, url.Values{"username": {"alice"}}, nil); w.Code != http.StatusForbidden {
		t.Errorf("forgot without csrf: %d", w.Code)
	}
	e.forgot("alice")
	l := e.lastLink()
	u, _ := url.Parse(l)
	if w := e.post(u.Path, url.Values{"token": {u.Query().Get("token")}, "password": {"newpassword1"}, "confirm": {"newpassword1"}}, nil); w.Code != http.StatusForbidden {
		t.Errorf("reset without csrf: %d", w.Code)
	}
	if e.user("u1").PasswordHash != "H:oldpassword" {
		t.Error("password changed without csrf")
	}
}

func TestMailFailureLeavesNoLiveToken(t *testing.T) {
	e := newAEnv(t, true)
	e.mail.err = context.DeadlineExceeded
	e.forgot("alice")
	n, _ := e.st.CountActionTokens(context.Background(), "r", "u1", core.ActionResetPassword, e.now.Add(-time.Hour))
	if n != 0 {
		t.Errorf("%d token(s) left after a failed send", n)
	}
}

// failRL makes the shared limiter fail while everything else works.
type failRL struct{ core.Store }

func (failRL) HitRateLimit(context.Context, string, time.Time, time.Duration, int) (bool, error) {
	return false, context.DeadlineExceeded
}

// replica builds another provider over the same store, as a second process.
func (e *aenv) replica(st core.Store) *Provider {
	clock := func() time.Time { return e.now }
	return New(Config{Store: st, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{},
		BaseURL: "https://idp.example", Clock: clock, CSRFKey: []byte("0123456789abcdef0123456789abcdef"),
		Actions: &actions.Service{Store: e.st, Mailer: e.mail, BaseURL: "https://idp.example", Clock: clock}})
}

func TestForgotLimitSharedAcrossReplicasAndFailsClosed(t *testing.T) {
	e := newAEnv(t, true)
	for i := 0; i < forgotLimit; i++ {
		e.forgot("dora")
	}
	// A second replica sharing the store sees the exhausted budget.
	e.h = e.replica(e.st)
	e.forgot("alice")
	if n := len(e.mail.all()); n != 0 {
		t.Errorf("second replica allowed a request past the shared limit (%d mails)", n)
	}
	// A store error behaves as rate limited, with the generic answer.
	e3 := newAEnv(t, true)
	e3.h = e3.replica(failRL{e3.st})
	w := e3.forgot("alice")
	if n := len(e3.mail.all()); n != 0 {
		t.Errorf("limiter store error did not fail closed (%d mails)", n)
	}
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Check your email") {
		t.Errorf("fail-closed answer not generic: %d %s", w.Code, w.Body)
	}
}
