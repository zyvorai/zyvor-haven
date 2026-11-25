// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/sessions"
	"github.com/zyvorai/haven/internal/idp/ssf"
)

// scEnv is a pkEnv with a recording back-channel notifier and several
// browsers (cookie jars).
type scEnv struct {
	*pkEnv
	rec *recNotifier
}

type jar = map[string]*http.Cookie

func newSC(t *testing.T, pol core.SessionPolicy, mut func(*core.Realm), wrap func(core.Store) core.Store) *scEnv {
	t.Helper()
	e := &scEnv{rec: &recNotifier{}}
	e.pkEnv = newPKEnv(t, mut, wrap, func(c *Config) {
		c.Sessions = &sessions.Service{Store: c.Store, Notifier: e.rec}
	})
	e.policy(pol)
	return e
}

func (e *scEnv) policy(p core.SessionPolicy) {
	e.t.Helper()
	must(e.t, e.st.PutSessionPolicy(context.Background(), "r", p))
}

// browser switches to a fresh browser and returns its jar.
func (e *scEnv) browser() jar { e.cookies = jar{}; return e.cookies }

// signIn logs alice in with her password in a fresh browser, one second later
// than the previous login so that "oldest" is well defined.
func (e *scEnv) signIn(fields url.Values) (jar, *httptest.ResponseRecorder) {
	e.t.Helper()
	e.now = e.now.Add(time.Second)
	j := e.browser()
	return j, e.formLogin("alice", pkPW, fields)
}

func (e *pkEnv) formLogin(user, pw string, fields url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.formLoginAt(authPOST(), user, pw, fields)
}

func (e *pkEnv) formLoginAt(path, user, pw string, fields url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	csrf := csrfRe.FindStringSubmatch(e.do("GET", path, nil).Body.String())[1]
	f := url.Values{"csrf": {csrf}, "username": {user}, "password": {pw}}
	for k, v := range fields {
		f[k] = v
	}
	return e.do("POST", path, f)
}

// onlinePath asks for a session-bound refresh token (no offline_access).
func onlinePath() string { return authPath + authQuery(map[string]string{"scope": "openid"}).Encode() }

// signInOnline is signIn without offline_access.
func (e *scEnv) signInOnline(fields url.Values) (jar, *httptest.ResponseRecorder) {
	e.t.Helper()
	e.now = e.now.Add(time.Second)
	j := e.browser()
	return j, e.formLoginAt(onlinePath(), "alice", pkPW, fields)
}

// silent reports whether the browser is signed in (SSO answers with a code).
func (e *scEnv) silent(j jar) bool {
	e.cookies = j
	return isCode(e.do("GET", authPOST(), nil))
}

func (e *scEnv) sessions() []core.Session {
	e.t.Helper()
	all, err := e.st.ListSessions(context.Background(), "r", "u1", 1000)
	must(e.t, err)
	return all
}

func jsonField(w *httptest.ResponseRecorder, name string) string {
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	s, _ := m[name].(string)
	return s
}

// tokens exchanges the code of a login response.
func (e *pkEnv) tokens(w *httptest.ResponseRecorder) (int, string) {
	e.t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	must(e.t, err)
	res := e.do("POST", base+"token", codeForm(u.Query().Get("code")))
	return res.Code, jsonField(res, "refresh_token")
}

func (e *pkEnv) refresh(rt string) (int, string) {
	e.t.Helper()
	res := e.do("POST", base+"token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"app"}})
	return res.Code, jsonField(res, "refresh_token")
}

// ---- concurrent session limit ----

func TestSessionLimitUnsetIsUnlimited(t *testing.T) {
	e := newSC(t, core.SessionPolicy{}, nil, nil)
	var jars []jar
	for range 5 {
		j, w := e.signIn(nil)
		if !isCode(w) {
			t.Fatalf("login: %d", w.Code)
		}
		jars = append(jars, j)
	}
	for _, j := range jars {
		if !e.silent(j) {
			t.Fatal("a session ended without a limit")
		}
	}
}

// signalStore records Shared Signals (the SSF decorator's place in the chain).
type signalStore struct {
	core.Store
	got *[]core.Signal
}

func (s signalStore) Unwrap() core.Store                            { return s.Store }
func (s signalStore) EmitSignal(_ context.Context, sig core.Signal) { *s.got = append(*s.got, sig) }

func TestSessionLimitRevokesOldest(t *testing.T) {
	var signals []core.Signal
	e := newSC(t, core.SessionPolicy{MaxSessions: 2}, nil, func(s core.Store) core.Store { return signalStore{s, &signals} })
	a, wa := e.signInOnline(nil)
	e.cookies = a
	code, rtA := e.tokens(wa)
	if code != 200 || rtA == "" {
		t.Fatalf("tokens: %d", code)
	}
	oldest := e.sessions()[0].ID
	b, _ := e.signIn(nil)
	c, w := e.signIn(nil)
	if !isCode(w) {
		t.Fatalf("third login must succeed: %d %s", w.Code, w.Body)
	}
	if n := len(e.sessions()); n != 2 {
		t.Fatalf("%d sessions", n)
	}
	if e.silent(a) {
		t.Fatal("the oldest session survived")
	}
	if !e.silent(b) || !e.silent(c) {
		t.Fatal("a newer session was ended")
	}
	// Ended exactly like a logout: back-channel notification and refresh tokens.
	if e.rec.count(oldest, "app") != 1 {
		t.Errorf("back-channel notifications for the evicted session: %d", e.rec.count(oldest, "app"))
	}
	e.cookies = jar{}
	if code, _ := e.refresh(rtA); code == 200 {
		t.Error("refresh token of the evicted session still works")
	}
	evs, _ := e.st.ListEvents(context.Background(), "r", 100)
	found := false
	for _, ev := range evs {
		found = found || (ev.Type == "LOGOUT" && ev.Detail == "session_limit")
	}
	if !found {
		t.Error("no LOGOUT session_limit event")
	}
	revoked := 0
	for _, s := range signals {
		if s.Kind == ssf.EvSessionRevoked && s.SessionID == oldest && s.UserID == "u1" {
			revoked++
		}
	}
	if revoked != 1 {
		t.Errorf("session-revoked signals for the evicted session: %d", revoked)
	}
}

func TestSessionLimitDenyNew(t *testing.T) {
	e := newSC(t, core.SessionPolicy{MaxSessions: 1, OnLimit: core.SessionLimitDenyNew}, nil, nil)
	a, w := e.signIn(nil)
	if !isCode(w) {
		t.Fatal("first login")
	}
	first := e.sessions()[0].ID
	b, w := e.signIn(nil)
	if isCode(w) || w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Too many sessions") {
		t.Fatalf("second login: %d %s", w.Code, w.Body)
	}
	if b[ssoCookie] != nil {
		t.Fatal("refused login set an SSO cookie")
	}
	if len(e.sessions()) != 1 || e.rec.count(first, "app") != 0 || !e.silent(a) {
		t.Fatal("the existing session was touched")
	}
	if e.events("LOGIN_ERROR") == 0 {
		t.Error("not audited")
	}
	// A wrong password answers as always: the limit is only told to someone who
	// completed the login.
	e.browser()
	if w := e.formLogin("alice", "nope", nil); !strings.Contains(w.Body.String(), badCreds) || strings.Contains(w.Body.String(), "Too many sessions") {
		t.Fatalf("wrong password: %d", w.Code)
	}
	// The same browser signing in again replaces its own session.
	e.cookies = a
	e.now = e.now.Add(time.Second)
	w = e.do("GET", authPath+authQuery(map[string]string{"prompt": "login"}).Encode(), nil)
	csrf := csrfRe.FindStringSubmatch(w.Body.String())[1]
	w = e.do("POST", authPath+authQuery(map[string]string{"prompt": "login"}).Encode(), url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {pkPW}})
	if !isCode(w) || len(e.sessions()) != 1 || e.sessions()[0].ID == first {
		t.Fatalf("re-login in the same browser: %d (%d sessions)", w.Code, len(e.sessions()))
	}
	// An expired session frees its slot.
	e.now = e.now.Add(31 * time.Minute)
	if _, w := e.signIn(nil); !isCode(w) {
		t.Fatalf("after expiry: %d", w.Code)
	}
}

func TestSessionLimitAppliesAfterSecondFactorAndPasskey(t *testing.T) {
	e := newSC(t, core.SessionPolicy{}, nil, nil)
	a := e.register(-7)
	e.policy(core.SessionPolicy{MaxSessions: 1, OnLimit: core.SessionLimitDenyNew})
	e.browser()
	w := e.passwordLogin(pkPW)
	if !isPasskeyPage(w) {
		t.Fatalf("setup: %d", w.Code)
	}
	w = e.do("POST", authPOST(), assertionForm(parsePKPage(t, w), "2fa", a, pkOrigin))
	if isCode(w) || w.Code != http.StatusForbidden {
		t.Fatalf("second-factor login ignored the limit: %d", w.Code)
	}
	e.browser()
	if w := e.passkeyLogin(a); isCode(w) || w.Code != http.StatusForbidden {
		t.Fatalf("passkey login ignored the limit: %d", w.Code)
	}
}

type failSessionPolicy struct{ core.Store }

func (f failSessionPolicy) Unwrap() core.Store { return f.Store }
func (f failSessionPolicy) GetSessionPolicy(context.Context, string) (core.SessionPolicy, error) {
	return core.SessionPolicy{}, errors.New("boom")
}
func (f failSessionPolicy) PutSessionPolicy(context.Context, string, core.SessionPolicy) error {
	return nil
}
func (f failSessionPolicy) CreateLimitedSession(context.Context, core.Session, core.NewSessionOptions) ([]core.Session, error) {
	return nil, errors.New("boom")
}
func (f failSessionPolicy) SessionRememberIdle(context.Context, string, string) (time.Duration, error) {
	return 0, errors.New("boom")
}

func TestSessionPolicyErrorRefusesLogin(t *testing.T) {
	e := newPKEnv(t, nil, func(s core.Store) core.Store { return failSessionPolicy{s} }, nil)
	w := e.passwordLogin(pkPW)
	if isCode(w) || w.Code != http.StatusInternalServerError || e.sessionCount() != 0 {
		t.Fatalf("login proceeded without a readable policy: %d", w.Code)
	}
}

// ---- keep me signed in ----

func (e *scEnv) only() core.Session {
	e.t.Helper()
	all := e.sessions()
	if len(all) != 1 {
		e.t.Fatalf("%d sessions", len(all))
	}
	return all[0]
}

func (e *scEnv) reset() {
	e.t.Helper()
	_, err := e.st.TakeUserSessions(context.Background(), "r", "u1")
	must(e.t, err)
}

var on = url.Values{"remember_me": {"on"}}

func TestRememberMeIsOptInPerRealm(t *testing.T) {
	e := newSC(t, core.SessionPolicy{}, nil, nil)
	if strings.Contains(e.loginPage().Body.String(), `type="checkbox"`) {
		t.Fatal("checkbox shown although the realm did not opt in")
	}
	// A forged field is ignored.
	j, w := e.signIn(on)
	s := e.only()
	if !isCode(w) || s.ExpiresAt.Sub(s.CreatedAt) != maxSessionLife || s.IdleExpires.Sub(s.CreatedAt) != defaultIdle {
		t.Fatalf("lifetime without opt-in: %v %v", s.ExpiresAt.Sub(s.CreatedAt), s.IdleExpires.Sub(s.CreatedAt))
	}
	if c := j[ssoCookie]; c == nil || !c.Expires.Equal(s.ExpiresAt) {
		t.Errorf("cookie expiry: %+v", c)
	}
}

func TestRememberMeLifetimes(t *testing.T) {
	e := newSC(t, core.SessionPolicy{RememberMe: true}, nil, nil)
	body := e.loginPage().Body.String()
	if !strings.Contains(body, `<input type="checkbox" name="remember_me" value="on">`) {
		t.Fatalf("checkbox missing or pre-ticked: %s", body[strings.Index(body, "<main"):])
	}
	// Unticked: an ordinary session.
	_, w := e.signIn(nil)
	if s := e.only(); !isCode(w) || s.ExpiresAt.Sub(s.CreatedAt) != maxSessionLife {
		t.Fatalf("unticked: %v", s.ExpiresAt.Sub(s.CreatedAt))
	}
	e.reset()
	// A failed attempt keeps the tick.
	e.browser()
	if b := e.formLogin("alice", "nope", on).Body.String(); !strings.Contains(b, `value="on" checked>`) {
		t.Error("tick lost on a failed attempt")
	}
	j, w := e.signIn(on)
	s := e.only()
	if !isCode(w) || s.ExpiresAt.Sub(s.CreatedAt) != core.DefaultRememberMax || s.IdleExpires.Sub(s.CreatedAt) != core.DefaultRememberIdle {
		t.Fatalf("ticked: %v %v", s.ExpiresAt.Sub(s.CreatedAt), s.IdleExpires.Sub(s.CreatedAt))
	}
	if c := j[ssoCookie]; c == nil || !c.Expires.Equal(s.ExpiresAt) || !c.HttpOnly || !c.Secure {
		t.Errorf("cookie: %+v", c)
	}
	// Alive after days of idling, and each use slides the long idle window.
	e.now = e.now.Add(6 * 24 * time.Hour)
	if !e.silent(j) {
		t.Fatal("remembered session expired after 6 days")
	}
	if s := e.only(); s.IdleExpires.Sub(e.now) != core.DefaultRememberIdle {
		t.Fatalf("slid to %v", s.IdleExpires.Sub(e.now))
	}
	e.now = e.now.Add(core.DefaultRememberIdle)
	if e.silent(j) {
		t.Fatal("remembered session survived its idle window")
	}
}

func TestRememberMeAbsoluteBoundAndWithdrawal(t *testing.T) {
	pol := core.SessionPolicy{RememberMe: true, RememberIdle: 20 * 24 * time.Hour, RememberMax: 30 * 24 * time.Hour}
	e := newSC(t, pol, nil, nil)
	j, _ := e.signIn(on)
	// Used regularly, it still ends at the absolute maximum.
	for range 2 {
		e.now = e.now.Add(14 * 24 * time.Hour)
		if !e.silent(j) {
			t.Fatal("ended early")
		}
	}
	e.now = e.now.Add(3 * 24 * time.Hour) // day 31
	if e.silent(j) {
		t.Fatal("remembered session outlived the maximum")
	}
	// Shortening the maximum applies to existing sessions at once.
	e.reset()
	j, w := e.signInOnline(on)
	e.cookies = j
	_, rt := e.tokens(w)
	if rt == "" {
		t.Fatal("no refresh token")
	}
	e.now = e.now.Add(3 * 24 * time.Hour)
	if !e.silent(j) {
		t.Fatal("setup")
	}
	e.policy(core.SessionPolicy{RememberMe: true, RememberMax: 48 * time.Hour})
	if e.silent(j) {
		t.Fatal("session older than the shortened maximum accepted")
	}
	// Turning the option off ends the use of remembered sessions, also for
	// refresh tokens.
	e.policy(pol)
	if !e.silent(j) {
		t.Fatal("setup 2")
	}
	e.policy(core.SessionPolicy{})
	if e.silent(j) {
		t.Fatal("remembered session accepted after the option was turned off")
	}
	e.cookies = jar{}
	if code, _ := e.refresh(rt); code == 200 {
		t.Fatal("refresh token of a withdrawn remembered session still works")
	}
}

// In deny mode a withdrawn long session must not occupy a slot.
func TestRememberMeWithdrawnSessionFreesItsSlot(t *testing.T) {
	e := newSC(t, core.SessionPolicy{RememberMe: true, MaxSessions: 1, OnLimit: core.SessionLimitDenyNew}, nil, nil)
	if _, w := e.signIn(on); !isCode(w) {
		t.Fatal("setup")
	}
	if _, w := e.signIn(nil); isCode(w) {
		t.Fatal("limit not applied")
	}
	e.policy(core.SessionPolicy{MaxSessions: 1, OnLimit: core.SessionLimitDenyNew})
	if _, w := e.signIn(nil); !isCode(w) {
		t.Fatalf("a session nobody can use blocks the login: %d", w.Code)
	}
}

func TestRememberMeSurvivesSecondFactor(t *testing.T) {
	e := newSC(t, core.SessionPolicy{}, nil, nil)
	a := e.register(-7)
	e.reset()
	e.policy(core.SessionPolicy{RememberMe: true})
	secondStep := func(first url.Values, tamper func()) core.Session {
		e.reset()
		e.browser()
		w := e.formLogin("alice", pkPW, first)
		if !isPasskeyPage(w) {
			t.Fatalf("setup: %d", w.Code)
		}
		if tamper != nil {
			tamper()
		}
		w = e.do("POST", authPOST(), assertionForm(parsePKPage(t, w), "2fa", a, pkOrigin))
		if !isCode(w) {
			t.Fatalf("second factor: %d %s", w.Code, w.Body)
		}
		if e.cookies[rememberCookie] != nil {
			t.Error("remember cookie not cleared after use")
		}
		return e.only()
	}
	if s := secondStep(on, nil); s.ExpiresAt.Sub(s.CreatedAt) != core.DefaultRememberMax {
		t.Fatalf("choice lost across the second factor: %v", s.ExpiresAt.Sub(s.CreatedAt))
	}
	if s := secondStep(nil, nil); s.ExpiresAt.Sub(s.CreatedAt) != maxSessionLife {
		t.Fatalf("unticked became remembered: %v", s.ExpiresAt.Sub(s.CreatedAt))
	}
	// A cookie that was not made for this user and this request is ignored.
	for name, forge := range map[string]func() string{
		"garbage": func() string { return "aaaa.bbbb" },
		"other user": func() string {
			return e.h.signPending("r", "u2", rememberPurpose, mfaBind(httptest.NewRequest("GET", authPOST(), nil)), time.Minute)
		},
		"other request": func() string {
			return e.h.signPending("r", "u1", rememberPurpose, "0000000000000000", time.Minute)
		},
		"other purpose": func() string {
			return e.h.signPending("r", "u1", "mfa", mfaBind(httptest.NewRequest("GET", authPOST(), nil)), time.Minute)
		},
	} {
		s := secondStep(nil, func() { e.cookies[rememberCookie] = &http.Cookie{Name: rememberCookie, Value: forge()} })
		if s.ExpiresAt.Sub(s.CreatedAt) != maxSessionLife {
			t.Errorf("%s: forged cookie accepted", name)
		}
	}
	// A stale cookie from an abandoned ticked attempt is dropped by an
	// unticked password step.
	e.reset()
	e.browser()
	e.formLogin("alice", pkPW, on)
	stale := e.cookies[rememberCookie]
	if stale == nil {
		t.Fatal("no remember cookie at the password step")
	}
	if s := secondStep(nil, nil); s.ExpiresAt.Sub(s.CreatedAt) != maxSessionLife {
		t.Fatal("stale choice applied")
	}
}

func TestRememberMeWithPasskeyButton(t *testing.T) {
	e := newSC(t, core.SessionPolicy{}, nil, nil)
	a := e.register(-7)
	e.policy(core.SessionPolicy{RememberMe: true})
	for _, tc := range []struct {
		field string
		want  time.Duration
	}{{"on", core.DefaultRememberMax}, {"", maxSessionLife}} {
		e.reset()
		e.browser()
		f := assertionForm(parsePKPage(t, e.loginPage()), "login", a, pkOrigin)
		f.Set("remember_me", tc.field) // copied from the checkbox by the page script
		if w := e.do("POST", authPOST(), f); !isCode(w) {
			t.Fatalf("passkey login: %d", w.Code)
		}
		if s := e.only(); s.ExpiresAt.Sub(s.CreatedAt) != tc.want {
			t.Errorf("remember_me=%q: %v", tc.field, s.ExpiresAt.Sub(s.CreatedAt))
		}
	}
}
