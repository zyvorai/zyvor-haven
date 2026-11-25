// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/webauthn/webauthntest"
)

// ---- conditional UI (passkey autofill) ----

func TestPasskeyConditionalUIOnLoginPage(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	w := e.loginPage()
	body, csp := w.Body.String(), w.Header().Get("Content-Security-Policy")
	for _, want := range []string{`autocomplete="username webauthn"`, `data-conditional="1"`, `mediation:'conditional'`,
		"isConditionalMediationAvailable", "auto.abort()", `<input type="hidden" name="remember_me">`,
		// the password form is an ordinary form, whatever the script does
		`<input id="p" name="password" type="password" autocomplete="current-password" required`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %q", want)
		}
	}
	// Nothing was loosened for it: same script-nonce-only policy.
	if !strings.Contains(csp, "script-src 'nonce-") || strings.Contains(csp, "unsafe") ||
		strings.Contains(csp, "connect-src") || strings.Contains(csp, "frame-src") {
		t.Errorf("CSP: %s", csp)
	}
	// Only the login form asks for autofill: the second-factor step and the
	// account page never start a conditional request.
	a := e.register(-7)
	e.forget()
	if step := e.passwordLogin(pkPW).Body.String(); strings.Contains(step, `data-conditional="1"`) {
		t.Error("second-factor step starts a conditional request")
	}
	// The challenge behind the autofill request is the single-use one of the
	// page: an assertion picked from autofill cannot be posted twice.
	e.forget()
	pg := parsePKPage(t, e.loginPage())
	f := assertionForm(pg, "login", a, pkOrigin)
	if !isCode(e.do("POST", authPOST(), f)) {
		t.Fatal("autofill assertion refused")
	}
	e.forget()
	f.Set("csrf", parsePKPage(t, e.loginPage()).csrf)
	if isCode(e.do("POST", authPOST(), f)) {
		t.Fatal("autofill assertion accepted twice")
	}
}

func TestPasskeyConditionalUIAbsentWhenPasskeysOff(t *testing.T) {
	// An unusable relying party switches passkeys off.
	e := newPKEnv(t, nil, nil, func(c *Config) { c.WebAuthn = WebAuthnConfig{Origins: []string{"not-an-origin"}} })
	body := e.loginPage().Body.String()
	if strings.Contains(body, "webauthn") || strings.Contains(body, "<script") || !strings.Contains(body, `autocomplete="username"`) {
		t.Fatalf("passkeys off but the page mentions them: %s", body[strings.Index(body, "<main>"):])
	}
	if w := e.passwordLogin(pkPW); !isCode(w) {
		t.Fatalf("password sign-in blocked: %d", w.Code)
	}
}

// ---- passkey re-authentication on the account page ----

var (
	reauthOptsRe  = regexp.MustCompile(`data-pk="get" data-opts="([^"]*)"`)
	addSubmitText = `name="pk_action" value="add"`
)

// stale registers a passkey and lets the sign-in age past the recent window.
func staleAccount(t *testing.T, mut func(*core.Realm)) (*pkEnv, *webauthntest.Authenticator) {
	t.Helper()
	e := newPKEnv(t, mut, nil, nil)
	a := e.register(-7)
	e.now = e.now.Add(11 * time.Minute)
	return e, a
}

func (e *pkEnv) reauthPage() pkPage {
	e.t.Helper()
	pg := parsePKPage(e.t, e.do("GET", e.accountPath(), nil))
	return pg
}

func reauthForm(pg pkPage, a *webauthntest.Authenticator, origin string) url.Values {
	f := assertionForm(pg, "", a, origin)
	f.Del("pk_mode")
	f.Set("pk_action", "reauth_passkey")
	return f
}

func TestPasskeyReauthOnAccountPage(t *testing.T) {
	e, a := staleAccount(t, nil)
	w := e.do("GET", e.accountPath(), nil)
	body := w.Body.String()
	if !strings.Contains(body, "Confirm with a passkey") || !strings.Contains(body, `name="password"`) ||
		!reauthOptsRe.MatchString(body) || strings.Contains(body, addSubmitText) || strings.Contains(body, `data-conditional="1"`) {
		t.Fatalf("stale account page: %s", body[strings.Index(body, "<main"):])
	}
	pg := e.reauthPage()
	if pg.opts["userVerification"] != "required" || len(pg.opts["allowCredentials"].([]any)) != 1 {
		t.Fatalf("reauth options: %v", pg.opts)
	}
	f := reauthForm(pg, a, pkOrigin)
	w = e.do("POST", e.accountPath(), f)
	if w.Code != http.StatusSeeOther || e.cookies[pkReauthCook] == nil {
		t.Fatalf("passkey reauth: %d %s", w.Code, w.Body)
	}
	if got, _ := e.st.GetPasskey(context.Background(), "r", bu(a.CredID)); !got.LastUsedAt.Equal(e.now) {
		t.Error("use not recorded")
	}
	// Now adding and removing work.
	pg2 := parsePKPage(t, e.do("GET", e.accountPath(), nil))
	if !strings.Contains(pg2.body, addSubmitText) {
		t.Fatal("not unlocked")
	}
	if w := e.do("POST", e.accountPath(), url.Values{"csrf": {pg2.csrf}, "pk_action": {"delete"}, "cred": {bu(a.CredID)}}); w.Code != http.StatusSeeOther {
		t.Fatalf("delete after passkey reauth: %d", w.Code)
	}
}

func TestPasskeyReauthRefusals(t *testing.T) {
	cases := map[string]func(t *testing.T, e *pkEnv, a *webauthntest.Authenticator) url.Values{
		"wrong origin": func(t *testing.T, e *pkEnv, a *webauthntest.Authenticator) url.Values {
			return reauthForm(e.reauthPage(), a, "https://evil.example")
		},
		"no user verification": func(t *testing.T, e *pkEnv, a *webauthntest.Authenticator) url.Values {
			a.UV = false
			return reauthForm(e.reauthPage(), a, pkOrigin)
		},
		"unknown credential": func(t *testing.T, e *pkEnv, a *webauthntest.Authenticator) url.Values {
			o := webauthntest.New(-7, pkRPID)
			o.UserHandle = a.UserHandle
			return reauthForm(e.reauthPage(), o, pkOrigin)
		},
		"another user's passkey": func(t *testing.T, e *pkEnv, a *webauthntest.Authenticator) url.Values {
			ctx := context.Background()
			must(t, e.st.CreateUser(ctx, core.User{ID: "u2", Realm: "r", Username: "bob", Enabled: true}))
			real, err := e.st.GetPasskey(ctx, "r", bu(a.CredID))
			must(t, err)
			// Move the credential to bob: a valid signature, but not alice's key.
			must(t, e.st.DeletePasskey(ctx, "r", "u1", real.CredentialID, false))
			real.UserID = "u2"
			must(t, e.st.AddPasskey(ctx, real))
			must(t, e.st.AddPasskey(ctx, core.Passkey{Realm: "r", UserID: "u1", CredentialID: "alices-other", PublicKey: []byte{1}}))
			return reauthForm(e.reauthPage(), a, pkOrigin)
		},
		"login challenge": func(t *testing.T, e *pkEnv, a *webauthntest.Authenticator) url.Values {
			pg := e.reauthPage()
			// A genuine sign-in challenge (anyone can fetch one from the login page).
			pg.challenge, pg.token = e.h.pkChallenge("r", "u1", pkPurposeLogin)
			return reauthForm(pg, a, pkOrigin)
		},
		"challenge of another session": func(t *testing.T, e *pkEnv, a *webauthntest.Authenticator) url.Values {
			pg := e.reauthPage()
			// Same user, same challenge, genuinely signed, but for another session.
			pg.token = e.h.signPending("r", "u1", pkReauthPurpose("some-other-session"), bu(pg.challenge), pkChallengeTTL)
			return reauthForm(pg, a, pkOrigin)
		},
		"expired challenge": func(t *testing.T, e *pkEnv, a *webauthntest.Authenticator) url.Values {
			pg := e.reauthPage()
			e.now = e.now.Add(6 * time.Minute)
			f := reauthForm(pg, a, pkOrigin)
			f.Set("csrf", e.reauthPage().csrf)
			return f
		},
		"locked account": func(t *testing.T, e *pkEnv, a *webauthntest.Authenticator) url.Values {
			u, _ := e.st.GetUser(context.Background(), "r", "u1")
			u.LockedUntil = e.now.Add(time.Hour)
			must(t, e.st.UpdateUser(context.Background(), u))
			return reauthForm(e.reauthPage(), a, pkOrigin)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			e, a := staleAccount(t, nil)
			f := build(t, e, a)
			w := e.do("POST", e.accountPath(), f)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "could not confirm it is you") {
				t.Fatalf("%d %s", w.Code, w.Body.String()[strings.Index(w.Body.String(), "<main"):])
			}
			if e.cookies[pkReauthCook] != nil {
				t.Fatal("re-authentication cookie issued")
			}
			if strings.Contains(w.Body.String(), addSubmitText) {
				t.Fatal("page unlocked")
			}
		})
	}
}

func TestPasskeyReauthSingleUseCSRFAndRate(t *testing.T) {
	e, a := staleAccount(t, nil)
	a.Counting, a.SignCount = false, 0
	must(t, e.st.UpdatePasskeyUse(context.Background(), "r", bu(a.CredID), 0, false, e.now))
	pg := e.reauthPage()
	f := reauthForm(pg, a, pkOrigin)
	// CSRF first: nothing is consumed by a forged post.
	bad := url.Values{}
	for k, v := range f {
		bad[k] = v
	}
	bad.Set("csrf", "forged")
	if w := e.do("POST", e.accountPath(), bad); w.Code != http.StatusForbidden || e.cookies[pkReauthCook] != nil {
		t.Fatalf("reauth without a CSRF token: %d", w.Code)
	}
	if w := e.do("POST", e.accountPath(), f); w.Code != http.StatusSeeOther {
		t.Fatalf("reauth: %d %s", w.Code, w.Body)
	}
	// Replay of the captured fields, with a zero-counter authenticator: only
	// the single-use challenge stops it.
	delete(e.cookies, pkReauthCook)
	f.Set("csrf", e.reauthPage().csrf)
	if w := e.do("POST", e.accountPath(), f); w.Code != http.StatusForbidden || e.cookies[pkReauthCook] != nil {
		t.Fatalf("replayed re-authentication accepted: %d", w.Code)
	}
	// Password and passkey share one budget (5 per user): 2 used above.
	for i := 0; i < 3; i++ {
		csrf := e.reauthPage().csrf
		e.do("POST", e.accountPath(), url.Values{"csrf": {csrf}, "pk_action": {"reauth"}, "password": {"nope"}})
	}
	pg = e.reauthPage()
	if w := e.do("POST", e.accountPath(), reauthForm(pg, a, pkOrigin)); w.Code != http.StatusTooManyRequests || e.cookies[pkReauthCook] != nil {
		t.Fatalf("sixth attempt: %d", w.Code)
	}
}

func TestPasskeyReauthNotOfferedWithoutPasskey(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	if !isCode(e.passwordLogin(pkPW)) {
		t.Fatal("login")
	}
	e.now = e.now.Add(11 * time.Minute)
	body := e.do("GET", e.accountPath(), nil).Body.String()
	if strings.Contains(body, "Confirm with a passkey") || strings.Contains(body, "<script") || !strings.Contains(body, `name="password"`) {
		t.Fatalf("page: %s", body[strings.Index(body, "<main"):])
	}
}

// ---- passkey-only for users who have a passkey ----

func (e *pkEnv) passkeyOnly(on bool) {
	e.t.Helper()
	must(e.t, e.st.SetPasskeyOnly(context.Background(), "r", on))
}

func (e *pkEnv) addUser(id, name string) {
	e.t.Helper()
	hash, err := e.h.cfg.Hasher.Hash(pkPW)
	must(e.t, err)
	must(e.t, e.st.CreateUser(context.Background(), core.User{ID: id, Realm: "r", Username: name, Enabled: true, EmailVerified: true, PasswordHash: hash}))
}

func (e *pkEnv) loginAs(user, pw string) *httptest.ResponseRecorder {
	w := e.loginPage()
	csrf := csrfRe.FindStringSubmatch(w.Body.String())[1]
	return e.do("POST", authPOST(), url.Values{"csrf": {csrf}, "username": {user}, "password": {pw}})
}

func (e *pkEnv) passkeyLogin(a *webauthntest.Authenticator) *httptest.ResponseRecorder {
	pg := parsePKPage(e.t, e.loginPage())
	return e.do("POST", authPOST(), assertionForm(pg, "login", a, pkOrigin))
}

// stripVolatile removes per-response values so two pages can be compared.
func stripVolatile(s string) string {
	for _, re := range []string{`value="[^"]*"`, `nonce="[^"]*"`, `data-opts="[^"]*"`} {
		s = regexp.MustCompile(re).ReplaceAllString(s, "")
	}
	return s
}

func (e *pkEnv) sessionCount() int {
	e.t.Helper()
	all, err := e.st.ListSessions(context.Background(), "r", "", 1000)
	must(e.t, err)
	return len(all)
}

func TestPasskeyOnlyOffByDefault(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	e.forget()
	if !isCode(e.passkeyLogin(a)) { // proves the credential
		t.Fatal("passkey login")
	}
	e.forget()
	w := e.passwordLogin(pkPW)
	if !isPasskeyPage(w) {
		t.Fatalf("with the option off the password still leads to the passkey step: %d", w.Code)
	}
	if strings.Contains(e.loginPage().Body.String(), passkeyOnlyNote) {
		t.Error("note shown while the option is off")
	}
}

func TestPasskeyOnlyNeverLocksOutUsersWithoutPasskey(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	e.passkeyOnly(true)
	if !strings.Contains(e.loginPage().Body.String(), passkeyOnlyNote) {
		t.Error("no note on the login page")
	}
	if w := e.passwordLogin(pkPW); !isCode(w) {
		t.Fatalf("user without a passkey cannot sign in: %d %s", w.Code, w.Body)
	}
	// Even with the relying party broken.
	e = newPKEnv(t, nil, nil, func(c *Config) { c.WebAuthn = WebAuthnConfig{Origins: []string{"nonsense"}} })
	e.passkeyOnly(true)
	if w := e.passwordLogin(pkPW); !isCode(w) {
		t.Fatalf("user without a passkey, passkeys off: %d", w.Code)
	}
	// Somebody else's passkey does not affect this user.
	e = newPKEnv(t, nil, nil, nil)
	e.register(-7)
	e.addUser("u2", "bob")
	e.passkeyOnly(true)
	e.forget()
	if w := e.loginAs("bob", pkPW); !isCode(w) {
		t.Fatalf("bob (no passkey): %d", w.Code)
	}
}

func TestPasskeyOnlyUnprovenPasskeyKeepsPasswordPlusPasskey(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7) // never used without a password: may be non-discoverable
	e.passkeyOnly(true)
	e.forget()
	w := e.passwordLogin(pkPW)
	if !isPasskeyPage(w) {
		t.Fatalf("lock-out: the password must still lead to the passkey step: %d %s", w.Code, w.Body)
	}
	if e.sessionCount() != 1 { // only the registration session
		t.Fatal("session before the passkey")
	}
	w = e.do("POST", authPOST(), assertionForm(parsePKPage(t, w), "2fa", a, pkOrigin))
	if !isCode(w) {
		t.Fatalf("password plus passkey: %d %s", w.Code, w.Body)
	}
	// A second-factor use proves nothing about discoverability.
	e.forget()
	if !isPasskeyPage(e.passwordLogin(pkPW)) {
		t.Fatal("second-factor use switched the password off")
	}
}

func TestPasskeyOnlyRefusesPasswordOnceEveryPasskeyIsProven(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	b := e.addPasskey(-8)
	e.passkeyOnly(true)
	e.forget()
	if !isCode(e.passkeyLogin(a)) {
		t.Fatal("passkey login with a")
	}
	e.forget()
	if !isPasskeyPage(e.passwordLogin(pkPW)) {
		t.Fatal("one of two passkeys is still unproven: the password path must stay")
	}
	e.forget()
	if !isCode(e.passkeyLogin(b)) {
		t.Fatal("passkey login with b")
	}
	e.forget()
	before := e.sessionCount()
	right := e.passwordLogin(pkPW)
	wrong := e.passwordLogin("not-the-password")
	if isCode(right) || isPasskeyPage(right) || e.sessionCount() != before || e.cookies[ssoCookie] != nil {
		t.Fatalf("password accepted for a passkey-only user: %d", right.Code)
	}
	// No oracle: the right and a wrong password are answered identically.
	if right.Code != wrong.Code || stripVolatile(right.Body.String()) != stripVolatile(wrong.Body.String()) {
		t.Fatalf("right and wrong password are distinguishable (%d / %d)", right.Code, wrong.Code)
	}
	if !strings.Contains(right.Body.String(), badCreds) {
		t.Fatal("not the generic message")
	}
	// Nor by the cookies set, whatever else the realm has switched on and
	// whatever the browser sends along.
	must(t, e.st.PutSessionPolicy(context.Background(), "r", core.SessionPolicy{RememberMe: true, MaxSessions: 1}))
	cookieNames := func(w *httptest.ResponseRecorder) string {
		var out []string
		for _, c := range w.Result().Cookies() {
			out = append(out, fmt.Sprintf("%s/%d", c.Name, c.MaxAge))
		}
		slices.Sort(out)
		return strings.Join(out, " ")
	}
	for _, sent := range []bool{false, true} {
		attempt := func(pw string) *httptest.ResponseRecorder {
			e.forget()
			if sent {
				e.cookies[rememberCookie] = &http.Cookie{Name: rememberCookie, Value: "x"}
			}
			return e.formLogin("alice", pw, url.Values{"remember_me": {"on"}})
		}
		r, w := attempt(pkPW), attempt("not-the-password")
		if cookieNames(r) != cookieNames(w) || stripVolatile(r.Body.String()) != stripVolatile(w.Body.String()) {
			t.Fatalf("right and wrong password are distinguishable: %q / %q", cookieNames(r), cookieNames(w))
		}
	}
	must(t, e.st.PutSessionPolicy(context.Background(), "r", core.SessionPolicy{}))
	// The passkey still works, as first factor.
	e.forget()
	if !isCode(e.passkeyLogin(a)) {
		t.Fatal("passkey login refused")
	}
	// Turning the option off restores the password (plus passkey) path.
	e.passkeyOnly(false)
	e.forget()
	if !isPasskeyPage(e.passwordLogin(pkPW)) {
		t.Fatal("option off")
	}
	// Removing every passkey restores the plain password.
	e.passkeyOnly(true)
	must(t, e.st.DeletePasskey(context.Background(), "r", "u1", bu(a.CredID), false))
	must(t, e.st.DeletePasskey(context.Background(), "r", "u1", bu(b.CredID), false))
	e.forget()
	if !isCode(e.passwordLogin(pkPW)) {
		t.Fatal("user without passkeys locked out")
	}
}

func TestPasskeyOnlyFailsClosed(t *testing.T) {
	// Relying party broken after the passkey was registered: the password stays
	// refused (an administrator turns the option off or removes the passkey).
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	e.passkeyOnly(true)
	e.forget()
	e.h.cfg.WebAuthn = WebAuthnConfig{Origins: []string{"nonsense"}}
	if w := e.passwordLogin(pkPW); isCode(w) || e.cookies[ssoCookie] != nil {
		t.Fatalf("password re-opened by a broken relying party: %d", w.Code)
	}
	// A policy that cannot be read refuses the login.
	e = newPKEnv(t, nil, func(s core.Store) core.Store { return &failPasskeyOnly{Store: s} }, nil)
	if w := e.passwordLogin(pkPW); isCode(w) || w.Code != http.StatusInternalServerError {
		t.Fatalf("policy error: %d", w.Code)
	}
	_ = a
}

// failPasskeyOnly is a store whose passkey-only policy cannot be read.
type failPasskeyOnly struct{ core.Store }

func (f *failPasskeyOnly) Unwrap() core.Store { return f.Store }
func (f *failPasskeyOnly) PasskeyOnly(context.Context, string) (bool, error) {
	return false, errors.New("boom")
}
func (f *failPasskeyOnly) SetPasskeyOnly(context.Context, string, bool) error { return nil }
func (f *failPasskeyOnly) MarkPasswordlessPasskey(context.Context, string, string, time.Time) error {
	return nil
}
func (f *failPasskeyOnly) PasswordlessPasskeys(context.Context, string, string) ([]string, error) {
	return nil, nil
}

// Whatever route leads to completeLogin, a user the option applies to gets a
// session only when a passkey was used.
func TestPasskeyOnlyCompletionGate(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	e.register(-7)
	e.passkeyOnly(true)
	rl, err := e.st.GetRealm(context.Background(), "r")
	must(t, err)
	cl, err := e.st.GetClientByClientID(context.Background(), "r", "app")
	must(t, err)
	u, err := e.st.GetUser(context.Background(), "r", "u1")
	must(t, err)
	run := func(detail string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", authPOST(), nil)
		e.h.completeLogin(w, r, &authzReq{realm: rl, client: cl, redirect: cb, state: "s"}, u, detail)
		return w
	}
	for _, detail := range []string{"", "totp", "recovery_code", "federated:corp", "something-new"} {
		before := e.sessionCount()
		w := run(detail)
		if isCode(w) || w.Code != http.StatusForbidden || e.sessionCount() != before || !strings.Contains(w.Body.String(), "Use your passkey") {
			t.Errorf("%q completed a passkey-only login: %d", detail, w.Code)
		}
	}
	for _, detail := range []string{"passkey", "passkey_2fa"} {
		if w := run(detail); !isCode(w) {
			t.Errorf("%q refused: %d", detail, w.Code)
		}
	}
	e.passkeyOnly(false)
	if w := run("federated:corp"); !isCode(w) {
		t.Errorf("option off: %d", w.Code)
	}
}

func TestPasskeyOnlyRemovesTOTPFallback(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, true, true)
	// A fallback taken before the option was switched on...
	w := f.passwordLogin(pkPW)
	tok := f.fbTokenOf(w)
	totpPage := f.postStep(w, url.Values{"fb_token": {tok}})
	if !isTOTPPage(totpPage) {
		t.Fatalf("setup: %d", totpPage.Code)
	}
	f.passkeyOnly(true)
	// ...cannot be finished.
	mfaTok := tokenRe.FindStringSubmatch(totpPage.Body.String())[1]
	done := f.postStep(totpPage, url.Values{"mfa_token": {mfaTok}, "code": {f.code()}})
	if isCode(done) || done.Code != http.StatusForbidden || f.cookies[ssoCookie] != nil {
		t.Fatalf("one-time code completed a passkey-only login: %d", done.Code)
	}
	// And none is offered any more.
	f.forget()
	w = f.passwordLogin(pkPW)
	if !isPasskeyPage(w) || f.fbTokenOf(w) != "" {
		t.Fatalf("fallback still offered: %d", w.Code)
	}
	// An old fallback button no longer helps either: it only leads to a refusal.
	old := f.postStep(w, url.Values{"fb_token": {tok}})
	if isTOTPPage(old) {
		mfaTok = tokenRe.FindStringSubmatch(old.Body.String())[1]
		f.now = f.now.Add(time.Minute)
		if isCode(f.postStep(old, url.Values{"mfa_token": {mfaTok}, "code": {f.code()}})) {
			t.Fatal("old fallback token completed the login")
		}
	}
}

func TestPasskeyOnlyAccountPage(t *testing.T) {
	e, a := staleAccount(t, nil)
	e.passkeyOnly(true)
	body := e.do("GET", e.accountPath(), nil).Body.String()
	if strings.Contains(body, `name="password"`) || !strings.Contains(body, "Confirm with your passkey") || !strings.Contains(body, "Confirm with a passkey") {
		t.Fatalf("page: %s", body[strings.Index(body, "<main"):])
	}
	csrf := csrfRe.FindStringSubmatch(body)[1]
	w := e.do("POST", e.accountPath(), url.Values{"csrf": {csrf}, "pk_action": {"reauth"}, "password": {pkPW}})
	if w.Code != http.StatusForbidden || e.cookies[pkReauthCook] != nil {
		t.Fatalf("password re-authentication accepted: %d", w.Code)
	}
	if w := e.do("POST", e.accountPath(), reauthForm(e.reauthPage(), a, pkOrigin)); w.Code != http.StatusSeeOther {
		t.Fatalf("passkey re-authentication: %d", w.Code)
	}
}

func TestPasskeyFirstFactorLoginMarksCredential(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	marks := func() []string {
		m, err := e.st.PasswordlessPasskeys(context.Background(), "r", "u1")
		must(t, err)
		return m
	}
	e.forget()
	// A failed passwordless attempt marks nothing.
	pg := parsePKPage(t, e.loginPage())
	f := assertionForm(pg, "login", a, pkOrigin)
	sig, _ := base64.RawURLEncoding.DecodeString(f.Get("pk_sig"))
	sig[len(sig)-1] ^= 1
	f.Set("pk_sig", bu(sig))
	if isCode(e.do("POST", authPOST(), f)) || len(marks()) != 0 {
		t.Fatal("bad signature accepted or marked")
	}
	e.forget()
	if !isCode(e.passkeyLogin(a)) || len(marks()) != 1 || marks()[0] != bu(a.CredID) {
		t.Fatalf("marks: %v", marks())
	}
}
