// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// How the authentication level and the consent choice interact with session
// controls, passkeys, client authentication, the groups claim and the account
// console.

func (e *pkEnv) silentTokens(t *testing.T, over map[string]string) (map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	w := e.do("GET", acrURL(over), nil)
	if !isCode(w) {
		return nil, w
	}
	st, out := exchange(t, e.h, codeIn(t, w))
	if st != 200 {
		t.Fatalf("exchange: %d %v", st, out)
	}
	return out, w
}

// verifiedAccess reads the claims of an access token signed with a real key.
func authTimeOf(t *testing.T, tok string) int64 {
	t.Helper()
	v, ok := claimsOf(t, tok)["auth_time"].(float64)
	if !ok {
		t.Fatalf("no auth_time in %v", claimsOf(t, tok))
	}
	return int64(v)
}

// ---- passkey re-authentication and autofill ----

// Confirming with a passkey on an account page unlocks that page. It does not
// turn a password session into a passkey one, nor make it newer.
func TestInteractionPasskeyReauthDoesNotRaiseTheSession(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7) // password session, then a passkey is added to it
	before, _ := e.silentTokens(t, nil)
	wantContext(t, "before", before["access_token"].(string), acr1, "pwd")
	started := authTimeOf(t, before["access_token"].(string))

	e.now = e.now.Add(11 * time.Minute)
	w := e.do("POST", e.accountPath(), reauthForm(e.reauthPage(), a, pkOrigin))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("reauth: %d %s", w.Code, w.Body)
	}
	after, _ := e.silentTokens(t, nil)
	wantContext(t, "after", after["access_token"].(string), acr1, "pwd")
	if authTimeOf(t, after["access_token"].(string)) != started {
		t.Fatal("a re-authentication moved auth_time")
	}
	_, w = e.silentTokens(t, map[string]string{"acr_values": acrPHR, "prompt": "none"})
	wantACRErr(t, w, "login_required")
	_, w = e.silentTokens(t, map[string]string{"max_age": "60", "prompt": "none"})
	wantACRErr(t, w, "login_required")
}

// The autofill (conditional mediation) request uses the login page's options:
// user verification is demanded and checked, so "uv" in amr is what happened.
func TestInteractionPasskeyAutofillReportsUserVerification(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	e.forget()
	over := map[string]string{"acr_values": acrPHR}
	page := e.do("GET", acrURL(over), nil)
	if !strings.Contains(page.Body.String(), `data-conditional="1"`) {
		t.Fatal("no conditional request on the login page")
	}
	pg := parsePKPage(t, page)
	if pg.opts["userVerification"] != "required" {
		t.Fatalf("options: %v", pg.opts)
	}
	a.UV = false
	w := e.do("POST", acrURL(over), assertionForm(pg, "login", a, pkOrigin))
	if isCode(w) || e.cookies[ssoCookie] != nil {
		t.Fatalf("an assertion without user verification signed in: %d", w.Code)
	}
	a.UV = true
	pg = parsePKPage(t, e.do("GET", acrURL(over), nil))
	w = e.do("POST", acrURL(over), assertionForm(pg, "login", a, pkOrigin))
	st, out := exchange(t, e.h, codeIn(t, w))
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	wantContext(t, "autofill", out["access_token"].(string), acrPHR, "webauthn user uv mfa")
}

// ---- session limit and "keep me signed in" ----

func (e *mfaEnv) sessionIDsOf(user string) []string {
	e.t.Helper()
	l, err := e.st.ListSessions(context.Background(), "r", user, 100)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, s := range l {
		out = append(out, s.ID)
	}
	slices.Sort(out)
	return out
}

func (e *mfaEnv) sessionPolicy(p core.SessionPolicy) {
	e.t.Helper()
	if err := e.st.PutSessionPolicy(context.Background(), "r", p); err != nil {
		e.t.Fatal(err)
	}
}

// stepUpTOTP signs in with password and code for the demand in over.
func (b *mfaBrowser) stepUpTOTP(over map[string]string, extra url.Values) *httptest.ResponseRecorder {
	b.t().Helper()
	u := acrURL(over)
	w := b.get(u)
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || m == nil {
		b.t().Fatalf("login page: %d %s", w.Code, w.Header().Get("Location"))
	}
	f := url.Values{"csrf": {m[1]}, "username": {"alice"}, "password": {"pw"}}
	for k, v := range extra {
		f[k] = v
	}
	pg := b.post(u, f)
	return b.stepFor(over, pg, url.Values{"code": {b.e.code("id-alice", 0)}})
}

func TestInteractionStepUpUnderSessionLimit(t *testing.T) {
	mfa := map[string]string{"acr_values": acrMFA}
	t.Run("deny_new does not block the same browser", func(t *testing.T) {
		e := newMFA(t, true)
		e.sessionPolicy(core.SessionPolicy{MaxSessions: 1, OnLimit: core.SessionLimitDenyNew})
		b := e.mfaBrowser()
		codeIn(t, b.loginACR("alice", nil))
		old := e.sessionIDsOf("id-alice")
		e.enrollDirect(e.alice)
		e.advance(time.Minute)
		tokens(t, e.h, b.stepUpTOTP(mfa, nil), acrMFA, "pwd otp mfa")
		if now := e.sessionIDsOf("id-alice"); len(now) != 1 || now[0] == old[0] {
			t.Fatalf("sessions %v, was %v", now, old)
		}
	})
	t.Run("revoke_oldest evicts only the replaced session", func(t *testing.T) {
		e := newMFA(t, true)
		e.sessionPolicy(core.SessionPolicy{MaxSessions: 2})
		other := e.mfaBrowser()
		codeIn(t, other.loginACR("alice", nil)) // the oldest session
		e.advance(time.Minute)
		b := e.mfaBrowser()
		codeIn(t, b.loginACR("alice", nil))
		e.enrollDirect(e.alice)
		e.advance(time.Minute)
		tokens(t, e.h, b.stepUpTOTP(mfa, nil), acrMFA, "pwd otp mfa")
		if n := len(e.sessionIDsOf("id-alice")); n != 2 {
			t.Fatalf("%d sessions", n)
		}
		if w := other.get(acrURL(map[string]string{"prompt": "none"})); !isRedirectWithCode(w) {
			t.Fatalf("the step-up ended another device's session: %s", w.Header().Get("Location"))
		}
		// The other device's session did not become multi factor.
		wantACRErr(t, other.get(acrURL(map[string]string{"acr_values": acrMFA, "prompt": "none"})), "login_required")
	})
	t.Run("keep me signed in survives the second factor", func(t *testing.T) {
		e := newMFA(t, true)
		e.sessionPolicy(core.SessionPolicy{RememberMe: true})
		b := e.mfaBrowser()
		codeIn(t, b.loginACR("alice", nil))
		e.enrollDirect(e.alice)
		e.advance(time.Minute)
		tokens(t, e.h, b.stepUpTOTP(mfa, url.Values{rememberField: {"on"}}), acrMFA, "pwd otp mfa")
		l, _ := e.st.ListSessions(context.Background(), "r", "id-alice", 10)
		if len(l) != 1 || l[0].ExpiresAt.Sub(l[0].CreatedAt) <= maxSessionLife {
			t.Fatalf("not remembered: %+v", l)
		}
		// Days later the long session still reports the original sign-in.
		at := l[0].AuthTime.Unix()
		e.advance(48 * time.Hour)
		out := tokens(t, e.h, b.get(acrURL(map[string]string{"acr_values": acrMFA, "prompt": "none"})), acrMFA, "pwd otp mfa")
		if authTimeOf(t, out["access_token"].(string)) != at {
			t.Fatal("auth_time moved")
		}
		wantACRErr(t, b.get(acrURL(map[string]string{"max_age": "3600", "prompt": "none"})), "login_required")
	})
}

// A step-up that ends without the demanded level must not cost the user the
// session they had, nor anyone else's.
func TestInteractionRefusedStepUpLeavesSessionsAlone(t *testing.T) {
	for name, onLimit := range map[string]string{"revoke_oldest": "", "deny_new": core.SessionLimitDenyNew} {
		f := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, true, true)
		f.auth.UV = true
		pg := parsePKPage(t, f.do("GET", authPOST(), nil))
		if w := f.do("POST", authPOST(), assertionForm(pg, "login", f.auth, pkOrigin)); !isCode(w) {
			t.Fatalf("first sign-in: %d", w.Code)
		}
		list := func() string {
			l, err := f.st.ListSessions(context.Background(), "r", "u1", 100)
			must(t, err)
			var ids []string
			for _, s := range l {
				ids = append(ids, s.ID)
			}
			slices.Sort(ids)
			return strings.Join(ids, " ")
		}
		must(t, f.st.PutSessionPolicy(context.Background(), "r",
			core.SessionPolicy{MaxSessions: len(strings.Fields(list())), OnLimit: onLimit}))
		before := list()
		over := map[string]string{"acr_values": acrPHR, "prompt": "login"}
		u := acrURL(over)
		csrf := csrfRe.FindStringSubmatch(f.do("GET", u, nil).Body.String())[1]
		step := f.do("POST", u, url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {pkPW}})
		code := f.do("POST", u, url.Values{"csrf": {f.cookies[csrfCookie].Value}, "fb_token": {f.fbTokenOf(step)}})
		tk := tokenRe.FindStringSubmatch(code.Body.String())
		if tk == nil {
			t.Fatalf("%s: no code page: %d %s", name, code.Code, code.Body)
		}
		end := f.do("POST", u, url.Values{"csrf": {f.cookies[csrfCookie].Value}, "mfa_token": {tk[1]}, "code": {f.code()}})
		wantACRErr(t, end, errUnmetACR)
		if got := list(); got != before {
			t.Fatalf("%s: sessions changed by a refused step-up: %q was %q", name, got, before)
		}
		if w := f.do("GET", acrURL(map[string]string{"acr_values": acrPHR, "prompt": "none"}), nil); !isCode(w) {
			t.Fatalf("%s: the browser lost its stronger session: %s", name, w.Header().Get("Location"))
		}
	}
}

// ---- passkey-only ----

func TestInteractionPasskeyOnlyAndTheLadder(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, true, true)
	f.passkeyOnly(true)
	ladder := core.DefaultACRPolicy()
	ladder.EnrollOnStepUp = true
	must(t, f.st.PutACRPolicy(context.Background(), "r", ladder))
	f.auth.UV = true
	for _, want := range []string{acrMFA, acrPHR, acr1} {
		f.forget()
		over := map[string]string{"acr_values": want}
		pg := parsePKPage(t, f.do("GET", acrURL(over), nil))
		w := f.do("POST", acrURL(over), assertionForm(pg, "login", f.auth, pkOrigin))
		st, out := exchange(t, f.h, codeIn(t, w))
		if st != 200 {
			t.Fatalf("%d %v", st, out)
		}
		wantContext(t, want, out["access_token"].(string), want, "webauthn user uv mfa")
	}
	// Every passkey has now proved it works alone: no demand re-opens the
	// password, offers a code or enrolls anything.
	for _, want := range []string{acrMFA, acrPHR, acr1} {
		f.forget()
		u := acrURL(map[string]string{"acr_values": want})
		csrf := csrfRe.FindStringSubmatch(f.do("GET", u, nil).Body.String())[1]
		w := f.do("POST", u, url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {pkPW}})
		if isCode(w) || tokenRe.MatchString(w.Body.String()) || f.cookies[ssoCookie] != nil ||
			!strings.Contains(w.Body.String(), badCreds) {
			t.Fatalf("%s: %d %s %s", want, w.Code, w.Header().Get("Location"), w.Body)
		}
	}
}

// With an unusable relying party passkeys cannot be challenged. The account
// still has one: a demand must not enroll a second authenticator with only the
// password.
func TestInteractionBrokenPasskeyConfigNeverEnrolls(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{}, nil, true, false)
	ladder := core.DefaultACRPolicy()
	ladder.EnrollOnStepUp = true
	must(t, f.st.PutACRPolicy(context.Background(), "r", ladder))
	f.h.cfg.WebAuthn = WebAuthnConfig{Origins: []string{"not-an-origin"}}
	if _, _, ok := f.h.passkeys(); ok {
		t.Fatal("test setup: passkeys still usable")
	}
	u := acrURL(map[string]string{"acr_values": acrMFA})
	csrf := csrfRe.FindStringSubmatch(f.do("GET", u, nil).Body.String())[1]
	wantACRErr(t, f.do("POST", u, url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {pkPW}}), errUnmetACR)
	if _, err := f.st.GetTOTP(context.Background(), "r", "u1"); err == nil {
		t.Fatal("an authenticator was enrolled")
	}
}

// ---- strong client authentication ----

// svcCode signs alice in for the confidential client "svc".
func svcCode(t *testing.T, e *denv, over map[string]string) url.Values {
	t.Helper()
	q := authQuery(map[string]string{"client_id": "svc", "scope": "openid offline_access"})
	for k, v := range over {
		q.Set(k, v)
	}
	b := e.browser()
	w := b.do("GET", base+"auth?"+q.Encode(), nil)
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("login page: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = b.do("POST", base+"auth?"+q.Encode(), url.Values{"csrf": {m[1]}, "username": {"alice"}, "password": {"pw"}})
	return url.Values{"grant_type": {"authorization_code"}, "code": {codeIn(t, w)}, "redirect_uri": {cb}, "code_verifier": {verifier}}
}

func TestInteractionPrivateKeyJWTAndAuthenticationContext(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	form := svcCode(t, c.denv, map[string]string{"acr_values": acr1})
	assert := func(f url.Values) url.Values { return withAssertion(f, c.assertion(t, "svc", c.key, aOpt{})) }
	// A secret is no longer a way in, and the failed attempt costs nothing.
	if code, out, _ := c.send(tokenR, form, basicAuth("svc", "s3cret")); code != 401 {
		t.Fatalf("secret: %d %v", code, out)
	}
	code, out, _ := c.send(tokenR, assert(form))
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	wantContext(t, "private_key_jwt", out["access_token"].(string), acr1, "pwd")
	for name, tok := range map[string]any{"access": out["access_token"], "refresh": out["refresh_token"]} {
		code, in, _ := c.send(introR, assert(url.Values{"token": {tok.(string)}}))
		if code != 200 || in["active"] != true || in["acr"] != acr1 || in["auth_time"] == nil {
			t.Fatalf("%s introspection: %d %v", name, code, in)
		}
	}
	rf := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {out["refresh_token"].(string)}}
	strict := core.DefaultACRPolicy()
	strict.Levels[0].AnyOf = [][]string{{core.AMRMFA}}
	must(t, c.st.PutACRPolicy(context.Background(), "r", strict))
	if code, o, _ := c.send(tokenR, assert(rf)); code != 400 || o["error"] != "invalid_grant" {
		t.Fatalf("policy change: %d %v", code, o)
	}
	must(t, c.st.DeleteACRPolicy(context.Background(), "r"))
	code, o, _ := c.send(tokenR, assert(rf))
	if code != 200 {
		t.Fatalf("%d %v", code, o)
	}
	wantContext(t, "refreshed", o["access_token"].(string), acr1, "pwd")
}

func TestInteractionCertificateBoundTokensCarryTheContext(t *testing.T) {
	e := newTLSEnv(t)
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodTLS, TLSSubjectDN: "CN=client1,O=Acme", CertBoundTokens: true})
	form := svcCode(t, e.denv, nil)
	form.Set("client_id", "svc")
	code, out, _ := e.send(tokenR, form, direct(e.leaf))
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	at := out["access_token"].(string)
	wantContext(t, "bound", at, acr1, "pwd")
	if thumb(t, at) != certThumbprint(e.leaf.cert) {
		t.Fatal("not bound")
	}
	if c := e.userinfoCall("Bearer", at); c != 401 {
		t.Fatalf("userinfo without the certificate: %d", c)
	}
	req := httptest.NewRequest("GET", base+"userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	direct(e.leaf)(req)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	var ui map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &ui)
	if w.Code != 200 || ui["acr"] != acr1 || ui["auth_time"] == nil {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body)
	}
	code, in, _ := e.send(introR, url.Values{"token": {at}, "client_id": {"svc"}}, direct(e.leaf))
	cnf, _ := in["cnf"].(map[string]any)
	if code != 200 || in["token_type"] != "Bearer" || in["acr"] != acr1 || fmt.Sprint(in["amr"]) != "[pwd]" ||
		cnf["x5t#S256"] != certThumbprint(e.leaf.cert) {
		t.Fatalf("introspect: %d %v", code, in)
	}
	_ = x509.ExtKeyUsageClientAuth
}

// ---- groups and per-scope consent ----

func TestInteractionUntickingGroupsRemovesTheClaim(t *testing.T) {
	e := newConsentEnv(t, true, devOpts{})
	pol, err := ParseGroupsClaimClients("r/app")
	must(t, err)
	e.h.cfg.GroupsClaim = pol
	setGroups(t, e.denv, []string{"/ops"})
	e.policy(core.ConsentPolicy{RequireAll: true})
	b := e.browser()
	q := authQuery(map[string]string{"scope": "openid groups offline_access"})
	page := b.authorize(q)
	if got := tickedScopes(page.Body.String()); !slices.Equal(got, []string{"groups", "offline_access"}) ||
		!strings.Contains(page.Body.String(), "read which groups you belong to") {
		t.Fatalf("consent page: %v %s", got, page.Body)
	}
	out := appToken(t, e.h, consentCodeOf(t, consentFlow(t, b, q, "offline_access")))
	if g, ok := claimsOf(t, out["id_token"].(string))["groups"]; ok || strings.Contains(out["scope"].(string), "groups") {
		t.Fatalf("declined groups still shared: %v %v", g, out["scope"])
	}
	st, o := refresh(t, e.h, out["refresh_token"].(string))
	if st != 200 {
		t.Fatalf("%d %v", st, o)
	}
	if g, ok := claimsOf(t, o["id_token"].(string))["groups"]; ok {
		t.Fatalf("declined groups after refresh: %v", g)
	}
	st, o = tokenCall(t, e.h, base+"token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"},
		"refresh_token": {o["refresh_token"].(string)}, "scope": {"openid groups"}}, "", "")
	if st != 400 || o["error"] != "invalid_scope" {
		t.Fatalf("groups added on refresh: %d %v", st, o)
	}
	// The line about groups is translated like every other one.
	for lang, want := range map[string]string{"de": "zu welchen Gruppen", "hi": "किन समूहों"} {
		l := authQuery(map[string]string{"scope": "openid groups", "prompt": "consent", "ui_locales": lang})
		if body := b.authorize(l).Body.String(); !strings.Contains(body, want) || strings.Contains(body, "read which groups") {
			t.Fatalf("%s: %s", lang, body)
		}
	}
	// Ticked: shared, and withdrawing it later ends the tokens that carry it.
	all := appToken(t, e.h, consentCodeOf(t, consentFlow(t, b, q, "groups", "offline_access")))
	if fmt.Sprint(claimsOf(t, all["id_token"].(string))["groups"]) != "[ops]" {
		t.Fatalf("granted groups: %v", claimsOf(t, all["id_token"].(string)))
	}
	again := authQuery(map[string]string{"scope": "openid groups offline_access", "prompt": "consent"})
	consentCodeOf(t, consentFlow(t, b, again, "offline_access"))
	if st, o := refresh(t, e.h, all["refresh_token"].(string)); st != 400 {
		t.Fatalf("a token with withdrawn groups still refreshes: %d %v", st, o)
	}
}

// A consent decision cannot be used to get past a demand added to the URL: the
// final gate of issueCode is the only check on that path.
func TestInteractionConsentDecisionCannotBypassTheLevel(t *testing.T) {
	e := newConsentEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{RequireAll: true})
	b := e.browser()
	q := authQuery(nil)
	page := b.authorize(q)
	body := page.Body.String()
	demand := authQuery(map[string]string{"acr_values": acrMFA})
	w := b.do("POST", base+"auth?"+demand.Encode(), url.Values{"csrf": {csrfRe.FindStringSubmatch(body)[1]},
		"consent_proof": {digestRe.FindStringSubmatch(body)[1]}, "consent_decision": {"allow"}, "consent_scope": {"email"}})
	wantACRErr(t, w, errUnmetACR)
}

// ---- account console ----

func TestInteractionAccountConsoleKeepsTheRecordedContext(t *testing.T) {
	e := newConEnv(t, conOpts{})
	b := e.visitor("ua", "192.0.2.50")
	sess := b.signIn("alice", "alice-pass")
	silent := func() map[string]any {
		t.Helper()
		w := b.do("GET", acrURL(map[string]string{"prompt": "none"}), nil)
		st, out := exchange(t, e.h, codeIn(t, w))
		if st != 200 {
			t.Fatalf("%d %v", st, out)
		}
		return out
	}
	before := silent()
	wantContext(t, "before", before["access_token"].(string), acr1, "pwd")
	e.now = e.now.Add(11 * time.Minute)
	e.wantStatus(b.post("password", "action", "reauth", "password", "alice-pass"), http.StatusSeeOther, "", "reauth")
	w := b.post("password", "action", "change", "current", "alice-pass", "password", "new-password-1", "confirm", "new-password-1")
	e.wantStatus(w, http.StatusSeeOther, "", "change")
	if got := b.session(); got.ID != sess.ID {
		t.Fatalf("the session changed: %s %s", got.ID, sess.ID)
	}
	after := silent()
	wantContext(t, "after", after["access_token"].(string), acr1, "pwd")
	if authTimeOf(t, after["access_token"].(string)) != sess.AuthTime.Unix() {
		t.Fatal("neither a confirmation nor a password change is a new sign-in")
	}
	if st, o := refresh(t, e.h, before["refresh_token"].(string)); st != 400 {
		t.Fatalf("an old refresh token survived the password change: %d %v", st, o)
	}
	wantACRErr(t, b.do("GET", acrURL(map[string]string{"max_age": "60", "prompt": "none"}), nil), "login_required")
}
