// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

const (
	acr1   = core.ACRSingleFactor
	acrMFA = core.ACRMultiFactor
	acrPHR = core.ACRPhishingResistant
)

// ---- helpers ----

func acrURL(over map[string]string) string { return base + "auth?" + authQuery(over).Encode() }

// tokenCall posts to the token / introspection endpoints of a provider.
func tokenCall(t *testing.T, h http.Handler, path string, f url.Values, user, pass string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.9:1"
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func exchange(t *testing.T, h http.Handler, code string) (int, map[string]any) {
	t.Helper()
	return tokenCall(t, h, base+"token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {cb}, "client_id": {"app"}, "code_verifier": {verifier}}, "", "")
}

func refresh(t *testing.T, h http.Handler, rt string) (int, map[string]any) {
	t.Helper()
	return tokenCall(t, h, base+"token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"app"}}, "", "")
}

func codeIn(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("want a redirect with a code, got %d: %s", w.Code, w.Body)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	c := u.Query().Get("code")
	if c == "" {
		t.Fatalf("no code in %s", u)
	}
	return c
}

// wantErr requires an error redirect to the client and no code.
func wantACRErr(t *testing.T, w *httptest.ResponseRecorder, code string) {
	t.Helper()
	u, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || u.Query().Get("error") != code || u.Query().Get("code") != "" {
		t.Fatalf("want error=%s, got %d %q %s", code, w.Code, w.Header().Get("Location"), w.Body)
	}
}

// wantContext checks acr, amr and auth_time of a JWT ("" acr = no claim).
func wantContext(t *testing.T, what, tok, acr, amr string) map[string]any {
	t.Helper()
	c := claimsOf(t, tok)
	gotACR, _ := c["acr"].(string)
	gotAMR := ""
	if l, ok := c["amr"].([]any); ok {
		gotAMR = strings.Trim(fmt.Sprint(l), "[]")
	}
	if gotACR != acr || gotAMR != amr {
		t.Fatalf("%s: acr=%q amr=%q, want %q %q", what, gotACR, gotAMR, acr, amr)
	}
	if _, ok := c["auth_time"].(float64); !ok {
		t.Fatalf("%s: no auth_time: %v", what, c)
	}
	return c
}

// tokens exchanges the code of w and checks both JWTs.
func tokens(t *testing.T, h http.Handler, w *httptest.ResponseRecorder, acr, amr string) map[string]any {
	t.Helper()
	st, out := exchange(t, h, codeIn(t, w))
	if st != 200 {
		t.Fatalf("exchange: %d %v", st, out)
	}
	wantContext(t, "access token", out["access_token"].(string), acr, amr)
	wantContext(t, "id token", out["id_token"].(string), acr, amr)
	return out
}

func (e *mfaEnv) putACR(mut func(*core.ACRPolicy)) {
	e.t.Helper()
	p := core.DefaultACRPolicy()
	mut(&p)
	if err := e.st.PutACRPolicy(context.Background(), "r", p); err != nil {
		e.t.Fatal(err)
	}
}

// login signs in with the password for an /auth query and returns the response
// to the password post.
func (b *mfaBrowser) loginACR(user string, over map[string]string) *httptest.ResponseRecorder {
	b.t().Helper()
	return b.loginQ(user, authQuery(over))
}

// stepAt posts a step page back to the URL of the same /auth query.
func (b *mfaBrowser) stepFor(over map[string]string, prev *httptest.ResponseRecorder, extra url.Values) *httptest.ResponseRecorder {
	b.t().Helper()
	tk := tokenRe.FindStringSubmatch(prev.Body.String())
	if tk == nil {
		b.t().Fatalf("not a step page (%d): %s %s", prev.Code, prev.Header().Get("Location"), prev.Body)
	}
	f := url.Values{"csrf": {b.csrf}, "mfa_token": {tk[1]}}
	for k, v := range extra {
		f[k] = v
	}
	return b.post(acrURL(over), f)
}

func acrIntrospect(t *testing.T, h http.Handler, st core.Store, tok string) map[string]any {
	t.Helper()
	if _, err := st.GetClientByClientID(context.Background(), "r", "rs"); err != nil {
		if err := st.CreateClient(context.Background(), core.Client{Realm: "r", ClientID: "rs", Enabled: true, SecretHash: HashSecret("rs-secret")}); err != nil {
			t.Fatal(err)
		}
	}
	code, out := tokenCall(t, h, base+"token/introspect", url.Values{"token": {tok}}, "rs", "rs-secret")
	if code != 200 {
		t.Fatalf("introspect: %d %v", code, out)
	}
	return out
}

// ---- claims ----

func TestAuthnClaimsFollowWhatHappened(t *testing.T) {
	e := newMFA(t, true)
	// Password only: ID token, access token, userinfo, introspection, refresh.
	b := e.mfaBrowser()
	started := e.now.Unix()
	out := tokens(t, e.h, b.loginACR("alice", nil), acr1, "pwd")
	at := out["access_token"].(string)
	req := httptest.NewRequest("GET", base+"userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	var ui map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &ui)
	if ui["acr"] != acr1 || int64(ui["auth_time"].(float64)) != started {
		t.Fatalf("userinfo: %s", w.Body)
	}
	in := acrIntrospect(t, e.h, e.st, at)
	if in["acr"] != acr1 || int64(in["auth_time"].(float64)) != started || fmt.Sprint(in["amr"]) != "[pwd]" {
		t.Fatalf("introspection: %v", in)
	}
	rin := acrIntrospect(t, e.h, e.st, out["refresh_token"].(string))
	if rin["active"] != true || rin["acr"] != acr1 || int64(rin["auth_time"].(float64)) != started {
		t.Fatalf("refresh introspection: %v", rin)
	}
	// Renewal never changes when or how the user authenticated, twice over.
	e.advance(3 * time.Minute)
	rt := out["refresh_token"].(string)
	for range 2 {
		st, o := refresh(t, e.h, rt)
		if st != 200 {
			t.Fatalf("refresh: %d %v", st, o)
		}
		for _, k := range []string{"access_token", "id_token"} {
			c := wantContext(t, "refreshed "+k, o[k].(string), acr1, "pwd")
			if int64(c["auth_time"].(float64)) != started {
				t.Fatalf("auth_time moved on refresh: %v", c["auth_time"])
			}
		}
		rt = o["refresh_token"].(string)
	}

	// TOTP.
	e.enrollDirect(e.bob)
	b = e.mfaBrowser()
	pg := b.loginACR("bob", nil)
	tokens(t, e.h, b.stepFor(nil, pg, url.Values{"code": {e.code("id-bob", 0)}}), acrMFA, "pwd otp mfa")
}

func TestAuthnRecoveryCodeIsNotReportedAsOTP(t *testing.T) {
	e := newMFA(t, true)
	codes := e.enrollDirect(e.alice)
	b := e.mfaBrowser()
	pg := b.loginACR("alice", nil)
	tokens(t, e.h, b.stepFor(nil, pg, url.Values{"code": {codes[0]}}), acrMFA, "pwd recovery mfa")
}

func TestAuthnSSOReuseKeepsTheOriginalContext(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	b := e.mfaBrowser()
	started := e.now.Unix()
	pg := b.loginACR("alice", nil)
	codeIn(t, b.stepFor(nil, pg, url.Values{"code": {e.code("id-alice", 0)}}))
	e.advance(10 * time.Minute)
	for _, q := range []map[string]string{nil, {"prompt": "none"}, {"prompt": "none", "acr_values": acrMFA},
		{"acr_values": acr1}} {
		w := b.get(acrURL(q))
		want := acrMFA
		if q["acr_values"] != "" {
			want = q["acr_values"] // the requested level is what is reported
		}
		out := tokens(t, e.h, w, want, "pwd otp mfa")
		if c := claimsOf(t, out["id_token"].(string)); int64(c["auth_time"].(float64)) != started {
			t.Fatalf("%v: auth_time %v, want %d", q, c["auth_time"], started)
		}
	}
}

// ---- step-up ----

func TestStepUpNeverIssuesAWeakerLevel(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()
	codeIn(t, b.loginACR("alice", nil)) // password-only SSO session
	mfa := map[string]string{"acr_values": acrMFA}

	// The weak session is not reused, silently or otherwise.
	wantACRErr(t, b.get(acrURL(map[string]string{"acr_values": acrMFA, "prompt": "none"})), "login_required")
	if w := b.get(acrURL(mfa)); w.Code != 200 || !strings.Contains(w.Body.String(), `name="username"`) {
		t.Fatalf("expected a login page: %d %s", w.Code, w.Header().Get("Location"))
	}
	// A user with no second factor cannot get there: no code, and by default
	// no enrollment either (a stolen password must not mint an MFA token).
	w := b.loginACR("alice", mfa)
	wantACRErr(t, w, errUnmetACR)
	if _, err := e.st.GetTOTP(context.Background(), "r", "id-alice"); err == nil {
		t.Fatal("an enrollment was started without the realm allowing it")
	}
	if len(e.events("LOGIN_ERROR")) == 0 {
		t.Fatal("the refusal is not audited")
	}

	// With a factor the same request steps up.
	e.enrollDirect(e.alice)
	b = e.mfaBrowser()
	pg := b.loginACR("alice", mfa)
	if !isTOTPPage(pg) {
		t.Fatalf("expected the code page: %d %s", pg.Code, pg.Body)
	}
	tokens(t, e.h, b.stepFor(mfa, pg, url.Values{"code": {e.code("id-alice", 0)}}), acrMFA, "pwd otp mfa")

	// phr needs a passkey, which this user does not have: refused right after
	// the password, without wasting a one-time code.
	b = e.mfaBrowser()
	wantACRErr(t, b.loginACR("alice", map[string]string{"acr_values": acrPHR}), errUnmetACR)
	if b.hasSSO() {
		t.Fatal("a session was created for a refused request")
	}
	// Preference list: the best level the user can reach.
	b = e.mfaBrowser()
	e.advance(time.Minute)
	both := map[string]string{"acr_values": acrPHR + " " + acrMFA}
	pg = b.loginACR("alice", both)
	tokens(t, e.h, b.stepFor(both, pg, url.Values{"code": {e.code("id-alice", 0)}}), acrMFA, "pwd otp mfa")
}

func TestStepUpEnrollmentWhenTheRealmAllowsIt(t *testing.T) {
	e := newMFA(t, true)
	e.putACR(func(p *core.ACRPolicy) { p.EnrollOnStepUp = true })
	mfa := map[string]string{"acr_values": acrMFA}
	b := e.mfaBrowser()
	pg := b.loginACR("alice", mfa)
	if !isEnrollPage(pg) {
		t.Fatalf("expected enrollment: %d %s %s", pg.Code, pg.Header().Get("Location"), pg.Body)
	}
	done := b.stepFor(mfa, pg, url.Values{"code": {e.code("id-alice", 0)}})
	if done.Code != 200 || b.hasSSO() {
		t.Fatalf("recovery code page: %d", done.Code)
	}
	tokens(t, e.h, b.stepFor(mfa, done, nil), acrMFA, "pwd otp mfa")
	// Enrollment cannot reach phr: refused, not enrolled.
	b = e.mfaBrowser()
	wantACRErr(t, b.loginACR("bob", map[string]string{"acr_values": acrPHR}), errUnmetACR)
}

// A realm that requires two-step verification enrolls users anyway; a request
// that demands it must not turn that into a refusal.
func TestStepUpWithRequiredMFAEnrolls(t *testing.T) {
	e := newMFA(t, true)
	e.setPolicy(true)
	mfa := map[string]string{"acr_values": acrMFA}
	b := e.mfaBrowser()
	pg := b.loginACR("alice", mfa)
	if !isEnrollPage(pg) {
		t.Fatalf("expected enrollment: %d %s", pg.Code, pg.Header().Get("Location"))
	}
	done := b.stepFor(mfa, pg, url.Values{"code": {e.code("id-alice", 0)}})
	tokens(t, e.h, b.stepFor(mfa, done, nil), acrMFA, "pwd otp mfa")
}

func TestStepUpUnknownLevelFailsBeforeAnyLogin(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()
	for _, q := range []map[string]string{
		{"acr_values": "gold"},
		{"acr_values": "gold", "prompt": "none"},
		{"claims": `{"id_token":{"acr":{"essential":true,"values":["gold"]}}}`},
		{"claims": `{"id_token":{"acr":{"essential":true,"values":["gold"]}}}`, "acr_values": acr1},
	} {
		wantACRErr(t, b.get(acrURL(q)), errUnmetACR)
	}
	// ...also when posting straight to the login form.
	w := b.get(authURL())
	csrf := csrfRe.FindStringSubmatch(w.Body.String())[1]
	wantACRErr(t, b.post(acrURL(map[string]string{"acr_values": "gold"}),
		url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {"pw"}}), errUnmetACR)
	if b.hasSSO() {
		t.Fatal("session created")
	}
}

func TestStepUpClaimsParameter(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()
	codeIn(t, b.loginACR("alice", nil))
	essential := `{"id_token":{"acr":{"essential":true,"values":["` + acrMFA + `"]}}}`
	for _, c := range []string{essential,
		`{"id_token":{"acr":{"value":"` + acrMFA + `"}}}`, // voluntary with a value: still binding
		`{"userinfo":{"acr":{"essential":true,"values":["` + acrMFA + `"]}}}`,
		`{"id_token":{"acr":{"essential":true,"values":["` + acr1 + `"]}},"access_token":{"acr":{"value":"` + acrPHR + `"}}}`,
	} {
		wantACRErr(t, b.get(acrURL(map[string]string{"claims": c, "prompt": "none"})), "login_required")
		wantACRErr(t, e.mfaBrowser().loginACR("alice", map[string]string{"claims": c}), errUnmetACR)
	}
	// Demands that the session meets, or that demand nothing.
	for _, c := range []string{
		`{"id_token":{"acr":{"essential":true}}}`,
		`{"id_token":{"acr":{"essential":true,"values":["` + acrMFA + `","` + acr1 + `"]}}}`,
		`{"id_token":{"acr":null,"email":{"essential":true}}}`,
		`{"id_token":{"acr":{"essential":false}},"userinfo":null}`,
	} {
		tokens(t, e.h, b.get(acrURL(map[string]string{"claims": c, "prompt": "none"})), acr1, "pwd")
	}
	for name, c := range map[string]string{
		"not json": `{`, "not an object": `[1]`, "target not an object": `{"id_token":1}`,
		"acr not an object": `{"id_token":{"acr":"x"}}`, "duplicate member": `{"id_token":{"acr":{"essential":true,"values":["` + acrMFA + `"]}},"id_token":{}}`,
		"empty values": `{"id_token":{"acr":{"values":[]}}}`, "both": `{"id_token":{"acr":{"value":"a","values":["a"]}}}`,
		"number value": `{"id_token":{"acr":{"value":2}}}`, "essential string": `{"id_token":{"acr":{"essential":"yes"}}}`,
		"quote": `{"id_token":{"acr":{"value":"a\"b"}}}`, "too long": `{"x":"` + strings.Repeat("a", maxClaimsLen) + `"}`,
	} {
		w := b.get(acrURL(map[string]string{"claims": c}))
		u, _ := url.Parse(w.Header().Get("Location"))
		if u.Query().Get("error") != "invalid_request" {
			t.Errorf("%s: %d %s", name, w.Code, w.Header().Get("Location"))
		}
	}
	// A repeated parameter would let one of the two be ignored.
	for _, k := range []string{"acr_values", "claims"} {
		v := acr1
		if k == "claims" {
			v = "{}"
		}
		q := authQuery(map[string]string{k: v})
		q.Add(k, essential)
		wantACRErr(t, b.get(base+"auth?"+q.Encode()), "invalid_request")
	}
	for _, v := range []string{strings.Repeat("a ", maxACRValues+1), strings.Repeat("a", maxACRBytes+1), `a"b`} {
		wantACRErr(t, b.get(acrURL(map[string]string{"acr_values": v})), "invalid_request")
	}
}

// A passkey user: the passkey is challenged, the fallback to TOTP cannot be
// used to obtain a level that needs the passkey (the issueCode gate).
func TestStepUpFallbackCannotSatisfyAPasskeyLevel(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, true, true)
	over := map[string]string{"acr_values": acrPHR}
	u := acrURL(over)
	w := f.do("GET", u, nil)
	csrf := csrfRe.FindStringSubmatch(w.Body.String())[1]
	pg := f.do("POST", u, url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {pkPW}})
	if !isPasskeyPage(pg) {
		t.Fatalf("expected the passkey step: %d %s", pg.Code, pg.Body)
	}
	tp := f.do("POST", u, url.Values{"csrf": {f.cookies[csrfCookie].Value}, "fb_token": {f.fbTokenOf(pg)}})
	if !isTOTPPage(tp) {
		t.Fatalf("expected the code page: %d %s", tp.Code, tp.Body)
	}
	tk := tokenRe.FindStringSubmatch(tp.Body.String())[1]
	end := f.do("POST", u, url.Values{"csrf": {f.cookies[csrfCookie].Value}, "mfa_token": {tk}, "code": {f.code()}})
	wantACRErr(t, end, errUnmetACR)
}

// passkeySecondFactor drives password + passkey step for an /auth query.
func (f *fbEnv) passkeySecondFactor(over map[string]string, uv bool) *httptest.ResponseRecorder {
	f.t.Helper()
	f.forget()
	f.auth.UV = uv
	u := acrURL(over)
	w := f.do("GET", u, nil)
	csrf := csrfRe.FindStringSubmatch(w.Body.String())[1]
	w = f.do("POST", u, url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {pkPW}})
	if !isPasskeyPage(w) {
		return w
	}
	pg := parsePKPage(f.t, w)
	return f.do("POST", u, assertionForm(pg, "2fa", f.auth, pkOrigin))
}

func TestAuthnPasskeyWithAndWithoutUserVerification(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{}, nil, true, false)
	tokens(t, f.h, f.passkeySecondFactor(nil, false), acrPHR, "pwd webauthn user mfa")
	tokens(t, f.h, f.passkeySecondFactor(nil, true), acrPHR, "pwd webauthn user uv mfa")
	// Passwordless (user verification is mandatory there).
	f.forget()
	f.auth.UV = true
	over := map[string]string{"acr_values": acrPHR}
	pg := parsePKPage(t, f.do("GET", acrURL(over), nil))
	tokens(t, f.h, f.do("POST", acrURL(over), assertionForm(pg, "login", f.auth, pkOrigin)), acrPHR, "webauthn user uv mfa")

	// A realm that wants user verification gets it checked on what happened.
	must(t, f.st.PutACRPolicy(context.Background(), "r", core.ACRPolicy{Levels: []core.ACRLevel{
		{Value: "base", AnyOf: [][]string{{core.AMRPassword}}},
		{Value: "verified", AnyOf: [][]string{{core.AMRWebAuthn, core.AMRUV}}},
	}}))
	want := map[string]string{"acr_values": "verified"}
	wantACRErr(t, f.passkeySecondFactor(want, false), errUnmetACR)
	tokens(t, f.h, f.passkeySecondFactor(want, true), "verified", "pwd webauthn user uv mfa")
}

// A request parameter must never choose a weaker factor than the passkey, nor
// add a factor to an account that has one.
func TestStepUpNeverSubstitutesOrEnrollsForAPasskeyUser(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{}, nil, true, false)
	must(t, f.st.PutACRPolicy(context.Background(), "r", core.ACRPolicy{EnrollOnStepUp: true, Levels: []core.ACRLevel{
		{Value: "base", AnyOf: [][]string{{core.AMRPassword}}},
		{Value: "code", AnyOf: [][]string{{core.AMROTP}}},
	}}))
	wantACRErr(t, f.passkeySecondFactor(map[string]string{"acr_values": "code"}, true), errUnmetACR)
	if _, err := f.st.GetTOTP(context.Background(), "r", "u1"); err == nil {
		t.Fatal("a second authenticator was enrolled for a passkey user")
	}
}

// ---- refresh and policy changes ----

func TestRefreshRechecksTheCurrentPolicy(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	login := func(over map[string]string) map[string]any {
		t.Helper()
		e.advance(time.Minute)
		b := e.mfaBrowser()
		pg := b.loginACR("alice", over)
		st, out := exchange(t, e.h, codeIn(t, b.stepFor(over, pg, url.Values{"code": {e.code("id-alice", 0)}})))
		if st != 200 {
			t.Fatalf("exchange: %d %v", st, out)
		}
		return out
	}
	asked := login(map[string]string{"acr_values": acrMFA})["refresh_token"].(string)
	notAsked := login(nil)["refresh_token"].(string)

	// The ladder now says an authenticator code is not multi factor.
	e.putACR(func(p *core.ACRPolicy) {
		p.Levels[1].AnyOf = [][]string{{core.AMRWebAuthn, core.AMRMFA}}
	})
	for name, rt := range map[string]string{"demanded": asked, "derived": notAsked} {
		st, out := refresh(t, e.h, rt)
		if st != 400 || out["error"] != "invalid_grant" || out["access_token"] != nil {
			t.Fatalf("%s: refresh kept a level the policy no longer grants: %d %v", name, st, out)
		}
		if in := acrIntrospect(t, e.h, e.st, rt); in["active"] != false {
			t.Fatalf("%s: introspection says active: %v", name, in)
		}
	}
	// The refused request spent nothing; the previous policy works again.
	if err := e.st.DeleteACRPolicy(context.Background(), "r"); err != nil {
		t.Fatal(err)
	}
	st, out := refresh(t, e.h, asked)
	if st != 200 {
		t.Fatalf("after restoring the policy: %d %v", st, out)
	}
	wantContext(t, "restored", out["access_token"].(string), acrMFA, "pwd otp mfa")

	// A ladder that would now rate the same methods higher does not raise it.
	e.putACR(func(p *core.ACRPolicy) { p.Levels[2].AnyOf = [][]string{{core.AMRMFA}} })
	st, out = refresh(t, e.h, notAsked)
	if st != 200 {
		t.Fatalf("looser policy: %d %v", st, out)
	}
	wantContext(t, "not raised", out["access_token"].(string), acrMFA, "pwd otp mfa")

	// A removed level cannot be claimed any more.
	e.putACR(func(p *core.ACRPolicy) { p.Levels = p.Levels[:1] })
	if st, out := refresh(t, e.h, out["refresh_token"].(string)); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("removed level: %d %v", st, out)
	}
}

func TestCodeExchangeRechecksPolicyAndContextCannotBeForged(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()
	code := codeIn(t, b.loginACR("alice", map[string]string{"acr_values": acr1}))
	// Raise the claimed level inside the code: it is just an unknown code.
	parts := strings.Split(code, resSep)
	if len(parts) != 3 || parts[1] != "" {
		t.Fatalf("code format: %q", code)
	}
	forged := parts[0] + resSep + resSep + base64.RawURLEncoding.EncodeToString([]byte(
		`{"a":"`+acrPHR+`","m":["pwd","webauthn","mfa"],"t":1}`))
	if st, out := exchange(t, e.h, forged); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("forged code: %d %v", st, out)
	}
	e.putACR(func(p *core.ACRPolicy) { p.Levels[0].AnyOf = [][]string{{core.AMRMFA}} })
	if st, out := exchange(t, e.h, code); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("code after policy change: %d %v", st, out)
	}
	if err := e.st.DeleteACRPolicy(context.Background(), "r"); err != nil {
		t.Fatal(err)
	}
	st, out := exchange(t, e.h, codeIn(t, b.get(authURL())))
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	rt := out["refresh_token"].(string)
	p := strings.Split(rt, resSep)
	for _, bad := range []string{p[0], p[0] + resSep + resSep + base64.RawURLEncoding.EncodeToString([]byte(`{"a":"`+acrPHR+`"}`))} {
		if st, out := refresh(t, e.h, bad); st != 400 || out["error"] != "invalid_grant" {
			t.Fatalf("altered refresh token: %d %v", st, out)
		}
	}
}

// ---- fail closed ----

// noAuthnStore hides core.AuthnStore (no Unwrap, so StoreAs cannot see it).
type noAuthnStore struct{ core.Store }

type brokenAuthn struct {
	core.Store
	inner                        core.AuthnStore
	failPut, failPolicy, failGet bool
}

var errBroken = errors.New("broken")

func (s *brokenAuthn) Unwrap() core.Store { return s.Store }
func (s *brokenAuthn) GetACRPolicy(ctx context.Context, r string) (core.ACRPolicy, error) {
	if s.failPolicy {
		return core.ACRPolicy{}, errBroken
	}
	return s.inner.GetACRPolicy(ctx, r)
}
func (s *brokenAuthn) PutACRPolicy(ctx context.Context, r string, p core.ACRPolicy) error {
	return s.inner.PutACRPolicy(ctx, r, p)
}
func (s *brokenAuthn) DeleteACRPolicy(ctx context.Context, r string) error {
	return s.inner.DeleteACRPolicy(ctx, r)
}
func (s *brokenAuthn) PutSessionAuthn(ctx context.Context, a core.SessionAuthn) error {
	if s.failPut {
		return errBroken
	}
	return s.inner.PutSessionAuthn(ctx, a)
}
func (s *brokenAuthn) GetSessionAuthn(ctx context.Context, r, id string) (core.SessionAuthn, error) {
	if s.failGet {
		return core.SessionAuthn{}, errBroken
	}
	return s.inner.GetSessionAuthn(ctx, r, id)
}

func TestAuthnStoreAbsentMeansNoClaimsAndNoDemands(t *testing.T) {
	e := newMFA(t, false, func(c *Config) { c.Store = noAuthnStore{c.Store} })
	b := e.mfaBrowser()
	st, out := exchange(t, e.h, codeIn(t, b.loginACR("alice", nil)))
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	c := claimsOf(t, out["access_token"].(string))
	if c["acr"] != nil || c["amr"] != nil {
		t.Fatalf("claims without a store: %v", c)
	}
	wantACRErr(t, b.get(acrURL(map[string]string{"acr_values": acr1})), errUnmetACR)
	w := b.get("/realms/r/.well-known/openid-configuration")
	if strings.Contains(w.Body.String(), "acr_values_supported") {
		t.Fatal("discovery advertises acr without a store")
	}
}

func TestAuthnStoreErrorsFailClosed(t *testing.T) {
	var br *brokenAuthn
	e := newMFA(t, false, func(c *Config) {
		inner, _ := core.StoreAs[core.AuthnStore](c.Store)
		br = &brokenAuthn{Store: c.Store, inner: inner}
		c.Store = br
	})
	br.failPut = true
	b := e.mfaBrowser()
	w := b.loginACR("alice", nil)
	if w.Code != 500 || b.hasSSO() {
		t.Fatalf("record failure: %d sso=%v", w.Code, b.hasSSO())
	}
	if l, _ := e.st.ListSessions(context.Background(), "r", "id-alice", 10); len(l) != 0 {
		t.Fatal("a session without its record survived")
	}
	br.failPut = false
	codeIn(t, b.loginACR("alice", nil))
	st, out := exchange(t, e.h, codeIn(t, b.get(authURL())))
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	br.failPolicy = true
	wantACRErr(t, b.get(acrURL(map[string]string{"acr_values": acr1, "prompt": "none"})), "server_error")
	wantACRErr(t, b.get(authURL()), "server_error")
	if st, o := refresh(t, e.h, out["refresh_token"].(string)); st != 500 || o["access_token"] != nil {
		t.Fatalf("refresh with unreadable policy: %d %v", st, o)
	}
	br.failPolicy, br.failGet = false, true
	wantACRErr(t, b.get(authURL()), "server_error")
}

// A session from before the upgrade has no record: it is reused without claims
// when nothing is demanded, and never satisfies a demand.
func TestAuthnSessionWithoutRecord(t *testing.T) {
	var br *brokenAuthn
	e := newMFA(t, false, func(c *Config) {
		inner, _ := core.StoreAs[core.AuthnStore](c.Store)
		br = &brokenAuthn{Store: c.Store, inner: forgetful{inner}}
		c.Store = br
	})
	b := e.mfaBrowser()
	codeIn(t, b.loginACR("alice", nil))
	st, out := exchange(t, e.h, codeIn(t, b.get(authURL())))
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	c := claimsOf(t, out["id_token"].(string))
	if c["acr"] != nil || c["amr"] != nil || c["auth_time"] == nil {
		t.Fatalf("claims: %v", c)
	}
	wantACRErr(t, b.get(acrURL(map[string]string{"acr_values": acr1, "prompt": "none"})), "login_required")
}

// forgetful accepts session records and loses them.
type forgetful struct{ core.AuthnStore }

func (forgetful) PutSessionAuthn(context.Context, core.SessionAuthn) error { return nil }

func TestAuthnDiscovery(t *testing.T) {
	e := newMFA(t, true)
	get := func() map[string]any {
		w := e.mfaBrowser().get("/realms/r/.well-known/openid-configuration")
		var d map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &d)
		return d
	}
	d := get()
	if fmt.Sprint(d["acr_values_supported"]) != fmt.Sprint([]string{acr1, acrMFA, acrPHR}) || d["claims_parameter_supported"] != true {
		t.Fatalf("%v %v", d["acr_values_supported"], d["claims_parameter_supported"])
	}
	for _, want := range []string{"acr", "amr", "auth_time"} {
		if !strings.Contains(fmt.Sprint(d["claims_supported"]), want) {
			t.Errorf("claims_supported lacks %s", want)
		}
	}
	e.putACR(func(p *core.ACRPolicy) { p.Levels = []core.ACRLevel{{Value: "only", AnyOf: [][]string{{"pwd"}}}} })
	if got := fmt.Sprint(get()["acr_values_supported"]); got != "[only]" {
		t.Errorf("custom ladder: %s", got)
	}
}

func TestTokenSuffix(t *testing.T) {
	g := grantAuthn{ACR: "a", AMR: []string{"pwd"}, AuthTime: 7, Req: [][]string{{"a"}}, Limited: true}
	for _, res := range [][]string{nil, {"https://a.example/x"}, {"https://a.example/x", "https://b.example/y"}} {
		for _, in := range []grantAuthn{{}, g} {
			tok := "rand" + encodeSuffix(res, in)
			r, ok := decodeResources(tok)
			a, ok2 := decodeAuthn(tok)
			if !ok || !ok2 || fmt.Sprint(r) != fmt.Sprint(res) || fmt.Sprint(a) != fmt.Sprint(in) || strings.Contains(tok, ".") {
				t.Errorf("%q: %v %v %v %v", tok, r, ok, a, ok2)
			}
		}
	}
	for _, bad := range []string{"r~~", "r~~!!", "r~~e30~x", "r~~" + base64.RawURLEncoding.EncodeToString([]byte("nope")),
		"r~~" + strings.Repeat("A", 2*maxAuthnBytes)} {
		if _, ok := decodeAuthn(bad); ok {
			t.Errorf("%.20q accepted", bad)
		}
	}
	if _, ok := decodeResources("r~"); ok {
		t.Error("an empty resource suffix without context is malformed")
	}
}

// ---- device flow ----

func TestAuthnDeviceFlow(t *testing.T) {
	e := newDEnv(t, devOpts{})
	for _, f := range []url.Values{{"acr_values": {acrMFA}}, {"claims": {"{}"}}} {
		f.Set("client_id", "cli")
		st, out, _ := e.post(devPath, f, "", "", "")
		if st != 400 || out["error"] != "invalid_request" {
			t.Fatalf("a demand the flow cannot enforce must be refused: %d %v", st, out)
		}
	}
	g := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(g, "alice", "pw")
	if w := b.decide(g.UserCode, "approve"); w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	e.advance(10 * time.Second)
	st, out := e.poll("cli", g.DeviceCode)
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	wantContext(t, "device access token", out["access_token"].(string), acr1, "pwd")
	st, out = tokenCall(t, e.h, base+"token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"cli"},
		"refresh_token": {out["refresh_token"].(string)}}, "", "")
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	wantContext(t, "device refresh", out["access_token"].(string), acr1, "pwd")
}
