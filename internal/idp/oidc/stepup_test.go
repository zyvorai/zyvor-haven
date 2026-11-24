// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/totp"
)

// ---- helpers (mfaEnv: memstore + secretbox + controllable clock) ----

func (e *mfaEnv) putPolicy(p core.StepUpPolicy) {
	e.t.Helper()
	if err := e.st.PutStepUpPolicy(context.Background(), "r", p); err != nil {
		e.t.Fatal(err)
	}
}

func (e *mfaEnv) advance(d time.Duration) { e.now = e.now.Add(d) }

// loginQ does GET + POST of the password form for an arbitrary /auth query.
func (b *mfaBrowser) loginQ(user string, q url.Values) *httptest.ResponseRecorder {
	b.t().Helper()
	u := base + "auth?" + q.Encode()
	w := b.get(u)
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || m == nil {
		b.t().Fatalf("login page: %d %s", w.Code, w.Body)
	}
	return b.post(u, url.Values{"username": {user}, "password": {"pw"}, "csrf": {m[1]}})
}

// relogin signs in again in a browser that may hold an SSO session
// (prompt=login skips silent reuse).
func (b *mfaBrowser) relogin(user string) *httptest.ResponseRecorder {
	b.t().Helper()
	return b.loginQ(user, authQuery(map[string]string{"prompt": "login"}))
}

func (b *mfaBrowser) cookie(name string) *http.Cookie {
	for _, c := range b.cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func isEnrollPage(w *httptest.ResponseRecorder) bool { return secretRe.MatchString(w.Body.String()) }

// reportOnly / enforce are the two modes of the same rule set.
func rules(p core.StepUpPolicy, enforce bool) core.StepUpPolicy {
	p.Enabled, p.Enforce = true, enforce
	return p
}

// learn logs a factorless user in once under report-only so the device is known.
func (e *mfaEnv) learn(b *mfaBrowser, user string, p core.StepUpPolicy) {
	e.t.Helper()
	e.putPolicy(rules(p, false))
	if w := b.password(user, "pw"); !isRedirectWithCode(w) {
		e.t.Fatalf("report-only login must not interrupt: %d %s", w.Code, w.Body)
	}
}

// ---- tests ----

func TestStepUpOffByDefault(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()
	if w := b.password("bob", "pw"); !isRedirectWithCode(w) {
		t.Fatalf("login: %d", w.Code)
	}
	if b.cookie(deviceCookie) != nil {
		t.Error("a device cookie was set although no policy is enabled (nothing may be collected)")
	}
	ds, _ := e.st.ListDevices(context.Background(), "r", "id-bob")
	if len(ds) != 0 || len(e.events("STEPUP_REQUIRED"))+len(e.events("STEPUP_REPORT")) != 0 {
		t.Errorf("state recorded with the policy off: %v", ds)
	}
	// Rules set but not Enabled: still nothing.
	e.putPolicy(core.StepUpPolicy{OnNewDevice: true, Enforce: true})
	if w := e.mfaBrowser().password("bob", "pw"); !isRedirectWithCode(w) {
		t.Fatalf("a disabled policy interrupted the login: %d", w.Code)
	}
}

func TestStepUpNewDeviceForcesEnrollmentAndLearnsDevice(t *testing.T) {
	e := newMFA(t, true)
	p := core.StepUpPolicy{OnNewDevice: true}

	// Enforced, user without any factor, first ever login: must enroll now.
	e.putPolicy(rules(p, true))
	b1 := e.mfaBrowser()
	w := b1.password("bob", "pw")
	if !isEnrollPage(w) || isRedirectWithCode(w) || b1.hasSSO() {
		t.Fatalf("expected the enrollment page and no code/session: %d %s", w.Code, w.Body)
	}
	if evs := e.events("STEPUP_REQUIRED"); len(evs) != 1 || evs[0].Detail != "login:new_device" {
		t.Fatalf("audit: %+v", evs)
	}

	// Report-only: the login goes through, the decision is audited, the device is learned.
	b2 := e.mfaBrowser()
	e.learn(b2, "bob", p)
	if len(e.events("STEPUP_REPORT")) != 1 {
		t.Errorf("report-only decision not audited")
	}
	ck := b2.cookie(deviceCookie)
	if ck == nil || !ck.HttpOnly || ck.Path != "/realms/r" || ck.SameSite != http.SameSiteLaxMode || len(ck.Value) != 43 {
		t.Fatalf("device cookie: %+v", ck)
	}
	ds, _ := e.st.ListDevices(context.Background(), "r", "id-bob")
	if len(ds) != 1 || ds[0].Hash == ck.Value || ds[0].Hash != deviceHash(ck.Value) {
		t.Fatalf("store must hold only the hash of the cookie: %+v", ds)
	}
	if strings.Contains(ds[0].IPHash, "192.0.2") || ds[0].IPHash == "" {
		t.Errorf("ip hash: %q", ds[0].IPHash)
	}

	// Enforced again: the same browser is a known device, nothing is asked.
	e.putPolicy(rules(p, true))
	if w := b2.relogin("bob"); !isRedirectWithCode(w) {
		t.Fatalf("known device was challenged: %d %s", w.Code, w.Body)
	}
	// Another browser (no cookie) is new.
	if w := e.mfaBrowser().password("bob", "pw"); !isEnrollPage(w) {
		t.Fatalf("fresh browser not treated as new: %d", w.Code)
	}
	// A malformed cookie is ignored, not trusted.
	b3 := e.mfaBrowser()
	b3.cookies["x"] = &http.Cookie{Name: deviceCookie, Value: "garbage", Path: "/realms/r"}
	if w := b3.password("bob", "pw"); !isEnrollPage(w) {
		t.Fatalf("malformed cookie accepted: %d", w.Code)
	}
}

// A device cookie is per user: alice's known browser says nothing about bob.
func TestStepUpDeviceIsPerUser(t *testing.T) {
	e := newMFA(t, true)
	p := core.StepUpPolicy{OnNewDevice: true}
	b := e.mfaBrowser()
	e.learn(b, "alice", p)
	e.putPolicy(rules(p, true))
	if w := b.relogin("alice"); !isRedirectWithCode(w) {
		t.Fatalf("alice's own device challenged: %d", w.Code)
	}
	// Same browser, same cookie, other user.
	if w := b.relogin("bob"); !isEnrollPage(w) {
		t.Fatalf("alice's device cookie vouched for bob: %d", w.Code)
	}
}

func TestStepUpIPChange(t *testing.T) {
	e := newMFA(t, true)
	p := core.StepUpPolicy{OnIPChange: true}
	b := e.mfaBrowser()
	e.learn(b, "bob", p)
	e.putPolicy(rules(p, true))

	b.ip = "192.0.2.77:1" // same /24
	if w := b.relogin("bob"); !isRedirectWithCode(w) {
		t.Fatalf("same network prefix treated as a change: %d", w.Code)
	}
	b.ip = "198.51.100.9:1" // different /24
	w := b.relogin("bob")
	if !isEnrollPage(w) {
		t.Fatalf("network change not detected: %d", w.Code)
	}
	if evs := e.events("STEPUP_REQUIRED"); len(evs) != 1 || evs[0].Detail != "login:ip_changed" {
		t.Fatalf("audit: %+v", evs)
	}
}

func TestStepUpIdle(t *testing.T) {
	e := newMFA(t, true)
	p := core.StepUpPolicy{IdleAfter: time.Hour}
	b := e.mfaBrowser()
	e.learn(b, "bob", p)
	e.putPolicy(rules(p, true))
	e.advance(59 * time.Minute)
	if w := b.relogin("bob"); !isRedirectWithCode(w) {
		t.Fatalf("below the idle threshold: %d", w.Code)
	}
	e.advance(61 * time.Minute) // measured from the login just made
	if w := b.relogin("bob"); !isEnrollPage(w) {
		t.Fatalf("idle threshold not enforced: %d", w.Code)
	}
}

func TestStepUpMaxAgeAndSensitiveScopeAtLogin(t *testing.T) {
	e := newMFA(t, true)
	e.putPolicy(rules(core.StepUpPolicy{OnMaxAge: true}, true))
	if w := e.mfaBrowser().loginQ("bob", authQuery(nil)); !isRedirectWithCode(w) {
		t.Fatalf("no max_age requested: %d", w.Code)
	}
	if w := e.mfaBrowser().loginQ("bob", authQuery(map[string]string{"max_age": "60"})); !isEnrollPage(w) {
		t.Fatalf("max_age did not force a factor: %d", w.Code)
	}
	e.putPolicy(rules(core.StepUpPolicy{SensitiveScopes: []string{"offline_access"}}, true))
	if w := e.mfaBrowser().loginQ("bob", authQuery(map[string]string{"scope": "openid email"})); !isRedirectWithCode(w) {
		t.Fatalf("non-sensitive scope: %d", w.Code)
	}
	if w := e.mfaBrowser().loginQ("bob", authQuery(nil)); !isEnrollPage(w) { // default query asks for offline_access
		t.Fatalf("sensitive scope did not force a factor: %d", w.Code)
	}
}

// Step-up never makes a login WEAKER: an enrolled user is still challenged by
// their factor, and the code page is what they get.
func TestStepUpEnrolledUserStillGetsTheirFactor(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	e.putPolicy(rules(core.StepUpPolicy{OnNewDevice: true}, true))
	b, w := e.codePage("alice")
	if isRedirectWithCode(w) || isEnrollPage(w) {
		t.Fatalf("unexpected page: %d", w.Code)
	}
	if got := b.step(w, url.Values{"code": {e.code("id-alice", 0)}}); !isRedirectWithCode(got) {
		t.Fatalf("code rejected: %d %s", got.Code, got.Body)
	}
	if b.cookie(deviceCookie) == nil {
		t.Error("device not remembered after a completed login")
	}
}

// Without the secret key a required factor cannot be enrolled: refuse, never
// fall back to the password alone.
func TestStepUpFailsClosedWithoutKey(t *testing.T) {
	e := newMFA(t, false)
	e.putPolicy(rules(core.StepUpPolicy{OnNewDevice: true}, true))
	b := e.mfaBrowser()
	w := b.password("bob", "pw")
	if isRedirectWithCode(w) || b.hasSSO() || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("login let through without a possible second factor: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(e.logs.String(), "HAVEN_IDP_SECRET_KEY") {
		t.Error("operator not told why")
	}
	// Report-only must not refuse anyone.
	e.putPolicy(rules(core.StepUpPolicy{OnNewDevice: true}, false))
	if w := e.mfaBrowser().password("bob", "pw"); !isRedirectWithCode(w) {
		t.Fatalf("report-only refused a login: %d", w.Code)
	}
}

// ---- silent SSO ----

// ssoLogin signs alice in with her TOTP and returns the browser.
func (e *mfaEnv) ssoLogin() *mfaBrowser {
	e.t.Helper()
	b, w := e.codePage("alice")
	if got := b.step(w, url.Values{"code": {e.code("id-alice", 0)}}); !isRedirectWithCode(got) {
		e.t.Fatalf("login: %d %s", got.Code, got.Body)
	}
	return b
}

func (b *mfaBrowser) authGET(q url.Values) *httptest.ResponseRecorder {
	return b.get(base + "auth?" + q.Encode())
}

func TestStepUpBlocksSilentSSO(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	e.putPolicy(core.StepUpPolicy{}) // device learning needs Enabled; set per case below

	// Baseline: no policy, SSO is reused.
	b := e.ssoLogin()
	if w := b.authGET(authQuery(nil)); !isRedirectWithCode(w) {
		t.Fatalf("baseline SSO reuse broken: %d", w.Code)
	}

	cases := []struct {
		name   string
		p      core.StepUpPolicy
		mutate func(e *mfaEnv, b *mfaBrowser)
		q      map[string]string
		reason string
	}{
		{"sensitive scope, auth too old", core.StepUpPolicy{SensitiveScopes: []string{"offline_access"}, SensitiveAuthMaxAge: 5 * time.Minute},
			func(e *mfaEnv, b *mfaBrowser) { e.advance(6 * time.Minute) }, nil, "sensitive_scope"},
		{"sensitive scope, always", core.StepUpPolicy{SensitiveScopes: []string{"offline_access"}},
			func(e *mfaEnv, b *mfaBrowser) {}, nil, "sensitive_scope"},
		{"stolen session cookie without the device cookie", core.StepUpPolicy{OnNewDevice: true},
			func(e *mfaEnv, b *mfaBrowser) { delete(b.cookies, deviceCookie+"|/realms/r") }, nil, "new_device"},
		{"session used from another network", core.StepUpPolicy{OnIPChange: true},
			func(e *mfaEnv, b *mfaBrowser) { b.ip = "203.0.113.5:1" }, nil, "ip_changed"},
		{"idle", core.StepUpPolicy{IdleAfter: 10 * time.Minute},
			func(e *mfaEnv, b *mfaBrowser) { e.advance(11 * time.Minute) }, nil, "idle"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newMFA(t, true)
			e.enrollDirect(e.alice)
			e.putPolicy(rules(c.p, false))
			b := e.ssoLogin() // learns the device while report-only
			e.putPolicy(rules(c.p, true))
			c.mutate(e, b)

			w := b.authGET(authQuery(c.q))
			if isRedirectWithCode(w) || w.Code != 200 || !strings.Contains(w.Body.String(), "Sign in") {
				t.Fatalf("SSO was reused although the policy fires: %d %s", w.Code, w.Header().Get("Location"))
			}
			// prompt=none answers login_required, never a code.
			wn := b.authGET(authQuery(map[string]string{"prompt": "none"}))
			if wn.Code != http.StatusFound || !strings.Contains(wn.Header().Get("Location"), "login_required") {
				t.Fatalf("prompt=none: %d %s", wn.Code, wn.Header().Get("Location"))
			}
			evs := e.events("STEPUP_REQUIRED")
			if len(evs) == 0 || evs[0].Detail != "sso:"+c.reason {
				t.Fatalf("audit: %+v", evs)
			}
			// Report-only: the same request is served and only audited.
			e.putPolicy(rules(c.p, false))
			if w := b.authGET(authQuery(c.q)); !isRedirectWithCode(w) {
				t.Fatalf("report-only blocked SSO: %d", w.Code)
			}
			if len(e.events("STEPUP_REPORT")) == 0 {
				t.Error("report-only did not audit")
			}
		})
	}

	// Quiet signals: policy on, nothing fired, SSO still reused.
	e2 := newMFA(t, true)
	e2.enrollDirect(e2.alice)
	pol := core.StepUpPolicy{OnNewDevice: true, OnIPChange: true, IdleAfter: time.Hour,
		SensitiveScopes: []string{"offline_access"}, SensitiveAuthMaxAge: 5 * time.Minute}
	e2.putPolicy(rules(pol, false))
	b2 := e2.ssoLogin()
	e2.putPolicy(rules(pol, true))
	e2.advance(time.Minute)
	if w := b2.authGET(authQuery(nil)); !isRedirectWithCode(w) {
		t.Fatalf("SSO blocked although no signal fired: %d %s", w.Code, w.Body)
	}
}

// failingPolicyStore makes the policy unreadable.
type failingPolicyStore struct{ *memstore.Store }

func (failingPolicyStore) GetStepUpPolicy(context.Context, string) (core.StepUpPolicy, error) {
	return core.StepUpPolicy{}, errors.New("db down")
}

func TestStepUpFailsClosedWhenPolicyUnreadable(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	b := e.ssoLogin()
	e.h.cfg.Store = failingPolicyStore{e.st}
	if w := b.authGET(authQuery(nil)); isRedirectWithCode(w) {
		t.Fatalf("SSO reused although the step-up policy could not be read")
	}
	if w := e.mfaBrowser().password("bob", "pw"); isRedirectWithCode(w) || w.Code != http.StatusInternalServerError {
		t.Fatalf("login let through with an unreadable policy: %d", w.Code)
	}
}

// With the store feature absent the whole thing is off, quietly.
type noStepUpStore struct{ core.Store }

func TestStepUpAbsentStoreMeansOff(t *testing.T) {
	e := newMFA(t, true)
	e.h.cfg.Store = noStepUpStore{e.st} // hides StepUpStore (no Unwrap)
	if _, on := e.h.stepUpStore(); on {
		t.Fatal("feature reported on")
	}
	b := e.mfaBrowser()
	if w := b.password("bob", "pw"); !isRedirectWithCode(w) {
		t.Fatalf("login: %d", w.Code)
	}
	if b.cookie(deviceCookie) != nil {
		t.Error("device cookie without a store")
	}
}

// Federated and other completeLogin callers also remember the device; the
// remembered record must never contain the raw cookie or IP.
func TestStepUpStoredFieldsAreHashes(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()
	e.learn(b, "bob", core.StepUpPolicy{OnNewDevice: true})
	ds, _ := e.st.ListDevices(context.Background(), "r", "id-bob")
	raw := ds[0].Hash + ds[0].IPHash
	if strings.Contains(raw, b.cookie(deviceCookie).Value) || strings.Contains(raw, "192.0.2") {
		t.Fatal("raw cookie or IP in the device record")
	}
	_ = totp.RecoveryCount
}

func TestIPPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1": "192.0.2.0/24", "192.0.2.254": "192.0.2.0/24", "::ffff:192.0.2.9": "192.0.2.0/24",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1::/48", "2001:db8:1:ffff::1": "2001:db8:1::/48",
		"": "", "not-an-ip": "", "192.0.2": "",
	} {
		if got := ipPrefix(in); got != want {
			t.Errorf("ipPrefix(%q) = %q, want %q", in, got, want)
		}
	}
	if ipHash("r", "u", "") != "" || ipHash("r", "u", "192.0.2.1") == ipHash("r", "v", "192.0.2.1") {
		t.Error("ipHash must be empty for unknown and salted per user")
	}
}
