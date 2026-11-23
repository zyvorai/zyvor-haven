// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/obs"
)

// recorder is an obs.Recorder that remembers every call as a string.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.calls = append(r.calls, s)
	r.mu.Unlock()
}
func (r *recorder) Login(realm, res string)        { r.add("login:" + realm + ":" + res) }
func (r *recorder) Lockout(realm string)           { r.add("lockout:" + realm) }
func (r *recorder) RefreshReuse(realm string)      { r.add("reuse:" + realm) }
func (r *recorder) CodeReplay(realm string)        { r.add("replay:" + realm) }
func (r *recorder) AdminAuthFailure(kind string)   { r.add("adminauth:" + kind) }
func (r *recorder) TokenIssued(realm, g, k string) { r.add("issued:" + realm + ":" + g + ":" + k) }
func (r *recorder) TokenError(realm, g, c string)  { r.add("tokerr:" + realm + ":" + g + ":" + c) }
func (r *recorder) AdminOp(realm, res, act string, ok bool) {
	r.add("adminop:" + realm + ":" + res + ":" + act + ":" + map[bool]string{true: "ok", false: "err"}[ok])
}

var _ obs.Recorder = (*recorder)(nil)

// take returns the calls so far (sorted) and clears them.
func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.calls
	r.calls = nil
	sort.Strings(out)
	return out
}

func (r *recorder) expect(t *testing.T, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := r.take()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recorder calls\n got: %v\nwant: %v", got, want)
	}
}

func newObsEnv(t *testing.T, mut func(*core.Realm)) (*env, *recorder) {
	e := newEnv(t, mut)
	rec := &recorder{}
	e.h.cfg.Obs = rec
	return e, rec
}

func TestObsNilDefaultsToNop(t *testing.T) {
	e := newEnv(t, nil)
	if _, ok := e.h.cfg.Obs.(obs.Nop); !ok {
		t.Fatalf("Obs = %T, want obs.Nop", e.h.cfg.Obs)
	}
	// And the whole flow runs with it.
	if _, tok, _ := e.tokenReq(codeForm(e.getCode(authQuery(nil))), "", ""); tok["access_token"] == nil {
		t.Fatal("flow failed with Nop")
	}
}

func TestObsLoginSuccess(t *testing.T) {
	e, rec := newObsEnv(t, nil)
	if w := e.login(authQuery(nil), "alice", "pw"); w.Code != 302 {
		t.Fatalf("login %d", w.Code)
	}
	rec.expect(t, "login:r:success")
}

func TestObsBadCredentialsIndistinguishable(t *testing.T) {
	e, rec := newObsEnv(t, nil)
	q := authQuery(nil)
	e.login(q, "alice", "wrong")
	wrong := rec.take()
	e.login(q, "nobody", "wrong")
	unknown := rec.take()
	if !reflect.DeepEqual(wrong, unknown) {
		t.Fatalf("wrong password %v differs from unknown user %v", wrong, unknown)
	}
	if !reflect.DeepEqual(wrong, []string{"login:r:bad_credentials"}) {
		t.Fatalf("got %v", wrong)
	}
	// empty fields also report bad_credentials
	e.login(q, "alice", "")
	rec.expect(t, "login:r:bad_credentials")
}

func TestObsLockout(t *testing.T) {
	e, rec := newObsEnv(t, nil)
	q := authQuery(nil)
	for i := 0; i < lockThreshold-1; i++ {
		e.login(q, "alice", "wrong")
	}
	got := rec.take()
	if len(got) != lockThreshold-1 {
		t.Fatalf("before threshold: %v", got)
	}
	for _, c := range got {
		if c != "login:r:bad_credentials" {
			t.Fatalf("unexpected call %q", c)
		}
	}
	e.login(q, "alice", "wrong") // the locking attempt
	rec.expect(t, "login:r:bad_credentials", "lockout:r")
	e.login(q, "alice", "wrong") // locked
	rec.expect(t, "login:r:locked")
	e.login(q, "alice", "pw") // right password, still locked
	rec.expect(t, "login:r:locked")
	// after expiry a good login succeeds, no lockout
	e.now = e.now.Add(lockDuration + time.Minute)
	e.login(q, "alice", "pw")
	rec.expect(t, "login:r:success")
}

func TestObsLockoutDisabledWithoutBruteForce(t *testing.T) {
	e, rec := newObsEnv(t, func(r *core.Realm) { r.BruteForceProtection = false })
	for i := 0; i < lockThreshold+1; i++ {
		e.login(authQuery(nil), "alice", "wrong")
	}
	for _, c := range rec.take() {
		if c != "login:r:bad_credentials" {
			t.Fatalf("unexpected call %q", c)
		}
	}
}

func TestObsLoginDisabledUnverifiedCSRF(t *testing.T) {
	e, rec := newObsEnv(t, func(r *core.Realm) { r.EmailVerificationRequired = true })
	q := authQuery(nil)
	u := e.st.users["u1"]
	u.EmailVerified = false
	e.st.users["u1"] = u
	e.login(q, "alice", "pw")
	rec.expect(t, "login:r:unverified")

	u.EmailVerified, u.Enabled = true, false
	e.st.users["u1"] = u
	e.login(q, "alice", "pw")
	rec.expect(t, "login:r:disabled")
	// wrong password for a disabled user is still bad_credentials
	e.login(q, "alice", "wrong")
	rec.expect(t, "login:r:bad_credentials")

	csrf, ck := e.loginForm(q)
	rec.take()
	e.postLogin(q, "alice", "pw", csrf, nil) // no cookie
	rec.expect(t, "login:r:csrf")
	e.postLogin(q, "alice", "pw", "AAAA.BBBB", ck) // forged
	rec.expect(t, "login:r:csrf")
}

func TestObsTokenGrantsIssued(t *testing.T) {
	e, rec := newObsEnv(t, nil)
	code := e.getCode(authQuery(nil)) // openid profile email offline_access
	rec.take()
	_, tok, _ := e.tokenReq(codeForm(code), "", "")
	rec.expect(t, "issued:r:authorization_code:access", "issued:r:authorization_code:id", "issued:r:authorization_code:refresh")

	// refresh with rotation: new access, id (scope has openid) and refresh
	rf := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {"app"}}
	if s, _, _ := e.tokenReq(rf, "", ""); s != 200 {
		t.Fatalf("refresh %d", s)
	}
	rec.expect(t, "issued:r:refresh_token:access", "issued:r:refresh_token:id", "issued:r:refresh_token:refresh")

	// code without openid or offline_access, realm without refresh ttl: access only
	e.st.realms["r"] = func() core.Realm { r := e.st.realms["r"]; r.RefreshTokenTTL = 0; return r }()
	code = e.getCode(authQuery(map[string]string{"scope": "profile"}))
	rec.take()
	e.tokenReq(codeForm(code), "", "")
	rec.expect(t, "issued:r:authorization_code:access")

	// client credentials
	if s, _, _ := e.tokenReq(url.Values{"grant_type": {"client_credentials"}}, "svc", "s3cret"); s != 200 {
		t.Fatalf("cc %d", s)
	}
	rec.expect(t, "issued:r:client_credentials:access")
}

func TestObsRefreshWithoutRotationIssuesNoNewRefresh(t *testing.T) {
	e, rec := newObsEnv(t, func(r *core.Realm) { r.RefreshTokenRotation = false })
	_, tok, _ := e.tokenReq(codeForm(e.getCode(authQuery(nil))), "", "")
	rec.take()
	rf := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {"app"}}
	if s, _, _ := e.tokenReq(rf, "", ""); s != 200 {
		t.Fatalf("refresh %d", s)
	}
	rec.expect(t, "issued:r:refresh_token:access", "issued:r:refresh_token:id")
}

func TestObsTokenErrors(t *testing.T) {
	e, rec := newObsEnv(t, nil)
	// A valid refresh token whose scope lacks "email" for the invalid_scope case.
	code := e.getCode(authQuery(map[string]string{"scope": "openid offline_access"}))
	_, tok, _ := e.tokenReq(codeForm(code), "", "")
	refresh := tok["refresh_token"].(string)
	rec.take()

	cases := []struct {
		name    string
		form    url.Values
		user    string
		pass    string
		grant   string
		errCode string
	}{
		{"unsupported grant", url.Values{"grant_type": {"password"}}, "svc", "s3cret", "other", "unsupported_grant_type"},
		{"missing grant", url.Values{}, "svc", "s3cret", "other", "unsupported_grant_type"},
		{"bad client secret", url.Values{"grant_type": {"client_credentials"}}, "svc", "wrong", "client_credentials", "invalid_client"},
		{"unknown client, code grant", url.Values{"grant_type": {"authorization_code"}, "client_id": {"nope"}}, "", "", "authorization_code", "invalid_client"},
		{"public client cc", url.Values{"grant_type": {"client_credentials"}, "client_id": {"app"}}, "", "", "client_credentials", "unauthorized_client"},
		{"code missing", url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}}, "", "", "authorization_code", "invalid_request"},
		{"refresh missing", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"}}, "", "", "refresh_token", "invalid_request"},
		{"bad code", url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "code": {"bogus"}, "redirect_uri": {cb}}, "", "", "authorization_code", "invalid_grant"},
		{"bad refresh", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"}, "refresh_token": {"bogus"}}, "", "", "refresh_token", "invalid_grant"},
		{"scope too wide", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"}, "refresh_token": {refresh}, "scope": {"openid email"}}, "", "", "refresh_token", "invalid_scope"},
		{"multiple auth methods", url.Values{"grant_type": {"client_credentials"}, "client_secret": {"x"}}, "svc", "s3cret", "client_credentials", "invalid_request"},
	}
	for _, c := range cases {
		s, b, _ := e.tokenReq(c.form, c.user, c.pass)
		if s < 400 || b["error"] != c.errCode {
			t.Fatalf("%s: status %d body %v, want error %s", c.name, s, b, c.errCode)
		}
		rec.expect(t, "tokerr:r:"+c.grant+":"+c.errCode)
	}

	// Malformed body: ParseForm fails.
	req := httptest.NewRequest("POST", base+"token", strings.NewReader("grant_type=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if w := e.do(req); w.Code != 400 {
		t.Fatalf("malformed: %d", w.Code)
	}
	rec.expect(t, "tokerr:r:other:invalid_request")
}

func TestObsUnknownRealmRecordsNothing(t *testing.T) {
	e, rec := newObsEnv(t, nil)
	req := httptest.NewRequest("POST", "/realms/ghost/protocol/openid-connect/token",
		strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if w := e.do(req); w.Code != 404 {
		t.Fatalf("status %d", w.Code)
	}
	rec.expect(t)
}

func TestObsRefreshReuse(t *testing.T) {
	e, rec := newObsEnv(t, nil)
	_, tok, _ := e.tokenReq(codeForm(e.getCode(authQuery(nil))), "", "")
	r1 := tok["refresh_token"].(string)
	rf := func(r string) (int, map[string]any) {
		s, b, _ := e.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r}, "client_id": {"app"}}, "", "")
		return s, b
	}
	_, b := rf(r1)
	r2 := b["refresh_token"].(string)
	rec.take()

	if s, b := rf(r1); s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", s, b)
	}
	rec.expect(t, "reuse:r", "tokerr:r:refresh_token:invalid_grant")

	// The family is now revoked: using r2 is an error, but not a new reuse.
	if s, _ := rf(r2); s != 400 {
		t.Fatalf("r2: %d", s)
	}
	rec.expect(t, "tokerr:r:refresh_token:invalid_grant")
}

func TestObsExplicitRevokeIsNotReuse(t *testing.T) {
	e, rec := newObsEnv(t, nil)
	_, tok, _ := e.tokenReq(codeForm(e.getCode(authQuery(nil))), "", "")
	rec.take()
	req := httptest.NewRequest("POST", base+"revoke",
		strings.NewReader(url.Values{"token": {tok["refresh_token"].(string)}, "client_id": {"app"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if w := e.do(req); w.Code != 200 {
		t.Fatalf("revoke %d", w.Code)
	}
	rec.expect(t)
}

func TestObsCodeReplay(t *testing.T) {
	e, rec := newObsEnv(t, nil)
	code := e.getCode(authQuery(nil))
	rec.take()
	if s, _, _ := e.tokenReq(codeForm(code), "", ""); s != 200 {
		t.Fatalf("first exchange %d", s)
	}
	rec.take()
	if s, b, _ := e.tokenReq(codeForm(code), "", ""); s != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("replay: %d %v", s, b)
	}
	rec.expect(t, "replay:r", "tokerr:r:authorization_code:invalid_grant")

	// A code that was never issued is an error, not a replay.
	e.tokenReq(codeForm("never-issued"), "", "")
	rec.expect(t, "tokerr:r:authorization_code:invalid_grant")
}
