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
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
)

const ecPath = "/realms/r/account/email"

// ecSession logs u1 in (SSO session row + cookie).
func (e *aenv) ecSession(userID string) *http.Cookie {
	e.t.Helper()
	raw := "sso-cookie-" + userID
	err := e.st.PutSession(context.Background(), core.Session{ID: "s-" + userID, CookieHash: actions.Hash(raw),
		Realm: "r", UserID: userID, AuthTime: e.now, LastSeen: e.now, IdleExpires: e.now.Add(48 * time.Hour),
		ExpiresAt: e.now.Add(72 * time.Hour), CreatedAt: e.now})
	if err != nil {
		e.t.Fatal(err)
	}
	return &http.Cookie{Name: ssoCookie, Value: raw}
}

// ecGet loads the account page and returns csrf + csrf cookie.
func (e *aenv) ecGet(sso *http.Cookie) (*httptest.ResponseRecorder, string, *http.Cookie) {
	req := httptest.NewRequest("GET", ecPath, nil)
	if sso != nil {
		req.AddCookie(sso)
	}
	w := e.do(req)
	var ck *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == csrfCookie {
			ck = c
		}
	}
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		return w, "", ck
	}
	return w, m[1], ck
}

func (e *aenv) ecRequest(sso *http.Cookie, email, pw string) *httptest.ResponseRecorder {
	e.t.Helper()
	w, csrf, ck := e.ecGet(sso)
	if csrf == "" {
		e.t.Fatalf("account page did not render a form: %d %s", w.Code, w.Body)
	}
	req := httptest.NewRequest("POST", ecPath, strings.NewReader(url.Values{"email": {email}, "password": {pw}, "csrf": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sso)
	req.AddCookie(ck)
	w = e.do(req)
	e.h.Drain()
	return w
}

func (e *aenv) ecConfirm(link string) *httptest.ResponseRecorder {
	w, csrf, ck := e.form(link)
	if csrf == "" {
		return w
	}
	u, _ := url.Parse(link)
	return e.post(u.Path, url.Values{"token": {u.Query().Get("token")}, "csrf": {csrf}}, ck)
}

func (e *aenv) mailsTo(addr string) []string {
	var out []string
	for _, m := range e.mail.all() {
		if m.To == addr {
			out = append(out, m.Subject+"\n"+m.Text)
		}
	}
	return out
}

func TestEmailChangeEndToEnd(t *testing.T) {
	e := newAEnv(t, true)
	sso := e.ecSession("u1")
	w := e.ecRequest(sso, "alice.new@example.net", "oldpassword")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "does not change until") {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	if got := e.user("u1").Email; got != "alice@example.org" {
		t.Fatalf("address changed before confirmation: %q", got)
	}
	toNew, toOld := e.mailsTo("alice.new@example.net"), e.mailsTo("alice@example.org")
	if len(toNew) != 1 || len(toOld) != 1 {
		t.Fatalf("want one mail to new and one notice to old, got %d / %d", len(toNew), len(toOld))
	}
	if strings.Contains(toOld[0], "http") || strings.Contains(toOld[0], "token=") || strings.Contains(toOld[0], "alice.new@") {
		t.Errorf("notice to the old address leaks a link or the full new address: %q", toOld[0])
	}
	link := e.lastLinkTo("alice.new@example.net")
	// GET never consumes.
	e.form(link)
	e.form(link)
	if w := e.ecConfirm(link); w.Code != 200 || !strings.Contains(w.Body.String(), "Email address changed") {
		t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	u := e.user("u1")
	if u.Email != "alice.new@example.net" || !u.EmailVerified {
		t.Fatalf("after confirm: %+v", u)
	}
	e.h.Drain()
	if n := len(e.mailsTo("alice@example.org")); n != 2 {
		t.Errorf("old address should get a second notice after the change, got %d mails total", n)
	}
	// Single use.
	if w := e.ecConfirm(link); w.Code != 400 {
		t.Errorf("reused link: %d", w.Code)
	}
	evs, _ := e.st.ListEvents(context.Background(), "r", 10)
	types := ""
	for _, ev := range evs {
		types += ev.Type + " "
		if strings.Contains(ev.Detail, "@") {
			t.Errorf("event detail contains an address: %+v", ev)
		}
	}
	if !strings.Contains(types, "UPDATE_EMAIL_REQUEST") || !strings.Contains(types, "UPDATE_EMAIL ") {
		t.Errorf("events: %s", types)
	}
}

func (e *aenv) lastLinkTo(addr string) string {
	e.t.Helper()
	var last string
	for _, m := range e.mail.all() {
		if m.To == addr {
			last = m.Text
		}
	}
	m := linkRe.FindStringSubmatch(last)
	if m == nil {
		e.t.Fatalf("no link mailed to %s", addr)
	}
	return strings.ReplaceAll(m[1], "&amp;", "&")
}

func TestEmailChangeRequiresPasswordEveryTime(t *testing.T) {
	e := newAEnv(t, true)
	sso := e.ecSession("u1")
	w := e.ecRequest(sso, "x@example.net", "wrongpassword")
	if !strings.Contains(w.Body.String(), "Wrong password") {
		t.Fatalf("body: %s", w.Body)
	}
	if len(e.mail.all()) != 0 {
		t.Fatal("mail sent despite wrong password")
	}
	// Empty password too.
	e.ecRequest(sso, "x@example.net", "")
	if len(e.mail.all()) != 0 {
		t.Fatal("mail sent with empty password")
	}
}

func TestEmailChangeNeedsSessionCSRFAndEnabledUser(t *testing.T) {
	e := newAEnv(t, true)
	if w := e.do(httptest.NewRequest("GET", ecPath, nil)); w.Code != 401 {
		t.Errorf("no session GET: %d", w.Code)
	}
	sso := e.ecSession("u1")
	// POST with a missing/forged CSRF token.
	for name, mk := range map[string]func() *http.Request{
		"no csrf": func() *http.Request {
			r := httptest.NewRequest("POST", ecPath, strings.NewReader(url.Values{"email": {"x@example.net"}, "password": {"oldpassword"}}.Encode()))
			return r
		},
		"forged csrf": func() *http.Request {
			r := httptest.NewRequest("POST", ecPath, strings.NewReader(url.Values{"email": {"x@example.net"}, "password": {"oldpassword"}, "csrf": {"forged"}}.Encode()))
			r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "forged"})
			return r
		},
	} {
		r := mk()
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(sso)
		if w := e.do(r); w.Code != 403 {
			t.Errorf("%s: want 403, got %d", name, w.Code)
		}
	}
	e.h.Drain()
	if len(e.mail.all()) != 0 || e.user("u1").Email != "alice@example.org" {
		t.Fatal("state changed without CSRF")
	}
	// Disabled user with a live session.
	sso2 := e.ecSession("u2")
	if w := e.do(func() *http.Request { r := httptest.NewRequest("GET", ecPath, nil); r.AddCookie(sso2); return r }()); w.Code != 403 {
		t.Errorf("disabled user: %d", w.Code)
	}
}

func TestEmailChangeOffWithoutMail(t *testing.T) {
	e := newAEnv(t, false)
	sso := e.ecSession("u1")
	r := httptest.NewRequest("GET", ecPath, nil)
	r.AddCookie(sso)
	if w := e.do(r); w.Code != 404 {
		t.Errorf("account page without mail: %d", w.Code)
	}
	if w := e.do(httptest.NewRequest("GET", "/realms/r/login-actions/confirm-email-change?token=x", nil)); w.Code != 404 {
		t.Errorf("confirm page without mail: %d", w.Code)
	}
}

func TestEmailChangeDoesNotRevealTakenAddress(t *testing.T) {
	e := newAEnv(t, true)
	sso := e.ecSession("u1")
	free := e.ecRequest(sso, "free@example.net", "oldpassword")
	taken := e.ecRequest(sso, "DORA@example.org", "oldpassword") // dora's address
	norm := func(w *httptest.ResponseRecorder) string {
		s := regexp.MustCompile(`nonce="[^"]+"|value="[^"]*"`).ReplaceAllString(w.Body.String(), "")
		return s
	}
	if free.Code != taken.Code || norm(free) != norm(taken) {
		t.Errorf("responses differ:\n%d %s\n%d %s", free.Code, free.Body, taken.Code, taken.Body)
	}
	if n := len(e.mailsTo("DORA@example.org")) + len(e.mailsTo("dora@example.org")); n != 0 {
		t.Errorf("mail was sent to the other account's address (%d)", n)
	}
}

func TestEmailChangeLinkDiesIfAddressChangedMeanwhile(t *testing.T) {
	e := newAEnv(t, true)
	e.ecRequest(e.ecSession("u1"), "alice.new@example.net", "oldpassword")
	link := e.lastLinkTo("alice.new@example.net")
	u := e.user("u1")
	u.Email = "admin-set@example.org"
	if err := e.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if w := e.ecConfirm(link); w.Code != 400 {
		t.Fatalf("stale link accepted: %d", w.Code)
	}
	if got := e.user("u1").Email; got != "admin-set@example.org" {
		t.Errorf("address overwritten: %q", got)
	}
}

func TestEmailChangeLinkExpiresAndWrongPurposeFails(t *testing.T) {
	e := newAEnv(t, true)
	e.ecRequest(e.ecSession("u1"), "alice.new@example.net", "oldpassword")
	link := e.lastLinkTo("alice.new@example.net")
	e.now = e.now.Add(actions.ChangeEmailTTL + time.Minute)
	if w := e.ecConfirm(link); w.Code != 400 {
		t.Fatalf("expired link accepted: %d", w.Code)
	}
	// A verify-email token must not work as an email-change link.
	e.now = e.now.Add(-time.Hour * 3)
	svc := e.h.cfg.Actions
	rl, _ := e.st.GetRealm(context.Background(), "r")
	if err := svc.Send(context.Background(), rl, e.user("u1"), core.ActionVerifyEmail, actions.SendOpts{}); err != nil {
		t.Fatal(err)
	}
	vl := e.lastLink()
	vl = strings.Replace(vl, "verify-email", "confirm-email-change", 1)
	if w := e.ecConfirm(vl); w.Code != 400 {
		t.Fatalf("verify token accepted as email-change: %d", w.Code)
	}
}

func TestEmailChangeRateLimits(t *testing.T) {
	e := newAEnv(t, true)
	sso := e.ecSession("u1")
	for i := 0; i < ecSendMax; i++ {
		if w := e.ecRequest(sso, "a"+string(rune('a'+i))+"@example.net", "oldpassword"); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if w := e.ecRequest(sso, "zz@example.net", "oldpassword"); w.Code != http.StatusTooManyRequests {
		t.Errorf("send limit not enforced: %d", w.Code)
	}
	// Password guessing is limited too (separate user).
	e2 := newAEnv(t, true)
	sso2 := e2.ecSession("u1")
	for i := 0; i < mfaUserMax; i++ {
		e2.ecRequest(sso2, "x@example.net", "guess")
	}
	if w := e2.ecRequest(sso2, "x@example.net", "oldpassword"); w.Code != http.StatusTooManyRequests {
		t.Errorf("password attempt limit not enforced: %d", w.Code)
	}
	if len(e2.mail.all()) != 0 {
		t.Error("mail sent while locked out")
	}
}

func TestEmailChangeRejectsBadAddresses(t *testing.T) {
	e := newAEnv(t, true)
	sso := e.ecSession("u1")
	n := 0
	for _, bad := range []string{"", "nope", "a@b", "a b@example.net", "Bob <bob@example.net>", "a@example.net\r\nBcc: x@y.z",
		"a@example.net,b@example.net", "@example.net", strings.Repeat("a", 250) + "@example.net", "alice@example.org"} {
		if n++; n%4 == 0 {
			e.now = e.now.Add(mfaWindow + time.Second) // stay under the attempt limiter
		}
		w := e.ecRequest(sso, bad, "oldpassword")
		if w.Code != 200 || strings.Contains(w.Body.String(), "does not change until") {
			t.Errorf("%q accepted: %d", bad, w.Code)
		}
	}
	if len(e.mail.all()) != 0 {
		t.Errorf("mail sent for bad input: %d", len(e.mail.all()))
	}
}

func TestEmailChangeNewRequestWithdrawsOlderLink(t *testing.T) {
	e := newAEnv(t, true)
	sso := e.ecSession("u1")
	e.ecRequest(sso, "first@example.net", "oldpassword")
	first := e.lastLinkTo("first@example.net")
	e.ecRequest(sso, "second@example.net", "oldpassword")
	if w := e.ecConfirm(first); w.Code != 400 {
		t.Errorf("older link still works: %d", w.Code)
	}
	if w := e.ecConfirm(e.lastLinkTo("second@example.net")); w.Code != 200 {
		t.Errorf("newest link: %d", w.Code)
	}
}

func TestEmailChangeConfirmNeedsCSRF(t *testing.T) {
	e := newAEnv(t, true)
	e.ecRequest(e.ecSession("u1"), "alice.new@example.net", "oldpassword")
	u, _ := url.Parse(e.lastLinkTo("alice.new@example.net"))
	w := e.post(u.Path, url.Values{"token": {u.Query().Get("token")}}, nil)
	if w.Code != 403 || e.user("u1").Email != "alice@example.org" {
		t.Fatalf("confirm without CSRF: %d", w.Code)
	}
}

func TestValidateNewEmail(t *testing.T) {
	for in, ok := range map[string]bool{"a@example.com": true, " a@example.com ": true, "a+b@sub.example.co": true,
		"a@b": false, "x": false, "": false, "<a@example.com>": false} {
		_, err := actions.ValidateNewEmail(in)
		if (err == nil) != ok {
			t.Errorf("%q: ok=%v err=%v", in, ok, err)
		}
	}
}
