// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

func TestPendingProofs(t *testing.T) {
	e := newEnv(t, nil)
	tok := e.h.signPending("r", "u1", "mfa", "payload", time.Minute)
	if uid, pl, ok := e.h.checkPending("r", tok, "mfa"); !ok || uid != "u1" || pl != "payload" {
		t.Fatalf("valid proof rejected: %v %q %q", ok, uid, pl)
	}
	for name, c := range map[string]struct{ realm, tok, purpose string }{
		"other realm":   {"x", tok, "mfa"},
		"other purpose": {"r", tok, "other"},
		"tampered":      {"r", tok[:len(tok)-2] + "AA", "mfa"},
		"garbage":       {"r", "nope", "mfa"},
		"empty":         {"r", "", "mfa"},
	} {
		if _, _, ok := e.h.checkPending(c.realm, c.tok, c.purpose); ok {
			t.Errorf("%s accepted", name)
		}
	}
	e.now = e.now.Add(2 * time.Minute)
	if _, _, ok := e.h.checkPending("r", tok, "mfa"); ok {
		t.Error("expired proof accepted")
	}
}

// A step hook interrupts the login before any code or session exists; its
// continue hook finishes it. Prove the ordering guarantees every feature
// relies on.
func TestAuthStepHooks(t *testing.T) {
	savedS, savedC := authStepHooks, authContinueHooks
	defer func() { authStepHooks, authContinueHooks = savedS, savedC }()

	var sawPassword bool
	registerAuthStep(
		func(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) bool {
			tok := p.signPending(ar.realm.Name, u.ID, "test-step", "", time.Minute)
			p.stepPage(w, r, ar, http.StatusOK, "Second step", "", `<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="step_token" value="`+tok+`">
<input name="answer"><button>Go</button></form>`, nil)
			return true
		},
		func(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq) bool {
			tok := r.PostForm.Get("step_token")
			if tok == "" {
				return false
			}
			sawPassword = r.PostForm.Get("password") != ""
			uid, _, ok := p.checkPending(ar.realm.Name, tok, "test-step")
			if !ok || r.PostForm.Get("answer") != "42" {
				p.stepPage(w, r, ar, http.StatusOK, "Second step", "Wrong answer", `<p>retry</p>`, nil)
				return true
			}
			u, err := p.cfg.Store.GetUser(r.Context(), ar.realm.Name, uid)
			if err != nil {
				t.Error(err)
				return true
			}
			p.completeLogin(w, r, ar, u, "test-step")
			return true
		})

	e := newEnv(t, nil)
	q := authQuery(nil)
	csrf, ck := e.loginForm(q)
	w := e.postLogin(q, "alice", "pw", csrf, ck)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Second step") {
		t.Fatalf("step page not shown: %d %s", w.Code, w.Body)
	}
	if len(e.st.codes) != 0 {
		t.Fatal("a code was issued before the extra step finished")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == ssoCookie {
			t.Fatal("SSO cookie set before the extra step finished")
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("step page CSP: %s", csp)
	}
	// A wrong password never reaches the hook.
	if w2 := e.postLogin(q, "alice", "WRONG", csrf, ck); strings.Contains(w2.Body.String(), "Second step") {
		t.Error("step hook ran for a wrong password")
	}
	// Second step: wrong answer, then right answer.
	csrf2 := csrfRe.FindStringSubmatch(w.Body.String())[1]
	var ck2 *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == csrfCookie {
			ck2 = c
		}
	}
	stepTok := regexp.MustCompile(`name="step_token" value="([^"]+)"`).FindStringSubmatch(w.Body.String())[1]
	post := func(answer, csrf string, ck *http.Cookie) *httptest.ResponseRecorder {
		v := url.Values{"step_token": {stepTok}, "answer": {answer}, "csrf": {csrf}}
		req := httptest.NewRequest("POST", base+"auth?"+q.Encode(), strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if ck != nil {
			req.AddCookie(ck)
		}
		return e.do(req)
	}
	if w3 := post("1", csrf2, ck2); !strings.Contains(w3.Body.String(), "Wrong answer") || len(e.st.codes) != 0 {
		t.Fatalf("wrong answer accepted or code issued: %d", w3.Code)
	}
	if w4 := post("42", csrf2, nil); w4.Code != http.StatusForbidden { // CSRF cookie missing
		t.Errorf("continue hook reachable without CSRF: %d", w4.Code)
	}
	w5 := post("42", csrf2, ck2)
	if w5.Code != http.StatusFound || !strings.Contains(w5.Header().Get("Location"), "code=") {
		t.Fatalf("login not completed: %d %s", w5.Code, w5.Body)
	}
	if sawPassword {
		t.Error("second-step form carried the password")
	}
}

// A user with two factors is challenged by the first applicable step, so the
// order is a security decision and must not depend on file names or init order.
func TestAuthStepOrdering(t *testing.T) {
	// The real registry (passkeys + TOTP are registered by init()).
	var orders []int
	for _, h := range authStepHooks {
		orders = append(orders, h.order)
	}
	for i := 1; i < len(orders); i++ {
		if orders[i] < orders[i-1] {
			t.Fatalf("steps not sorted by order: %v", orders)
		}
	}
	pk, tp := -1, -1
	for i, o := range orders {
		switch o {
		case authOrderPasskey:
			pk = i
		case authOrderDefault:
			if tp < 0 {
				tp = i
			}
		}
	}
	if pk < 0 || tp < 0 || pk > tp {
		t.Fatalf("the passkey step must run before the TOTP step: orders=%v", orders)
	}
	// The continue hooks follow the same order.
	for i := 1; i < len(authContinueHooks); i++ {
		if authContinueHooks[i].order < authContinueHooks[i-1].order {
			t.Fatal("continue hooks not sorted")
		}
	}

	// Mechanics on a scratch registry: lower first, ties keep registration order.
	savedS, savedC := authStepHooks, authContinueHooks
	defer func() { authStepHooks, authContinueHooks = savedS, savedC }()
	authStepHooks, authContinueHooks = nil, nil
	var seen []string
	mk := func(name string) authStepHook {
		return func(*Provider, http.ResponseWriter, *http.Request, *authzReq, core.User) bool {
			seen = append(seen, name)
			return false
		}
	}
	registerAuthStepAt(100, mk("late-a"), nil)
	registerAuthStepAt(50, mk("early"), nil)
	registerAuthStepAt(100, mk("late-b"), nil)
	registerAuthStepAt(75, mk("middle"), nil)
	for _, h := range authStepHooks {
		h.fn(nil, nil, nil, nil, core.User{})
	}
	if got := strings.Join(seen, ","); got != "early,middle,late-a,late-b" {
		t.Errorf("order = %s", got)
	}
}
