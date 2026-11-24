// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/totp"
	"github.com/zyvorai/haven/internal/idp/webauthn/webauthntest"
)

// fbEnv: a user with BOTH a passkey and a confirmed TOTP credential.
type fbEnv struct {
	*pkEnv
	box  *secretbox.Box
	auth *webauthntest.Authenticator
	seed []byte
}

var fbTokenRe = regexp.MustCompile(`name="fb_token" value="([^"]+)"`)

func newFB(t *testing.T, policy core.StepUpPolicy, wrap func(core.Store) core.Store, passkey, totpOn bool) *fbEnv {
	t.Helper()
	f := &fbEnv{}
	k, _ := secretbox.ParseKey(secretbox.GenerateKey())
	f.box, _ = secretbox.New(k)
	f.pkEnv = newPKEnv(t, nil, wrap, func(c *Config) { c.SecretBox = f.box })
	ctx := context.Background()
	if passkey {
		f.auth = f.register(-7)
	}
	if totpOn {
		f.seed = totp.NewSeed()
		must(t, f.st.PutTOTP(ctx, core.TOTPCredential{Realm: "r", UserID: "u1", CreatedAt: f.now,
			SealedSeed: f.box.Seal(f.seed, "totp|r|u1")}))
		if ok, err := f.st.ConfirmTOTP(ctx, "r", "u1", totp.StepAt(f.now)-5); err != nil || !ok {
			t.Fatal(err, ok)
		}
	}
	must(t, f.st.PutStepUpPolicy(ctx, "r", policy))
	f.forget()
	return f
}

func (f *fbEnv) code() string { return totp.CodeAt(f.seed, totp.StepAt(f.now)) }

func authPOST() string { return authPath + authQuery(nil).Encode() }

// postStep posts fields to /auth with the csrf of the page in prev.
func (f *fbEnv) postStep(prev *httptest.ResponseRecorder, fields url.Values) *httptest.ResponseRecorder {
	csrf := csrfRe.FindStringSubmatch(prev.Body.String())[1]
	if ck, ok := f.cookies[csrfCookie]; ok { // pages re-issue the pair; the jar holds the latest
		csrf = ck.Value
	}
	v := url.Values{"csrf": {csrf}}
	for k, x := range fields {
		v[k] = x
	}
	return f.do("POST", authPOST(), v)
}

func (f *fbEnv) fbTokenOf(w *httptest.ResponseRecorder) string {
	m := fbTokenRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		return ""
	}
	return m[1]
}

func isPasskeyPage(w *httptest.ResponseRecorder) bool {
	return w.Code == 200 && strings.Contains(w.Body.String(), "Use your passkey")
}
func isTOTPPage(w *httptest.ResponseRecorder) bool {
	return w.Code == 200 && strings.Contains(w.Body.String(), "Enter the 6-digit code")
}
func isSignIn(w *httptest.ResponseRecorder) bool {
	return w.Code == 200 && strings.Contains(w.Body.String(), "Sign in to") && strings.Contains(w.Body.String(), msgExpired)
}

func (f *fbEnv) noSession(w *httptest.ResponseRecorder) {
	f.t.Helper()
	if isCode(w) {
		f.t.Fatal("a code was issued")
	}
	if _, ok := f.cookies[ssoCookie]; ok {
		f.t.Fatal("an SSO session exists")
	}
}

func TestFallbackPasskeyToTOTPAndBack(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, true, true)
	w := f.passwordLogin(pkPW)
	if !isPasskeyPage(w) {
		t.Fatalf("a user with both factors must get the passkey first: %d %s", w.Code, w.Body)
	}
	tok := f.fbTokenOf(w)
	if tok == "" {
		t.Fatal("no 'use another method' offered")
	}
	// The password step already happened; choosing another method issues nothing.
	w2 := f.postStep(w, url.Values{"fb_token": {tok}})
	if !isTOTPPage(w2) {
		t.Fatalf("expected the TOTP page: %d %s", w2.Code, w2.Body)
	}
	f.noSession(w2)
	// The TOTP page offers the way back, and it works.
	back := f.fbTokenOf(w2)
	if back == "" {
		t.Fatal("TOTP page offers no way back to the passkey")
	}
	w3 := f.postStep(w2, url.Values{"fb_token": {back}})
	if !isPasskeyPage(w3) {
		t.Fatalf("expected the passkey page again: %d", w3.Code)
	}
	// Go to TOTP again and finish: wrong code first (still no code), then the right one.
	w4 := f.postStep(w3, url.Values{"fb_token": {f.fbTokenOf(w3)}})
	mfaTok := tokenRe.FindStringSubmatch(w4.Body.String())[1]
	bad := f.postStep(w4, url.Values{"mfa_token": {mfaTok}, "code": {"000000"}})
	if !isTOTPPage(bad) || !strings.Contains(bad.Body.String(), mfaGeneric) {
		t.Fatalf("wrong code: %d %s", bad.Code, bad.Body)
	}
	f.noSession(bad)
	mfaTok = tokenRe.FindStringSubmatch(bad.Body.String())[1]
	good := f.postStep(bad, url.Values{"mfa_token": {mfaTok}, "code": {f.code()}})
	if !isCode(good) {
		t.Fatalf("login via fallback did not complete: %d %s", good.Code, good.Body)
	}
	if f.events("MFA_FALLBACK") < 3 {
		t.Errorf("MFA_FALLBACK events: %d", f.events("MFA_FALLBACK"))
	}

	// Replay protection is the unchanged TOTP path: the same code cannot be used by a second login.
	f.forget()
	w = f.passwordLogin(pkPW)
	w = f.postStep(w, url.Values{"fb_token": {f.fbTokenOf(w)}})
	mfaTok = tokenRe.FindStringSubmatch(w.Body.String())[1]
	if r := f.postStep(w, url.Values{"mfa_token": {mfaTok}, "code": {f.code()}}); isCode(r) {
		t.Fatal("a TOTP code was accepted twice through the fallback")
	}
}

func TestFallbackTOTPToPasskeyCompletes(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, true, true)
	w := f.passwordLogin(pkPW)
	w = f.postStep(w, url.Values{"fb_token": {f.fbTokenOf(w)}}) // to TOTP
	w = f.postStep(w, url.Values{"fb_token": {f.fbTokenOf(w)}}) // and back to the passkey
	pg := parsePKPage(t, w)
	if r := f.do("POST", authPOST(), assertionForm(pg, "2fa", f.auth, pkOrigin)); !isCode(r) {
		t.Fatalf("passkey after the round trip: %d %s", r.Code, r.Body)
	}
}

func TestFallbackNotOfferedWhenOffOrNothingToFallBackTo(t *testing.T) {
	// Policy off: both enrolled, no button, and a forged request does not open the other page.
	f := newFB(t, core.StepUpPolicy{}, nil, true, true)
	w := f.passwordLogin(pkPW)
	if !isPasskeyPage(w) || f.fbTokenOf(w) != "" {
		t.Fatalf("fallback offered with the policy off: %d", w.Code)
	}
	req := httptest.NewRequest("POST", authPOST(), nil)
	forged := f.h.signPending("r", "u1", fallbackPurpose, methodTOTP+"|"+mfaBind(req), time.Minute)
	r := f.postStep(w, url.Values{"fb_token": {forged}})
	if isTOTPPage(r) || !isSignIn(r) {
		t.Fatalf("a correctly signed token worked although the realm does not allow fallback: %d", r.Code)
	}

	// Only a passkey: nothing to fall back to.
	f2 := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, true, false)
	if w := f2.passwordLogin(pkPW); !isPasskeyPage(w) || f2.fbTokenOf(w) != "" {
		t.Fatalf("offered with only a passkey: %d", w.Code)
	}
	// Only TOTP: nothing to fall back to.
	f3 := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, false, true)
	if w := f3.passwordLogin(pkPW); !isTOTPPage(w) || f3.fbTokenOf(w) != "" {
		t.Fatalf("offered with only TOTP: %d", w.Code)
	}
}

func TestFallbackTokenRejections(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, true, true)
	w := f.passwordLogin(pkPW)
	good := f.fbTokenOf(w)
	req := httptest.NewRequest("POST", authPOST(), nil)
	bind := mfaBind(req)
	must(t, f.st.CreateUser(context.Background(), core.User{ID: "u2", Realm: "r", Username: "bob", Enabled: true, EmailVerified: true}))

	otherReq := httptest.NewRequest("POST", authPath+authQuery(map[string]string{"state": "other"}).Encode(), nil)
	cases := map[string]string{
		"another user without TOTP":  f.h.signPending("r", "u2", fallbackPurpose, methodTOTP+"|"+bind, time.Minute),
		"another authorization req":  f.h.signPending("r", "u1", fallbackPurpose, methodTOTP+"|"+mfaBind(otherReq), time.Minute),
		"wrong purpose (mfa proof)":  f.h.signPending("r", "u1", mfaPurpose, methodTOTP+"|"+bind, time.Minute),
		"unknown method":             f.h.signPending("r", "u1", fallbackPurpose, "sms|"+bind, time.Minute),
		"other realm":                f.h.signPending("other", "u1", fallbackPurpose, methodTOTP+"|"+bind, time.Minute),
		"tampered":                   good[:len(good)-2] + "AA",
		"garbage":                    "nope",
		"expired":                    f.h.signPending("r", "u1", fallbackPurpose, methodTOTP+"|"+bind, -time.Second),
		"no bind":                    f.h.signPending("r", "u1", fallbackPurpose, methodTOTP, time.Minute),
		"another user's real target": f.h.signPending("r", "u2", fallbackPurpose, methodPasskey+"|"+bind, time.Minute),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			r := f.postStep(w, url.Values{"fb_token": {tok}})
			if isTOTPPage(r) || isPasskeyPage(r) || isCode(r) || r.Code == 500 {
				t.Fatalf("accepted: %d %s", r.Code, r.Body)
			}
			f.noSession(r)
		})
	}

	// State changes between the click and the post are honoured.
	t.Run("user disabled meanwhile", func(t *testing.T) {
		u, _ := f.st.GetUser(context.Background(), "r", "u1")
		u.Enabled = false
		must(t, f.st.UpdateUser(context.Background(), u))
		defer func() { u.Enabled = true; _ = f.st.UpdateUser(context.Background(), u) }()
		if r := f.postStep(w, url.Values{"fb_token": {good}}); isTOTPPage(r) || !isSignIn(r) {
			t.Fatalf("disabled user got the TOTP page: %d", r.Code)
		}
	})
	t.Run("TOTP removed meanwhile", func(t *testing.T) {
		cred, _ := f.st.GetTOTP(context.Background(), "r", "u1")
		must(t, f.st.DeleteUserMFA(context.Background(), "r", "u1"))
		defer func() {
			_ = f.st.PutTOTP(context.Background(), cred)
			_, _ = f.st.ConfirmTOTP(context.Background(), "r", "u1", totp.StepAt(f.now)-5)
		}()
		if r := f.postStep(w, url.Values{"fb_token": {good}}); isTOTPPage(r) || !isSignIn(r) {
			t.Fatalf("method no longer enrolled but offered: %d", r.Code)
		}
	})
	t.Run("policy switched off meanwhile", func(t *testing.T) {
		must(t, f.st.PutStepUpPolicy(context.Background(), "r", core.StepUpPolicy{}))
		defer func() { _ = f.st.PutStepUpPolicy(context.Background(), "r", core.StepUpPolicy{AllowFallback: true}) }()
		if r := f.postStep(w, url.Values{"fb_token": {good}}); isTOTPPage(r) || !isSignIn(r) {
			t.Fatalf("fallback honoured after the policy was switched off: %d", r.Code)
		}
	})
	// And the good token still works afterwards (the table above consumed nothing).
	if r := f.postStep(w, url.Values{"fb_token": {good}}); !isTOTPPage(r) {
		t.Fatalf("good token no longer works: %d %s", r.Code, r.Body)
	}
}

func TestFallbackNeedsCSRFAndKey(t *testing.T) {
	f := newFB(t, core.StepUpPolicy{AllowFallback: true}, nil, true, true)
	w := f.passwordLogin(pkPW)
	tok := f.fbTokenOf(w)
	// No CSRF cookie: the continue hook is not reachable.
	req := httptest.NewRequest("POST", authPOST(), strings.NewReader(url.Values{"fb_token": {tok},
		"csrf": {csrfRe.FindStringSubmatch(w.Body.String())[1]}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.1:1"
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("fallback without CSRF cookie: %d", rec.Code)
	}
	// TOTP feature off (no key): the TOTP target is not available; the passkey page shows no offer.
	f.h.cfg.SecretBox = nil
	f.forget()
	if w := f.passwordLogin(pkPW); f.fbTokenOf(w) != "" {
		t.Fatal("TOTP offered without a secret key")
	}
}

func TestFallbackRateLimitFailsClosed(t *testing.T) {
	var ls *limitStore
	f := newFB(t, core.StepUpPolicy{AllowFallback: true},
		func(s core.Store) core.Store { ls = &limitStore{Store: s}; return ls }, true, true)
	for name, set := range map[string]func(){
		"denied":      func() { ls.deny, ls.err = true, nil },
		"store error": func() { ls.deny, ls.err = false, errors.New("db down") },
	} {
		ls.deny, ls.err = false, nil
		f.forget()
		w := f.passwordLogin(pkPW)
		tok := f.fbTokenOf(w)
		set()
		r := f.postStep(w, url.Values{"fb_token": {tok}})
		if r.Code != http.StatusTooManyRequests || isTOTPPage(r) {
			t.Fatalf("%s: %d", name, r.Code)
		}
	}
}
