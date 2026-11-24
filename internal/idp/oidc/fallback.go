// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
)

// "Use another method" on the passkey and TOTP login steps (docs/login-fallback-and-stepup.md).
//
// The fallback never completes a login and never skips a factor. The button
// posts a signed, short-lived "fallback" proof (the password step passed, for
// this user and this authorization request, towards one named method); the
// handler re-checks that the realm allows it and that the user really has the
// other method enrolled, then renders that method's ordinary step page. The
// code or assertion is verified, rate limited and replay protected by exactly
// the same code as before.

const (
	fallbackPurpose = "fallback"
	fallbackTTL     = 10 * time.Minute
	fallbackWindow  = 10 * time.Minute
	fallbackPerIP   = 30

	methodTOTP    = "totp"
	methodPasskey = "passkey"

	authOrderFallback = 10 // before every step that reads its own fields
)

func init() {
	registerAuthStepAt(authOrderFallback, nil, fallbackContinue)
}

// Fallback is the "use another method" button of a step page.
type Fallback struct {
	Token string
	Label string
}

// altFragment is appended to the passkey and TOTP step bodies; Data must
// carry an Alt *Fallback.
const altFragment = `
{{if .Data.Alt}}<form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="fb_token" value="{{.Data.Alt.Token}}"><button type="submit" class="secondary">{{.Data.Alt.Label}}</button></form>{{end}}`

// methodReady reports whether the user has the method enrolled and the
// feature for it is on. Errors count as "not ready".
func (p *Provider) methodReady(r *http.Request, realm, userID, method string) bool {
	ctx := r.Context()
	switch method {
	case methodTOTP:
		st, ok := p.mfaStore()
		if !ok {
			return false
		}
		c, err := st.GetTOTP(ctx, realm, userID)
		return err == nil && c.Confirmed
	case methodPasskey:
		st, _, ok := p.passkeys()
		if !ok {
			return false
		}
		creds, err := st.ListPasskeys(ctx, realm, userID)
		return err == nil && len(creds) > 0
	}
	return false
}

// fallbackOffer returns the button for a step page of method `from`, or nil
// when the realm does not allow it or the user has no other method.
func (p *Provider) fallbackOffer(r *http.Request, ar *authzReq, userID, from string) *Fallback {
	st, on := p.stepUpStore()
	if !on {
		return nil
	}
	pol, err := st.GetStepUpPolicy(r.Context(), ar.realm.Name)
	if err != nil || !pol.AllowFallback {
		return nil
	}
	to, label := methodPasskey, "Use a passkey instead"
	if from == methodPasskey {
		to, label = methodTOTP, "Use an authenticator code or recovery code instead"
	}
	if !p.methodReady(r, ar.realm.Name, userID, to) {
		return nil
	}
	return &Fallback{Label: label,
		Token: p.signPending(ar.realm.Name, userID, fallbackPurpose, to+"|"+mfaBind(r), fallbackTTL)}
}

func (p *Provider) fallbackRate(r *http.Request, realm string) bool {
	h := sha256.Sum256([]byte("fallback|" + realm + "|" + p.clientIP(r)))
	ok, err := p.cfg.Store.HitRateLimit(r.Context(), hex.EncodeToString(h[:]), p.now(), fallbackWindow, fallbackPerIP)
	if err != nil {
		p.cfg.Logger.Error("oidc: fallback rate limit", "err", err)
		return false
	}
	return ok
}

// fallbackContinue handles the post of the "use another method" button. It
// runs after the CSRF check.
func fallbackContinue(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq) bool {
	tok := r.PostForm.Get("fb_token")
	if tok == "" {
		return false
	}
	ctx := r.Context()
	rl := ar.realm
	expired := func() { p.loginPage(w, r, ar, msgExpired, "") }
	st, on := p.stepUpStore()
	if !on {
		p.errorPage(w, http.StatusNotFound, "Not available.")
		return true
	}
	if !p.fallbackRate(r, rl.Name) {
		p.errorPage(w, http.StatusTooManyRequests, mfaLimited)
		return true
	}
	uid, payload, ok := p.checkPending(rl.Name, tok, fallbackPurpose)
	if !ok {
		expired()
		return true
	}
	to, bind, _ := strings.Cut(payload, "|")
	if bind != mfaBind(r) || (to != methodTOTP && to != methodPasskey) {
		expired()
		return true
	}
	pol, err := st.GetStepUpPolicy(ctx, rl.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: fallback policy", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return true
	}
	if !pol.AllowFallback {
		expired()
		return true
	}
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, uid)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			expired()
		} else {
			p.cfg.Logger.Error("oidc: fallback load user", "err", err)
			p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		}
		return true
	}
	// The user may have been disabled or locked since the password step.
	locked := !u.LockedUntil.IsZero() && p.now().Before(u.LockedUntil)
	if !u.Enabled || (rl.BruteForceProtection && locked) || (rl.EmailVerificationRequired && !u.EmailVerified) {
		expired()
		return true
	}
	if !p.methodReady(r, rl.Name, uid, to) {
		expired()
		return true
	}
	p.mfaEvent(r, rl, "MFA_FALLBACK", u.ID, ar.client.ClientID, "to:"+to)
	switch to {
	case methodTOTP:
		p.verifyPage(w, r, ar, u, http.StatusOK, "")
	default:
		pst, rp, ok := p.passkeys()
		if !ok {
			expired()
			return true
		}
		creds, err := pst.ListPasskeys(ctx, rl.Name, uid)
		if err != nil || len(creds) == 0 {
			expired()
			return true
		}
		p.pkSecondFactorPage(w, r, ar, rp, uid, creds, "")
	}
	return true
}
