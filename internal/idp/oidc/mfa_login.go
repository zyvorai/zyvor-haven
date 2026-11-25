// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/totp"
)

// Login integration (registered with registerAuthStep, see mfa.go).
//
// After the password step the step hook either shows the code page (user has a
// confirmed credential), or, when the realm requires MFA and the user has none,
// the enrollment page. Neither issues a code or a session. The pages carry an
// "mfa_token": the signed pending proof (purpose "mfa", short ttl) that the
// password step passed for this user, bound to this authorization request and
// to one mode:
//
//	verify  enter a TOTP or recovery code
//	enroll  confirm a new authenticator (realm requires MFA)
//	done    enrollment confirmed, recovery codes shown; continue
//
// The continue hook accepts only requests carrying a valid proof. A bare code
// without one is not recognised and falls through to the normal login form
// handling (which then fails on the empty username/password).

const (
	modeVerify = "verify"
	modeEnroll = "enroll"
	modeDone   = "done"

	msgExpired = "Your sign-in expired. Sign in again."
)

type mfaPageData struct {
	Token      string
	Secret     string
	URI        string
	Codes      []string
	RecoveryOK bool
	Alt        *Fallback // "use another method" (fallback.go)
}

const verifyBody = `<p class="sub">{{.L.T "Enter the 6-digit code from your authenticator app, or a recovery code."}}</p>
<form method="post" action="{{.Action}}" autocomplete="off">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="mfa_token" value="{{.Data.Token}}">
<label for="c">{{.L.T "Code"}}</label><input id="c" name="code" autocomplete="one-time-code" autofocus required maxlength="64">
<button type="submit">{{.L.T "Verify"}}</button></form>` + altFragment

const enrollBody = `<p class="sub">{{.L.T "%s requires a second factor. Add this account to an authenticator app, then enter the 6-digit code it shows." .Realm}}</p>
<p>{{.L.H "Secret key: %s" (.L.C .Data.Secret)}}</p>
<p class="sub">{{.L.H "Or enter this setup link in an app that accepts one: %s" (.L.C .Data.URI)}}</p>
<form method="post" action="{{.Action}}" autocomplete="off">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="mfa_token" value="{{.Data.Token}}">
<label for="c">{{.L.T "6-digit code"}}</label><input id="c" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus required maxlength="16">
<button type="submit">{{.L.T "Confirm and continue"}}</button></form>`

const recoveryCodesFrag = `<p class="err"><strong>{{.L.T "Save these recovery codes now."}}</strong> {{.L.T "They are shown only once and cannot be displayed again. Each works one time if you lose your authenticator."}}</p>
<pre>{{range .Data.Codes}}{{.}}
{{end}}</pre>`

const doneBody = recoveryCodesFrag + `
<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="mfa_token" value="{{.Data.Token}}">
<button type="submit">{{.L.T "I have saved my codes: continue"}}</button></form>`

// credTag names one credential: a hash of its sealed seed, which carries a
// fresh random nonce, so a re-enrolled credential never shares it.
func credTag(c core.TOTPCredential) string { return hexKey("mfa-cred", c.SealedSeed)[:16] }

// mfaBind ties a proof to the authorization request it was issued for.
func mfaBind(r *http.Request) string { return hexKey("mfa-bind", r.URL.RawQuery)[:16] }

func (p *Provider) mfaProof(ar *authzReq, r *http.Request, userID, mode, extra string, ttl time.Duration) string {
	payload := mode + "|" + mfaBind(r)
	if extra != "" {
		payload += "|" + extra
	}
	return p.signPending(ar.realm.Name, userID, mfaPurpose, payload, ttl)
}

func (p *Provider) verifyPage(w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User, status int, errMsg string) {
	p.stepPage(w, r, ar, status, "Two-step verification", errMsg, verifyBody,
		mfaPageData{Token: p.mfaProof(ar, r, u.ID, modeVerify, "", mfaProofTTL), Alt: p.fallbackOffer(r, ar, u.ID, methodTOTP)})
}

// enrollPage shows the secret of the user's pending credential.
func (p *Provider) enrollPage(w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User, seed []byte, status int, errMsg string) {
	p.stepPage(w, r, ar, status, "Set up two-step verification", errMsg, enrollBody, mfaPageData{
		Token:  p.mfaProof(ar, r, u.ID, modeEnroll, "", mfaProofTTL),
		Secret: totp.EncodeSeed(seed),
		URI:    totp.URI(p.issuerName(ar.realm), u.Username, seed),
	})
}

// mfaStep runs after the password, enabled and email checks.
func mfaStep(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) bool {
	st, on := p.mfaStore()
	if !on {
		// Feature off. That must never quietly remove a factor somebody
		// depends on: with no key the seeds cannot be opened, so a user who
		// enrolled TOTP, or a realm that requires MFA, cannot be served and the
		// login is refused instead of falling back to the password alone.
		if p.mfaRequiredButUnavailable(r.Context(), ar.realm.Name, u.ID) {
			p.cfg.Logger.Error("oidc: two-step verification is required for this login but HAVEN_IDP_SECRET_KEY is not set: refusing the login", "realm", ar.realm.Name)
			p.cfg.Obs.Login(ar.realm.Name, "mfa_unavailable")
			p.event(r.Context(), ar.realm, "LOGIN_ERROR", u.ID, ar.client.ClientID, p.clientIP(r), "mfa_unavailable")
			p.errorPage(w, http.StatusServiceUnavailable, "Two-step verification is required for this account but is currently unavailable. Contact your administrator.")
			return true
		}
		return false
	}
	ctx := r.Context()
	cred, err := st.GetTOTP(ctx, ar.realm.Name, u.ID)
	switch {
	case err == nil && cred.Confirmed:
		p.verifyPage(w, r, ar, u, http.StatusOK, "")
		return true
	case err != nil && !isNotFound(err):
		p.cfg.Logger.Error("oidc: mfa load credential", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return true
	}
	// No confirmed credential. Enforce enrollment only if the realm asks.
	pol, err := st.GetMFAPolicy(ctx, ar.realm.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: mfa load policy", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return true
	}
	if !pol.RequireMFA {
		return false
	}
	seed, err := p.newEnrollment(r, st, ar.realm.Name, u.ID)
	if err != nil {
		p.cfg.Logger.Error("oidc: mfa start enrollment", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return true
	}
	p.enrollPage(w, r, ar, u, seed, http.StatusOK, "")
	return true
}

// mfaContinue handles the posts of the code page, the enrollment page and the
// recovery-code page. It runs after the CSRF check.
func mfaContinue(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq) bool {
	tok := r.PostForm.Get("mfa_token")
	if tok == "" {
		return false
	}
	expired := func() { p.loginPage(w, r, ar, msgExpired, "") }
	st, on := p.mfaStore()
	if !on {
		expired()
		return true
	}
	rl := ar.realm
	uid, payload, ok := p.checkPending(rl.Name, tok, mfaPurpose)
	if !ok {
		expired()
		return true
	}
	parts := strings.SplitN(payload, "|", 3)
	if len(parts) < 2 || parts[1] != mfaBind(r) {
		expired()
		return true
	}
	mode, extra := parts[0], ""
	if len(parts) == 3 {
		extra = parts[2]
	}
	ctx := r.Context()
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, uid)
	if err != nil {
		if isNotFound(err) {
			expired()
		} else {
			p.cfg.Logger.Error("oidc: mfa load user", "err", err)
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
	cred, err := st.GetTOTP(ctx, rl.Name, uid)
	if err != nil && !isNotFound(err) {
		p.cfg.Logger.Error("oidc: mfa load credential", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return true
	}
	have := err == nil

	switch mode {
	case modeVerify:
		if !have || !cred.Confirmed {
			expired()
			return true
		}
		p.mfaVerifyPost(w, r, ar, st, u, cred)
	case modeEnroll:
		if !have || cred.Confirmed {
			expired()
			return true
		}
		p.mfaEnrollPost(w, r, ar, st, u, cred)
	case modeDone:
		// Only reachable with a proof minted when this very credential was
		// confirmed, and only while it still exists.
		if !have || !cred.Confirmed || extra != credTag(cred) {
			expired()
			return true
		}
		p.completeLogin(w, r, ar, u, "totp")
	default:
		expired()
	}
	return true
}

func (p *Provider) mfaVerifyPost(w http.ResponseWriter, r *http.Request, ar *authzReq, st core.MFAStore, u core.User, cred core.TOTPCredential) {
	rl := ar.realm
	res, method := p.mfaCheck(r, st, rl, cred, r.PostForm.Get("code"))
	switch res {
	case mfaOK:
		if method == "recovery" {
			p.mfaEvent(r, rl, "RECOVERY_USED", u.ID, ar.client.ClientID, "login")
		}
		p.completeLogin(w, r, ar, u, method)
	case mfaBad:
		p.mfaEvent(r, rl, "MFA_FAILED", u.ID, ar.client.ClientID, "invalid_code")
		p.verifyPage(w, r, ar, u, http.StatusOK, mfaGeneric)
	case mfaDenied:
		p.verifyPage(w, r, ar, u, http.StatusTooManyRequests, mfaLimited)
	default:
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
	}
}

// mfaEnrollPost confirms the pending credential with a valid code, issues the
// recovery codes and shows them once.
func (p *Provider) mfaEnrollPost(w http.ResponseWriter, r *http.Request, ar *authzReq, st core.MFAStore, u core.User, cred core.TOTPCredential) {
	rl := ar.realm
	seed, err := p.openSeed(cred)
	if err != nil {
		p.cfg.Logger.Error("oidc: mfa cannot open pending seed", "realm", rl.Name, "user", u.ID)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return
	}
	allowed, err := p.mfaThrottle(r, rl.Name, u.ID, "enroll")
	if err != nil {
		p.cfg.Logger.Error("oidc: mfa rate limit", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return
	}
	if !allowed {
		p.enrollPage(w, r, ar, u, seed, http.StatusTooManyRequests, mfaLimited)
		return
	}
	input := r.PostForm.Get("code")
	if len(input) > mfaMaxInput {
		input = input[:mfaMaxInput]
	}
	step, good := totp.Verify(seed, input, p.now(), 0)
	if !good {
		p.mfaEvent(r, rl, "MFA_FAILED", u.ID, ar.client.ClientID, "invalid_code")
		p.enrollPage(w, r, ar, u, seed, http.StatusOK, mfaGeneric)
		return
	}
	won, err := st.ConfirmTOTP(r.Context(), rl.Name, u.ID, step)
	if err != nil {
		p.cfg.Logger.Error("oidc: mfa confirm", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return
	}
	if !won { // a parallel request confirmed first; start over
		p.loginPage(w, r, ar, msgExpired, "")
		return
	}
	codes, err := p.issueRecoveryCodes(r, st, rl.Name, u.ID)
	if err != nil {
		// Confirmed but no codes: the user can regenerate them on the account
		// page. Never complete the login without showing the codes.
		p.cfg.Logger.Error("oidc: mfa recovery codes", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Two-step verification is set up, but the recovery codes could not be created. Sign in again, then regenerate them in your account settings.")
		return
	}
	p.mfaEvent(r, rl, "TOTP_ENROLLED", u.ID, ar.client.ClientID, "login")
	p.stepPage(w, r, ar, http.StatusOK, "Save your recovery codes", "", doneBody, mfaPageData{
		Token: p.mfaProof(ar, r, u.ID, modeDone, credTag(cred), mfaDoneTTL),
		Codes: codes,
	})
}

// mfaRequiredButUnavailable reports whether a login that reached the MFA step
// would have needed TOTP while the feature is switched off. Anything it cannot
// establish counts as "required" (fail closed). When the store has no MFA
// support at all, TOTP was never usable, so nothing is required.
func (p *Provider) mfaRequiredButUnavailable(ctx context.Context, realm, userID string) bool {
	st, ok := core.StoreAs[core.MFAStore](p.cfg.Store)
	if !ok {
		return false
	}
	if cred, err := st.GetTOTP(ctx, realm, userID); err == nil && cred.Confirmed {
		return true
	} else if err != nil && !isNotFound(err) {
		return true
	}
	pol, err := st.GetMFAPolicy(ctx, realm)
	if err != nil {
		return true
	}
	return pol.RequireMFA
}
