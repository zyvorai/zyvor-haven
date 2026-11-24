// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"net/http"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/totp"
)

// Account page: GET/POST /realms/{realm}/account/totp. It needs a live SSO
// session of an enabled user and a CSRF token. Starting an enrollment,
// disabling TOTP and regenerating recovery codes additionally need a recent
// login: when the session's AuthTime is older than mfaFreshAuth the form asks
// for the account password too (there is no client to redirect through /auth
// with prompt=login from a page of the IdP itself).

type acctData struct {
	State        string // "off" | "pending" | "on"
	Remaining    int
	NeedPassword bool
	Info         string
	Secret, URI  string
	Codes        []string
	Required     bool
}

const acctPW = `{{if .NeedPassword}}<label for="pw{{.State}}">Password (to confirm it is you)</label><input id="pw{{.State}}" name="password" type="password" autocomplete="current-password" required maxlength="1024">{{end}}` // #nosec G101 -- HTML template fragment with a password input, no credential

const acctBody = `{{with .Data}}{{if .Codes}}` + `<p class="err"><strong>Save these recovery codes now.</strong> They are shown only once and cannot be displayed again. Each works one time if you lose your authenticator.</p>
<pre>{{range .Codes}}{{.}}
{{end}}</pre>
{{else if .Secret}}<p class="sub">Add this account to your authenticator app, then enter the 6-digit code it shows to finish.</p>
<p>Secret key: <code>{{.Secret}}</code></p>
<p class="sub">Or enter this setup link in an app that accepts one: <code>{{.URI}}</code></p>
<form method="post" action="{{$.Action}}" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="confirm">
<label for="cc">6-digit code</label><input id="cc" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus required maxlength="16">
<button type="submit">Confirm</button></form>
{{else}}{{if .Info}}<p class="sub">{{.Info}}</p>{{end}}
{{if eq .State "off"}}<p>Two-step verification is <strong>off</strong>.</p>{{if .Required}}<p class="sub">This realm requires it at sign-in.</p>{{end}}
<form method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="start">` + acctPW + `
<button type="submit">Set up authenticator app</button></form>
{{else if eq .State "pending"}}<p>Setup was started but not finished.</p>
<form method="post" action="{{$.Action}}" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="confirm">
<label for="cc">6-digit code from your app</label><input id="cc" name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="16">
<button type="submit">Confirm</button></form>
<form method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="start">` + acctPW + `
<button type="submit" class="secondary">Start over with a new secret</button></form>
<form method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="disable">` + acctPW + `
<button type="submit" class="secondary">Cancel setup</button></form>
{{else}}<p>Two-step verification is <strong>on</strong>. Recovery codes left: <strong>{{.Remaining}}</strong>.</p>
<form method="post" action="{{$.Action}}" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="regenerate">
<label for="rc">Current code or a recovery code</label><input id="rc" name="code" autocomplete="one-time-code" required maxlength="64">` + acctPW + `
<button type="submit">Generate new recovery codes</button></form>
<form method="post" action="{{$.Action}}" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="disable">
<label for="dc">Current code or a recovery code</label><input id="dc" name="code" autocomplete="one-time-code" required maxlength="64">` + acctPW + `
<button type="submit" class="secondary">Turn off two-step verification</button></form>
{{end}}{{end}}{{end}}`

func (p *Provider) accountTOTP(w http.ResponseWriter, r *http.Request) {
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return
	}
	st, on := p.mfaStore()
	if !on {
		p.errorPage(w, http.StatusNotFound, "Not found.")
		return
	}
	sess, ok := p.currentSession(r, rl)
	if !ok {
		p.errorPage(w, http.StatusUnauthorized, "Sign in first, then open this page again.")
		return
	}
	ctx := r.Context()
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, sess.UserID)
	if err != nil || !u.Enabled {
		if err != nil && !isNotFound(err) {
			p.cfg.Logger.Error("oidc: account load user", "err", err)
		}
		p.errorPage(w, http.StatusForbidden, "Sign in first, then open this page again.")
		return
	}
	a := &acct{p: p, w: w, r: r, rl: rl, st: st, u: u,
		fresh: p.now().Sub(sess.AuthTime) <= mfaFreshAuth, path: "/realms/" + rl.Name + "/account/totp"}
	if r.Method == http.MethodGet {
		a.status("", "", http.StatusOK)
		return
	}
	if err := r.ParseForm(); err != nil {
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	if !p.checkFormCSRF(r, rl.Name) {
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Go back and try again.")
		return
	}
	switch r.PostForm.Get("action") {
	case "start":
		a.start()
	case "confirm":
		a.confirm()
	case "disable":
		a.disable()
	case "regenerate":
		a.regenerate()
	default:
		a.status("", "Unknown action.", http.StatusBadRequest)
	}
}

type acct struct {
	p     *Provider
	w     http.ResponseWriter
	r     *http.Request
	rl    core.Realm
	st    core.MFAStore
	u     core.User
	fresh bool
	path  string
}

func (a *acct) render(status int, errMsg string, d acctData) {
	d.NeedPassword = !a.fresh
	a.p.mfaPage(a.w, a.r, a.rl, a.path, status, "Two-step verification", errMsg, acctBody, d)
}

func (a *acct) fail500(what string, err error) {
	a.p.cfg.Logger.Error("oidc: account totp "+what, "err", err)
	a.p.errorPage(a.w, http.StatusInternalServerError, mfaTemporary)
}

// status renders the current state (never a secret or codes).
func (a *acct) status(info, errMsg string, code int) {
	ctx := a.r.Context()
	d := acctData{State: "off", Info: info}
	cred, err := a.st.GetTOTP(ctx, a.rl.Name, a.u.ID)
	switch {
	case err == nil && cred.Confirmed:
		n, cerr := a.st.CountRecoveryCodes(ctx, a.rl.Name, a.u.ID)
		if cerr != nil {
			a.fail500("count", cerr)
			return
		}
		d.State, d.Remaining = "on", n
	case err == nil:
		d.State = "pending"
	case !isNotFound(err):
		a.fail500("load", err)
		return
	}
	if pol, perr := a.st.GetMFAPolicy(ctx, a.rl.Name); perr == nil {
		d.Required = pol.RequireMFA
	}
	a.render(code, errMsg, d)
}

// needFresh checks the password when the session is not recent. It reports
// whether the action may proceed; otherwise it has already responded.
func (a *acct) needFresh() bool {
	if a.fresh {
		return true
	}
	p := a.p
	pw := a.r.PostForm.Get("password")
	ok, err := p.cfg.Store.HitRateLimit(a.r.Context(), hexKey("mfa-pw", a.rl.Name, a.u.ID), p.now(), mfaWindow, mfaUserMax)
	if err != nil {
		a.fail500("rate limit", err)
		return false
	}
	if !ok {
		a.status("", mfaLimited, http.StatusTooManyRequests)
		return false
	}
	good := false
	if a.u.PasswordHash != "" && len(pw) <= 1024 {
		good, _ = p.cfg.Hasher.Verify(pw, a.u.PasswordHash)
	}
	if !good {
		a.p.mfaEvent(a.r, a.rl, "MFA_FAILED", a.u.ID, "", "reauth")
		a.status("", "Wrong password.", http.StatusOK)
		return false
	}
	return true
}

func (a *acct) start() {
	if !a.needFresh() {
		return
	}
	ctx := a.r.Context()
	if cred, err := a.st.GetTOTP(ctx, a.rl.Name, a.u.ID); err == nil && cred.Confirmed {
		a.status("", "Two-step verification is already on. Turn it off first to set it up again.", http.StatusOK)
		return
	}
	seed, err := a.p.newEnrollment(a.r, a.st, a.rl.Name, a.u.ID)
	if err != nil {
		a.fail500("start", err)
		return
	}
	a.render(http.StatusOK, "", acctData{State: "pending", Secret: totp.EncodeSeed(seed),
		URI: totp.URI(a.p.issuerName(a.rl), a.u.Username, seed)})
}

func (a *acct) confirm() {
	p, ctx := a.p, a.r.Context()
	cred, err := a.st.GetTOTP(ctx, a.rl.Name, a.u.ID)
	if err != nil || cred.Confirmed {
		if err != nil && !isNotFound(err) {
			a.fail500("load", err)
			return
		}
		a.status("", "There is no setup in progress.", http.StatusOK)
		return
	}
	seed, err := p.openSeed(cred)
	if err != nil {
		a.fail500("open seed", err)
		return
	}
	allowed, err := p.mfaThrottle(a.r, a.rl.Name, a.u.ID, "enroll")
	if err != nil {
		a.fail500("rate limit", err)
		return
	}
	if !allowed {
		a.status("", mfaLimited, http.StatusTooManyRequests)
		return
	}
	input := a.r.PostForm.Get("code")
	if len(input) > mfaMaxInput {
		input = input[:mfaMaxInput]
	}
	step, good := totp.Verify(seed, input, p.now(), 0)
	if !good {
		p.mfaEvent(a.r, a.rl, "MFA_FAILED", a.u.ID, "", "invalid_code")
		// Re-show the secret so the user can still finish this enrollment.
		a.render(http.StatusOK, mfaGeneric, acctData{State: "pending", Secret: totp.EncodeSeed(seed),
			URI: totp.URI(p.issuerName(a.rl), a.u.Username, seed)})
		return
	}
	won, err := a.st.ConfirmTOTP(ctx, a.rl.Name, a.u.ID, step)
	if err != nil {
		a.fail500("confirm", err)
		return
	}
	if !won {
		a.status("", "There is no setup in progress.", http.StatusOK)
		return
	}
	codes, err := p.issueRecoveryCodes(a.r, a.st, a.rl.Name, a.u.ID)
	if err != nil {
		a.fail500("recovery codes", err)
		return
	}
	p.mfaEvent(a.r, a.rl, "TOTP_ENROLLED", a.u.ID, "", "account")
	a.render(http.StatusOK, "", acctData{State: "on", Codes: codes})
}

// verifyCurrent checks the code field against the confirmed credential. It
// reports whether the action may proceed; otherwise it has already responded.
func (a *acct) verifyCurrent(cred core.TOTPCredential) bool {
	res, method := a.p.mfaCheck(a.r, a.st, a.rl, cred, a.r.PostForm.Get("code"))
	switch res {
	case mfaOK:
		if method == "recovery" {
			a.p.mfaEvent(a.r, a.rl, "RECOVERY_USED", a.u.ID, "", "account")
		}
		return true
	case mfaBad:
		a.p.mfaEvent(a.r, a.rl, "MFA_FAILED", a.u.ID, "", "invalid_code")
		a.status("", mfaGeneric, http.StatusOK)
	case mfaDenied:
		a.status("", mfaLimited, http.StatusTooManyRequests)
	default:
		a.p.errorPage(a.w, http.StatusInternalServerError, mfaTemporary)
	}
	return false
}

func (a *acct) disable() {
	if !a.needFresh() {
		return
	}
	ctx := a.r.Context()
	cred, err := a.st.GetTOTP(ctx, a.rl.Name, a.u.ID)
	if err != nil && !isNotFound(err) {
		a.fail500("load", err)
		return
	}
	wasOn := err == nil && cred.Confirmed
	if wasOn && !a.verifyCurrent(cred) {
		return
	}
	// An unfinished enrollment can be cancelled without a code.
	if err := a.st.DeleteUserMFA(ctx, a.rl.Name, a.u.ID); err != nil {
		a.fail500("delete", err)
		return
	}
	if wasOn {
		a.p.mfaEvent(a.r, a.rl, "TOTP_DISABLED", a.u.ID, "", "account")
	}
	a.status("Two-step verification is off.", "", http.StatusOK)
}

func (a *acct) regenerate() {
	if !a.needFresh() {
		return
	}
	ctx := a.r.Context()
	cred, err := a.st.GetTOTP(ctx, a.rl.Name, a.u.ID)
	if err != nil || !cred.Confirmed {
		if err != nil && !isNotFound(err) {
			a.fail500("load", err)
			return
		}
		a.status("", "Two-step verification is not on.", http.StatusOK)
		return
	}
	if !a.verifyCurrent(cred) {
		return
	}
	codes, err := a.p.issueRecoveryCodes(a.r, a.st, a.rl.Name, a.u.ID)
	if err != nil {
		a.fail500("recovery codes", err)
		return
	}
	a.p.mfaEvent(a.r, a.rl, "RECOVERY_REGENERATED", a.u.ID, "", "account")
	a.render(http.StatusOK, "", acctData{State: "on", Codes: codes})
}
