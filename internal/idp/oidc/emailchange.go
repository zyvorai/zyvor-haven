// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Self-service email change.
//
//	GET/POST /realms/{realm}/account/email                       request a change
//	GET/POST /realms/{realm}/login-actions/confirm-email-change  open the link sent to the NEW address
//
// Requesting needs a live SSO session of an enabled user, a CSRF token and the
// account password EVERY time (a recent login is not enough: the address
// decides where password-reset links go). The account address does not change
// until the link sent to the new address is confirmed. The old address gets a
// notice when the change is requested and again when it is applied. The page
// gives the same answer whether or not the new address is already in use by
// another account. Off (404) when email is not configured.

const (
	ecSendMax    = 3 // change requests per user per window
	ecSendWindow = time.Hour
	ecSentMsg    = "If that address can be used, we sent a confirmation link to it. Your email address does not change until you open that link. The link is valid for 2 hours."
)

func init() {
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		mux.HandleFunc("GET /realms/{realm}/account/email", p.accountEmail)
		mux.HandleFunc("POST /realms/{realm}/account/email", p.accountEmail)
		mux.HandleFunc("GET /realms/{realm}/login-actions/confirm-email-change", p.confirmEmailChange)
		mux.HandleFunc("POST /realms/{realm}/login-actions/confirm-email-change", p.confirmEmailChange)
	})
}

type ecData struct {
	Current string
	Info    string
	Token   string
	Done    bool
}

const ecBody = `{{with .Data}}{{if .Done}}<p class="sub">{{.Info}}</p>
{{else}}{{if .Info}}<p class="sub">{{.Info}}</p>{{end}}<p>Current address: <strong>{{if .Current}}{{.Current}}{{else}}none{{end}}</strong></p>
<form method="post" action="{{$.Action}}" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}">
<label for="ne">New email address</label><input id="ne" name="email" type="email" autocomplete="email" required maxlength="254">
<label for="pw">Password (to confirm it is you)</label><input id="pw" name="password" type="password" autocomplete="current-password" required maxlength="1024">
<button type="submit">Send confirmation link</button></form>
{{end}}{{end}}`

const ecConfirmBody = `{{with .Data}}<p class="sub">Press the button to make this your new email address.</p>
<form method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="token" value="{{.Token}}">
<button type="submit">Confirm new email address</button></form>{{end}}`

func (p *Provider) accountEmail(w http.ResponseWriter, r *http.Request) {
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return
	}
	if !p.actionsOn() {
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
			p.cfg.Logger.Error("oidc: email change load user", "err", err)
		}
		p.errorPage(w, http.StatusForbidden, "Sign in first, then open this page again.")
		return
	}
	path := "/realms/" + rl.Name + "/account/email"
	show := func(status int, errMsg, info string) {
		p.mfaPage(w, r, rl, path, status, "Change email address", errMsg, ecBody, ecData{Current: u.Email, Info: info})
	}
	if r.Method == http.MethodGet {
		show(http.StatusOK, "", "")
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
	// Password attempts: per user and per IP, both always counted, fail closed.
	now := p.now()
	userOK, err1 := p.cfg.Store.HitRateLimit(ctx, hexKey("emailchange-pw", rl.Name, u.ID), now, mfaWindow, mfaUserMax)
	ipOK, err2 := p.cfg.Store.HitRateLimit(ctx, hexKey("emailchange-ip", rl.Name, p.clientIP(r)), now, mfaWindow, mfaIPMax)
	if err1 != nil || err2 != nil {
		p.cfg.Logger.Error("oidc: email change rate limit", "err", errors.Join(err1, err2))
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return
	}
	if !userOK || !ipOK {
		show(http.StatusTooManyRequests, mfaLimited, "")
		return
	}
	pw := r.PostForm.Get("password")
	good := false
	if u.PasswordHash != "" && pw != "" && len(pw) <= 1024 {
		good, _ = p.cfg.Hasher.Verify(pw, u.PasswordHash)
	}
	if !good {
		p.event(ctx, rl, "UPDATE_EMAIL_ERROR", u.ID, "", p.clientIP(r), "reauth")
		show(http.StatusOK, "Wrong password.", "")
		return
	}
	newEmail, err := actions.ValidateNewEmail(r.PostForm.Get("email"))
	if err != nil {
		show(http.StatusOK, "Enter a valid email address.", "")
		return
	}
	if strings.EqualFold(newEmail, strings.TrimSpace(u.Email)) {
		show(http.StatusOK, "That is already your email address.", "")
		return
	}
	sendOK, err := p.cfg.Store.HitRateLimit(ctx, hexKey("emailchange-send", rl.Name, u.ID), now, ecSendWindow, ecSendMax)
	if err != nil {
		p.cfg.Logger.Error("oidc: email change send limit", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return
	}
	if !sendOK {
		show(http.StatusTooManyRequests, mfaLimited, "")
		return
	}
	// Same page whether the address is free, taken, or delivery fails later.
	taken := p.emailTaken(ctx, rl.Name, u.ID, newEmail)
	p.event(ctx, rl, "UPDATE_EMAIL_REQUEST", u.ID, "", p.clientIP(r), "")
	if !taken {
		p.bg.Add(1)
		go func(rl core.Realm, u core.User) {
			defer p.bg.Done()
			bctx, cancel := context.WithTimeout(context.Background(), mailTimeout)
			defer cancel()
			if err := p.cfg.Actions.SendEmailChange(bctx, rl, u, newEmail); err != nil {
				p.cfg.Logger.Error("oidc: email change link failed", "realm", rl.Name, "user", u.ID, "err", err)
				return
			}
			if strings.TrimSpace(u.Email) != "" {
				if err := p.cfg.Actions.NotifyEmailChange(bctx, rl, u.Email, u.Username, newEmail, false); err != nil {
					p.cfg.Logger.Error("oidc: email change notice failed", "realm", rl.Name, "user", u.ID, "err", err)
				}
			}
		}(rl, u)
	} else {
		p.cfg.Logger.Info("oidc: email change refused: address in use", "realm", rl.Name, "user", u.ID)
	}
	p.mfaPage(w, r, rl, path, http.StatusOK, "Check your email", "", ecBody, ecData{Done: true, Info: ecSentMsg})
}

// emailTaken reports whether another account of the realm uses the address
// (case-insensitive). A lookup error counts as taken: fail closed.
func (p *Provider) emailTaken(ctx context.Context, realm, selfID, email string) bool {
	us, err := p.cfg.Store.ListUsers(ctx, realm, email, 0, 50)
	if err != nil {
		p.cfg.Logger.Error("oidc: email change duplicate check", "err", err)
		return true
	}
	for _, c := range us {
		if c.ID != selfID && strings.EqualFold(strings.TrimSpace(c.Email), email) {
			return true
		}
	}
	return false
}

func (p *Provider) confirmEmailChange(w http.ResponseWriter, r *http.Request) {
	rl, ok := p.gate(w, r)
	if !ok {
		return
	}
	path := "/realms/" + rl.Name + "/login-actions/confirm-email-change"
	if r.Method == http.MethodGet {
		// A GET never consumes the link (mail scanners prefetch URLs).
		tok := r.URL.Query().Get("token")
		if tok == "" || len(tok) > 256 {
			p.errorPage(w, http.StatusBadRequest, invalidLink)
			return
		}
		p.mfaPage(w, r, rl, path, http.StatusOK, "Confirm new email address", "", ecConfirmBody, ecData{Token: tok})
		return
	}
	if err := r.ParseForm(); err != nil || !p.checkFormCSRF(r, rl.Name) {
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Go back and try again.")
		return
	}
	ctx := r.Context()
	newEmail, u, err := p.cfg.Actions.RedeemEmailChange(ctx, rl.Name, r.PostForm.Get("token"))
	if err != nil {
		if errors.Is(err, actions.ErrInvalidToken) {
			p.errorPage(w, http.StatusBadRequest, invalidLink)
			return
		}
		p.cfg.Logger.Error("oidc: redeem email change", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return
	}
	if p.emailTaken(ctx, rl.Name, u.ID, newEmail) {
		p.errorPage(w, http.StatusBadRequest, invalidLink)
		return
	}
	oldEmail := u.Email
	u.Email = newEmail
	u.EmailVerified = true // the link went to the new address, so it is proven
	u.PendingActions = slices.DeleteFunc(slices.Clone(u.PendingActions), func(a string) bool { return a == "VERIFY_EMAIL" })
	if err := p.cfg.Store.UpdateUser(ctx, u); err != nil {
		p.cfg.Logger.Error("oidc: save new email", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Request a new link.")
		return
	}
	// Links bound to the old address (and other pending changes) are dead.
	for _, purpose := range []string{core.ActionVerifyEmail, core.ActionResetPassword, actions.ActionChangeEmail} {
		if _, err := p.cfg.Store.DeleteActionTokens(ctx, rl.Name, u.ID, purpose); err != nil {
			p.cfg.Logger.Error("oidc: clear links after email change", "purpose", purpose, "err", err)
		}
	}
	p.event(ctx, rl, "UPDATE_EMAIL", u.ID, "", p.clientIP(r), "")
	if strings.TrimSpace(oldEmail) != "" {
		p.bg.Add(1)
		go func(rl core.Realm) {
			defer p.bg.Done()
			bctx, cancel := context.WithTimeout(context.Background(), mailTimeout)
			defer cancel()
			if err := p.cfg.Actions.NotifyEmailChange(bctx, rl, oldEmail, u.Username, newEmail, true); err != nil {
				p.cfg.Logger.Error("oidc: email change notice failed", "realm", rl.Name, "user", u.ID, "err", err)
			}
		}(rl)
	}
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: path, MaxAge: -1})
	p.simplePage(w, http.StatusOK, "Email address changed", "Your email address was changed. Account email now goes to the new address.")
}
