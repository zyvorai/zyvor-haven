// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/password"
)

const (
	forgotLimit  = 10 // requests per IP per window
	forgotWindow = 10 * time.Minute
	mailTimeout  = 30 * time.Second
	invalidLink  = "This link is invalid or has expired. Request a new one."
)

// limiter is a small per-key sliding-window counter.
type limiter struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

func (l *limiter) allow(key string, now time.Time, max int, win time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil || len(l.m) > 10000 {
		l.m = map[string][]time.Time{}
	}
	keep := l.m[key][:0]
	for _, t := range l.m[key] {
		if now.Sub(t) < win {
			keep = append(keep, t)
		}
	}
	if len(keep) >= max {
		l.m[key] = keep
		return false
	}
	l.m[key] = append(keep, now)
	return true
}

func (p *Provider) actionsOn() bool { return p.cfg.Actions.Enabled() }

func (p *Provider) forgotURL(realm string) string {
	if !p.actionsOn() {
		return ""
	}
	return p.base + "/realms/" + url.PathEscape(realm) + "/login-actions/forgot-password"
}

// Drain waits for in-flight background emails. Tests and shutdown use it.
func (p *Provider) Drain() { p.bg.Wait() }

// sendAsync emails an action link without making the HTTP response depend on
// whether (or how fast) mail was sent. It reports whether a send was started.
func (p *Provider) sendAsync(rl core.Realm, u core.User, purpose string) bool {
	if !p.actionsOn() || u.Email == "" || !u.Enabled {
		return false
	}
	p.bg.Add(1)
	go func() {
		defer p.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), mailTimeout)
		defer cancel()
		err := p.cfg.Actions.Send(ctx, rl, u, purpose, actions.SendOpts{})
		switch {
		case err == nil:
		case errors.Is(err, actions.ErrRateLimited):
			p.cfg.Logger.Info("oidc: action email rate limited", "realm", rl.Name, "purpose", purpose)
		default:
			p.cfg.Logger.Error("oidc: action email failed", "realm", rl.Name, "purpose", purpose, "err", err)
		}
	}()
	return true
}

func (p *Provider) actionBase(rl string) string {
	return p.base + "/realms/" + url.PathEscape(rl) + "/login-actions"
}

func (p *Provider) actionCookiePath(rl string) string { return "/realms/" + rl + "/login-actions" }

// actionPage renders a login-actions form with a fresh CSRF token.
func (p *Provider) actionPage(w http.ResponseWriter, rl core.Realm, status int, form, title, msg, errMsg, token string) {
	csrf := p.newCSRF(rl.Name)
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: p.actionCookiePath(rl.Name),
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	nonce := randToken(16)
	p.pageHeaders(w, nonce)
	w.WriteHeader(status)
	slug := map[string]string{"forgot": "forgot-password", "reset": "reset-password", "verify": "verify-email"}[form]
	_ = pageTmpl.Execute(w, pageData{Title: title, Nonce: nonce, Form: form, Message: msg, Error: errMsg,
		Token: token, CSRF: csrf, Action: p.actionBase(rl.Name) + "/" + slug})
}

func (p *Provider) checkActionCSRF(r *http.Request, realm string) bool {
	if r.ParseForm() != nil {
		return false
	}
	form := r.PostForm.Get("csrf")
	ck, err := r.Cookie(csrfCookie)
	return err == nil && form != "" && hmac.Equal([]byte(ck.Value), []byte(form)) && p.checkCSRF(realm, form)
}

// gate loads the realm and 404s when email flows are off.
func (p *Provider) gate(w http.ResponseWriter, r *http.Request) (core.Realm, bool) {
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok || !p.actionsOn() {
		p.errorPage(w, http.StatusNotFound, "Not found.")
		return core.Realm{}, false
	}
	return rl, true
}

func (p *Provider) findForReset(ctx context.Context, realm, id string) (core.User, bool) {
	u, err := p.cfg.Store.GetUserByUsername(ctx, realm, id)
	if err == nil {
		return u, true
	}
	if !errors.Is(err, idp.ErrNotFound) {
		p.cfg.Logger.Error("oidc: forgot-password lookup", "err", err)
		return core.User{}, false
	}
	if !strings.Contains(id, "@") {
		return core.User{}, false
	}
	us, err := p.cfg.Store.ListUsers(ctx, realm, id, 0, 50)
	if err != nil {
		return core.User{}, false
	}
	var hit []core.User
	for _, c := range us {
		if strings.EqualFold(c.Email, id) {
			hit = append(hit, c)
		}
	}
	if len(hit) != 1 { // ambiguous addresses are never guessed at
		return core.User{}, false
	}
	return hit[0], true
}

const sentMsg = "If an account matches, we sent a password reset link to its email address. The link is valid for one hour."

func (p *Provider) forgotPassword(w http.ResponseWriter, r *http.Request) {
	rl, ok := p.gate(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		p.actionPage(w, rl, http.StatusOK, "forgot", "Reset your password",
			"Enter your username or email address and we will send you a link.", "", "")
		return
	}
	if !p.checkActionCSRF(r, rl.Name) {
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Go back and try again.")
		return
	}
	ctx := r.Context()
	ip := p.clientIP(r)
	id := strings.TrimSpace(r.PostForm.Get("username"))
	// Same answer whatever happens below: this page must not reveal which
	// accounts exist, are enabled, or were rate limited.
	done := func() { p.simplePage(w, http.StatusOK, "Check your email", sentMsg) }
	if id == "" || len(id) > 256 || !p.forgot.allow(ip, p.now(), forgotLimit, forgotWindow) {
		done()
		return
	}
	if u, found := p.findForReset(ctx, rl.Name, id); found {
		if p.sendAsync(rl, u, core.ActionResetPassword) {
			p.event(ctx, rl, "RESET_PASSWORD_REQUEST", u.ID, "", ip, "")
		}
	}
	done()
}

func (p *Provider) resetPassword(w http.ResponseWriter, r *http.Request) {
	rl, ok := p.gate(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		// A GET never consumes the token: mail scanners and link previewers
		// fetch URLs before the human does.
		tok := r.URL.Query().Get("token")
		if tok == "" || len(tok) > 256 {
			p.errorPage(w, http.StatusBadRequest, invalidLink)
			return
		}
		p.actionPage(w, rl, http.StatusOK, "reset", "Choose a new password", "", "", tok)
		return
	}
	if !p.checkActionCSRF(r, rl.Name) {
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Go back and try again.")
		return
	}
	ctx := r.Context()
	tok := r.PostForm.Get("token")
	pw, confirm := r.PostForm.Get("password"), r.PostForm.Get("confirm")
	again := func(msg string) {
		p.actionPage(w, rl, http.StatusOK, "reset", "Choose a new password", "", msg, tok)
	}
	// Validate before redeeming so a typo does not burn the link.
	switch {
	case pw == "" || len(pw) > 1024:
		again("Enter a new password.")
		return
	case pw != confirm:
		again("The two passwords do not match.")
		return
	}
	if err := password.CheckPolicy(rl.PasswordPolicy, pw); err != nil {
		again("That password is not allowed: " + err.Error())
		return
	}
	_, u, err := p.cfg.Actions.Redeem(ctx, rl.Name, tok, core.ActionResetPassword)
	if err != nil {
		if errors.Is(err, actions.ErrInvalidToken) {
			p.errorPage(w, http.StatusBadRequest, invalidLink)
			return
		}
		p.cfg.Logger.Error("oidc: redeem reset token", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	h, err := p.cfg.Hasher.Hash(pw)
	if err != nil {
		p.cfg.Logger.Error("oidc: hash new password", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Request a new link.")
		return
	}
	u.PasswordHash = h
	u.FailedLogins, u.LockedUntil = 0, time.Time{}
	u.EmailVerified = true // the link went to the address on file, so it is proven
	u.PendingActions = slices.DeleteFunc(slices.Clone(u.PendingActions), func(a string) bool {
		return a == "UPDATE_PASSWORD" || a == "VERIFY_EMAIL"
	})
	if err := p.cfg.Store.UpdateUser(ctx, u); err != nil {
		p.cfg.Logger.Error("oidc: save reset password", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Request a new link.")
		return
	}
	// A reset means the old password may be compromised: end every session
	// that could have been obtained with it, and any other pending links.
	if _, err := p.cfg.Store.RevokeUserRefreshTokens(ctx, rl.Name, u.ID); err != nil {
		p.cfg.Logger.Error("oidc: revoke after reset", "err", err)
	}
	_, _ = p.cfg.Store.DeleteActionTokens(ctx, rl.Name, u.ID, core.ActionResetPassword)
	p.event(ctx, rl, "RESET_PASSWORD", u.ID, "", p.clientIP(r), "")
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: p.actionCookiePath(rl.Name), MaxAge: -1})
	p.simplePage(w, http.StatusOK, "Password updated",
		"Your password was changed and all other sessions were signed out. Return to the application and sign in.")
}

func (p *Provider) verifyEmail(w http.ResponseWriter, r *http.Request) {
	rl, ok := p.gate(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		tok := r.URL.Query().Get("token")
		if tok == "" || len(tok) > 256 {
			p.errorPage(w, http.StatusBadRequest, invalidLink)
			return
		}
		p.actionPage(w, rl, http.StatusOK, "verify", "Confirm your email address",
			"Press the button to confirm this email address for your account.", "", tok)
		return
	}
	if !p.checkActionCSRF(r, rl.Name) {
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Go back and try again.")
		return
	}
	ctx := r.Context()
	t, u, err := p.cfg.Actions.Redeem(ctx, rl.Name, r.PostForm.Get("token"), core.ActionVerifyEmail)
	if err != nil {
		if errors.Is(err, actions.ErrInvalidToken) {
			p.errorPage(w, http.StatusBadRequest, invalidLink)
			return
		}
		p.cfg.Logger.Error("oidc: redeem verify token", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	_ = t
	u.EmailVerified = true
	u.PendingActions = slices.DeleteFunc(slices.Clone(u.PendingActions), func(a string) bool { return a == "VERIFY_EMAIL" })
	if err := p.cfg.Store.UpdateUser(ctx, u); err != nil {
		p.cfg.Logger.Error("oidc: save verified email", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Request a new link.")
		return
	}
	p.event(ctx, rl, "VERIFY_EMAIL", u.ID, "", p.clientIP(r), "")
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: p.actionCookiePath(rl.Name), MaxAge: -1})
	p.simplePage(w, http.StatusOK, "Email confirmed", "Your email address is confirmed. Return to the application and sign in.")
}
