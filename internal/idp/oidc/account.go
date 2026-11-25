// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/http"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// The account console (docs/account-console.md):
//
//	GET      /realms/{realm}/account               overview
//	GET/POST /realms/{realm}/account/sessions      SSO sessions, sign out
//	GET/POST /realms/{realm}/account/devices       devices known to step-up
//	GET      /realms/{realm}/account/security      password, email, 2FA, passkeys
//	GET/POST /realms/{realm}/account/password      change the password
//	GET/POST /realms/{realm}/account/applications  consents, revoke
//	GET/POST /realms/{realm}/account/agents        own agents, revoke credentials
//	GET      /realms/{realm}/account/activity      own security events
//
// Rules every request passes through, in acctHandle:
//
//   - a live SSO session of an enabled user (and a verified email when the
//     realm demands one). The user id used everywhere comes from that session
//     and from nowhere else: no parameter names a user;
//   - every id in a form is looked up and checked against that user; somebody
//     else's id answers exactly like a missing one;
//   - POSTs are rate limited and carry a CSRF token bound to the session;
//   - every change needs a recent authentication (acctFresh): the session's own
//     login, or a confirmation on this page bound to this session. Changing the
//     password additionally needs the current password in the form;
//   - responses are no-store.
//
// The console is off (404) when the store has no core.AccountStore.

const (
	acctCSRFCookie    = "haven_acct_csrf"
	acctReauthCookie  = "haven_acct_reauth" // #nosec G101 -- cookie name, not a credential
	acctReauthPurpose = "acct-reauth"
	acctFresh         = mfaFreshAuth

	acctGetWindow   = time.Minute
	acctGetUserMax  = 120
	acctPostWindow  = 10 * time.Minute
	acctPostUserMax = 30
	acctPostIPMax   = 60

	acctSignInFirst = "Sign in to an application of this realm first, then open your account again."
	acctSlowDown    = "Too many requests. Wait a few minutes and try again."
	acctNeedRecent  = "Confirm it is you before making changes: your sign-in is older than 10 minutes."
	acctBadForm     = "Your session expired or the request was invalid. Go back and try again."
)

type acctPageDef struct {
	slug, title, nav string // nav: label in the menu; "" = not listed
	post             bool
	on               func(p *Provider) bool // nil = always
}

var acctPages = []acctPageDef{
	{slug: "", title: "Overview", nav: "Overview"},
	{slug: "sessions", title: "Active sessions", nav: "Sessions", post: true},
	{slug: "devices", title: "Known devices", nav: "Devices", post: true,
		on: func(p *Provider) bool { _, ok := p.stepUpStore(); return ok }},
	{slug: "security", title: "Sign-in and security", nav: "Security"},
	{slug: "password", title: "Change password", post: true},
	{slug: "applications", title: "Applications with access", nav: "Applications", post: true,
		on: func(p *Provider) bool { _, ok := p.consentStore(); return ok }},
	{slug: "agents", title: "Agent identities", nav: "Agents", post: true,
		on: func(p *Provider) bool { _, ok := core.StoreAs[core.AgentStore](p.cfg.Store); return ok }},
	{slug: "activity", title: "Recent security activity", nav: "Activity"},
}

func accountPath(realm, slug string) string {
	if slug == "" {
		return "/realms/" + realm + "/account"
	}
	return "/realms/" + realm + "/account/" + slug
}

func (p *Provider) accountStore() (core.AccountStore, bool) {
	return core.StoreAs[core.AccountStore](p.cfg.Store)
}

// accountLink is the console's path for links on other pages, "" when it is off.
func (p *Provider) accountLink(realm string) string {
	if _, ok := p.accountStore(); !ok {
		return ""
	}
	return accountPath(realm, "")
}

func init() {
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		for _, def := range acctPages {
			pattern := "/realms/{realm}/account"
			if def.slug != "" {
				pattern += "/" + def.slug
			}
			h := func(w http.ResponseWriter, r *http.Request) { p.acctHandle(w, r, def) }
			mux.HandleFunc("GET "+pattern, h)
			if def.post {
				mux.HandleFunc("POST "+pattern, h)
			}
		}
	})
}

// console is one authenticated request of the account console.
type console struct {
	p      *Provider
	w      http.ResponseWriter
	r      *http.Request
	rl     core.Realm
	st     core.AccountStore
	def    acctPageDef
	sess   core.Session
	u      core.User
	recent bool
	// reauth says how this user can confirm their identity on the page.
	reauth acctReauthMode
}

type acctReauthMode struct {
	Password bool // a password confirmation is possible
	Code     bool // and it also needs a two-step code
}

// acctLimit counts one hit and reports whether it is allowed. Store errors are
// logged and count as "not allowed".
func (p *Provider) acctLimit(ctx context.Context, window time.Duration, max int, parts ...string) (allowed, broken bool) {
	ok, err := p.cfg.Store.HitRateLimit(ctx, hexKey(parts...), p.now(), window, max)
	if err != nil {
		p.cfg.Logger.Error("oidc: account rate limit", "err", err)
		return false, true
	}
	return ok, false
}

func (p *Provider) acctHandle(w http.ResponseWriter, r *http.Request, def acctPageDef) {
	noStore(w)
	ctx := r.Context()
	rl, ok := p.realm(ctx, r.PathValue("realm"))
	if !ok {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return
	}
	st, ok := p.accountStore()
	if !ok || (def.on != nil && !def.on(p)) {
		p.errorPage(w, http.StatusNotFound, "Not found.")
		return
	}
	limited := func(broken bool) {
		if broken {
			p.errorPage(w, http.StatusServiceUnavailable, mfaTemporary)
			return
		}
		w.Header().Set("Retry-After", "600")
		p.errorPage(w, http.StatusTooManyRequests, acctSlowDown)
	}
	post := r.Method == http.MethodPost
	if post {
		if allowed, broken := p.acctLimit(ctx, acctPostWindow, acctPostIPMax, "acct-post-ip", rl.Name, p.clientIP(r)); !allowed {
			limited(broken)
			return
		}
	}
	sess, ok := p.currentSession(r, rl)
	if !ok {
		p.simplePage(w, http.StatusUnauthorized, "Your account", acctSignInFirst)
		return
	}
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, sess.UserID)
	if err != nil || u.ID == "" || u.ID != sess.UserID || !u.Enabled || (rl.EmailVerificationRequired && !u.EmailVerified) {
		if err != nil && !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: account load user", "err", err)
			p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
			return
		}
		p.simplePage(w, http.StatusForbidden, "Your account", acctSignInFirst)
		return
	}
	window, max, purpose := acctGetWindow, acctGetUserMax, "acct-get-user"
	if post {
		window, max, purpose = acctPostWindow, acctPostUserMax, "acct-post-user"
	}
	if allowed, broken := p.acctLimit(ctx, window, max, purpose, rl.Name, u.ID); !allowed {
		limited(broken)
		return
	}
	c := &console{p: p, w: w, r: r, rl: rl, st: st, def: def, sess: sess, u: u}
	if c.reauth, err = c.reauthMode(); err != nil {
		c.fail("re-authentication options", err)
		return
	}
	c.recent = p.acctRecent(r, rl, sess, u)

	if !post {
		c.render(http.StatusOK, acctMessages[r.URL.Query().Get("m")], "")
		return
	}
	if err := r.ParseForm(); err != nil {
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	if !p.checkAcctCSRF(r, rl.Name, sess.ID) {
		p.errorPage(w, http.StatusForbidden, acctBadForm)
		return
	}
	action := r.PostForm.Get("action")
	if action == "reauth" {
		c.doReauth()
		return
	}
	// Everything else changes something: recent authentication first.
	if !c.recent {
		c.event("ACCOUNT_ACTION_ERROR", "", "reauth_required")
		c.render(http.StatusForbidden, "", acctNeedRecent)
		return
	}
	switch def.slug + "/" + action {
	case "sessions/revoke":
		c.revokeSession()
	case "sessions/revoke-others":
		c.revokeOtherSessions()
	case "devices/forget":
		c.forgetDevice()
	case "devices/forget-all":
		c.forgetAllDevices()
	case "password/change":
		c.changePassword()
	case "applications/revoke":
		c.revokeApp()
	case "agents/revoke":
		c.revokeCredential()
	case "agents/revoke-all":
		c.revokeAllCredentials()
	default:
		c.render(http.StatusBadRequest, "", "Unknown action.")
	}
}

var acctMessages = map[string]string{ // #nosec G101 -- fixed status texts shown on the account pages, no credentials
	"reauth":   "Confirmed. You can make changes for the next 10 minutes.",
	"session":  "That session was signed out.",
	"sessions": "All your other sessions were signed out.",
	"device":   "Device forgotten.",
	"devices":  "All devices were forgotten.",
	"app":      "Access revoked. The application can no longer refresh its tokens; access tokens it already holds expire within minutes.",
	"cred":     "Credential revoked. Access tokens already issued with it expire within minutes.",
	"creds":    "All active credentials of that agent were revoked. Access tokens already issued expire within minutes.",
	"password": "Password changed. Your other sessions were signed out and applications must ask for new tokens.",
}

// checkAcctCSRF is a double-submit check whose token is also bound to the SSO
// session: a token minted for another session never validates.
func (p *Provider) checkAcctCSRF(r *http.Request, realm, sessionID string) bool {
	form := r.PostForm.Get("csrf")
	ck, err := r.Cookie(acctCSRFCookie)
	return err == nil && form != "" && hmac.Equal([]byte(ck.Value), []byte(form)) &&
		p.checkCSRF(acctCSRFScope(realm, sessionID), form)
}

func acctCSRFScope(realm, sessionID string) string { return realm + "|account|" + sessionID }

// acctRecent reports whether the user authenticated within acctFresh: the SSO
// session's own login, or a confirmation on this page for this very session.
func (p *Provider) acctRecent(r *http.Request, rl core.Realm, sess core.Session, u core.User) bool {
	if p.now().Sub(sess.AuthTime) < acctFresh {
		return true
	}
	ck, err := r.Cookie(acctReauthCookie)
	if err != nil {
		return false
	}
	uid, payload, ok := p.checkPending(rl.Name, ck.Value, acctReauthPurpose)
	return ok && uid == u.ID && payload == sess.ID
}

// reauthMode: a confirmation on the page must not be weaker than signing in.
// A user with a passkey (or without a password) has to sign in again; a user
// with TOTP must give a code along with the password.
func (c *console) reauthMode() (acctReauthMode, error) {
	var m acctReauthMode
	if c.u.PasswordHash == "" {
		return m, nil
	}
	ctx := c.r.Context()
	if pst, _, on := c.p.passkeys(); on {
		creds, err := pst.ListPasskeys(ctx, c.rl.Name, c.u.ID)
		if err != nil {
			return m, err
		}
		if len(creds) > 0 {
			return m, nil
		}
	}
	m.Password = true
	if mst, on := c.p.mfaStore(); on {
		cred, err := mst.GetTOTP(ctx, c.rl.Name, c.u.ID)
		switch {
		case err == nil:
			m.Code = cred.Confirmed
		case !errors.Is(err, idp.ErrNotFound):
			return acctReauthMode{}, err
		}
	}
	return m, nil
}

// checkPassword verifies the current password under the shared attempt limits.
// It reports whether the caller may go on; otherwise it has responded. The
// per-user counter is the one the two-step account page uses, so the pages do
// not each hand out their own budget of guesses.
func (c *console) checkPassword(pw, errType string) bool {
	p, ctx := c.p, c.r.Context()
	userOK, b1 := p.acctLimit(ctx, mfaWindow, mfaUserMax, "mfa-pw", c.rl.Name, c.u.ID)
	ipOK, b2 := p.acctLimit(ctx, mfaWindow, mfaIPMax, "acct-pw-ip", c.rl.Name, p.clientIP(c.r))
	if b1 || b2 {
		p.errorPage(c.w, http.StatusServiceUnavailable, mfaTemporary)
		return false
	}
	if !userOK || !ipOK {
		c.event(errType, "", "rate_limited")
		c.render(http.StatusTooManyRequests, "", mfaLimited)
		return false
	}
	locked := c.rl.BruteForceProtection && !c.u.LockedUntil.IsZero() && p.now().Before(c.u.LockedUntil)
	good := false
	if c.u.PasswordHash != "" && pw != "" && len(pw) <= 1024 && !locked {
		good, _ = p.cfg.Hasher.Verify(pw, c.u.PasswordHash)
	} else {
		p.cfg.Hasher.Verify(pw, p.dummy())
	}
	if !good {
		c.event(errType, "", "wrong_password")
		c.render(http.StatusForbidden, "", "That password is not correct.")
		return false
	}
	return true
}

func (c *console) doReauth() {
	p := c.p
	if !c.reauth.Password {
		c.event("ACCOUNT_REAUTH_ERROR", "", "sign_in_required")
		c.render(http.StatusForbidden, "", "A password alone cannot confirm it is you. Sign out and sign in again, then come back.")
		return
	}
	if !c.checkPassword(c.r.PostForm.Get("password"), "ACCOUNT_REAUTH_ERROR") {
		return
	}
	if c.reauth.Code {
		mst, on := p.mfaStore()
		if !on {
			p.errorPage(c.w, http.StatusServiceUnavailable, mfaTemporary)
			return
		}
		cred, err := mst.GetTOTP(c.r.Context(), c.rl.Name, c.u.ID)
		if err != nil || !cred.Confirmed {
			c.fail("load two-step credential", errors.Join(err, errors.New("credential changed")))
			return
		}
		switch res, method := p.mfaCheck(c.r, mst, c.rl, cred, c.r.PostForm.Get("code")); res {
		case mfaOK:
			if method == "recovery" {
				c.event("RECOVERY_USED", "", "account")
			}
		case mfaBad:
			c.event("ACCOUNT_REAUTH_ERROR", "", "invalid_code")
			c.render(http.StatusForbidden, "", mfaGeneric)
			return
		case mfaDenied:
			c.event("ACCOUNT_REAUTH_ERROR", "", "rate_limited")
			c.render(http.StatusTooManyRequests, "", mfaLimited)
			return
		default:
			p.errorPage(c.w, http.StatusInternalServerError, mfaTemporary)
			return
		}
	}
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(c.w, &http.Cookie{Name: acctReauthCookie,
		Value: p.signPending(c.rl.Name, c.u.ID, acctReauthPurpose, c.sess.ID, acctFresh),
		Path:  accountPath(c.rl.Name, ""), HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(acctFresh.Seconds())})
	c.event("ACCOUNT_REAUTH", "", "password")
	c.done("reauth")
}

// done redirects back to the current page with a fixed message code.
func (c *console) done(code string) {
	noStore(c.w)
	http.Redirect(c.w, c.r, accountPath(c.rl.Name, c.def.slug)+"?m="+code, http.StatusSeeOther) // #nosec G710 -- fixed in-realm account path and a code chosen by the handler, no user-supplied target
}

// event records an audit event of the signed-in user. detail is a fixed word or
// an identifier read from the store, never raw form input.
func (c *console) event(typ, clientID, detail string) {
	c.p.event(c.r.Context(), c.rl, typ, c.u.ID, clientID, c.p.clientIP(c.r), detail)
}

func (c *console) fail(what string, err error) {
	c.p.cfg.Logger.Error("oidc: account "+what, "realm", c.rl.Name, "err", err)
	c.p.errorPage(c.w, http.StatusInternalServerError, mfaTemporary)
}

// notFound answers an id that does not exist or is not the user's: the two are
// deliberately indistinguishable, and the id is not echoed or logged.
func (c *console) notFound(what string) {
	c.event("ACCOUNT_ACTION_ERROR", "", what+"_not_found")
	c.render(http.StatusNotFound, "", "That "+what+" was not found.")
}
