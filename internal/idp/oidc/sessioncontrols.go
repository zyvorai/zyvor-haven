// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"net/http"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/ssf"
)

// Session controls (docs/sso-and-logout.md): the realm's cap on concurrent
// sessions per user and the opt-in "keep me signed in" lifetime. Both are off
// until an administrator sets a session policy.

const (
	rememberCookie  = "haven_rm"
	rememberPurpose = "remember"
	rememberField   = "remember_me"
	rememberTTL     = csrfTTL

	// authOrderRemember is before every step that renders a page, but AFTER the
	// passkey-only refusal (authOrderPasskeyOnly): that answer must not carry a
	// cookie only a correct password produces.
	authOrderRemember = authOrderPasskeyOnly + 1

	maxPrecleanSessions = 1000
)

func init() { registerAuthStepAt(authOrderRemember, rememberStep, nil) }

// sessionPolicy returns the feature store (nil when the store has none) and the
// realm's policy.
func (p *Provider) sessionPolicy(ctx context.Context, realm string) (core.SessionPolicyStore, core.SessionPolicy, error) {
	st, ok := core.StoreAs[core.SessionPolicyStore](p.cfg.Store)
	if !ok {
		return nil, core.SessionPolicy{}, nil
	}
	pol, err := st.GetSessionPolicy(ctx, realm)
	if err != nil {
		return st, core.SessionPolicy{}, err
	}
	return st, pol, nil
}

// rememberStep carries the "keep me signed in" choice of the password form
// across later steps (second factors), whose forms do not have the checkbox:
// a signed, short-lived cookie bound to the user and to this authorization
// request. It never challenges the user.
func rememberStep(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) bool {
	_, pol, err := p.sessionPolicy(r.Context(), ar.realm.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: session policy", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return true
	}
	if pol.RememberMe && r.PostForm.Get(rememberField) == "on" {
		p.setRememberCookie(w, ar.realm.Name, p.signPending(ar.realm.Name, u.ID, rememberPurpose, mfaBind(r), rememberTTL), int(rememberTTL.Seconds()))
	} else if _, err := r.Cookie(rememberCookie); err == nil {
		p.setRememberCookie(w, ar.realm.Name, "", -1)
	}
	return false
}

func (p *Provider) setRememberCookie(w http.ResponseWriter, realm, value string, maxAge int) {
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(w, &http.Cookie{Name: rememberCookie, Value: value, Path: "/realms/" + realm + oidcPath + "/auth",
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

// wantsRemember reports whether the user ticked "keep me signed in" for this
// login: on the form of this request when it is the primary credential
// (password or passkey button), otherwise in the signed cookie of the password
// step.
func (p *Provider) wantsRemember(r *http.Request, realm, userID string) bool {
	if r.PostForm.Get("username") != "" || r.PostForm.Get("pk_mode") == "login" {
		return r.PostForm.Get(rememberField) == "on"
	}
	ck, err := r.Cookie(rememberCookie)
	if err != nil {
		return false
	}
	uid, bind, ok := p.checkPending(realm, ck.Value, rememberPurpose)
	return ok && uid == userID && bind == mfaBind(r)
}

// persistSession stores a new SSO session. It ends the browser's previous one
// (a fresh login replaces it), applies "keep me signed in" and enforces the
// concurrent session limit. It returns core.ErrSessionLimit when the realm
// refuses the login; any policy or store error refuses it too.
func (p *Provider) persistSession(w http.ResponseWriter, r *http.Request, rl core.Realm, s core.Session) (core.Session, error) {
	ctx := r.Context()
	old, hadOld := p.currentSession(r, rl)
	endOld := func() {
		if hadOld {
			_, _ = p.sessions().End(ctx, rl.Name, old.ID)
		}
	}
	st, pol, err := p.sessionPolicy(ctx, rl.Name)
	if err != nil {
		return s, err
	}
	var remember time.Duration
	if pol.RememberMe && p.wantsRemember(r, rl.Name, s.UserID) {
		idle, absolute := pol.RememberLifetimes()
		remember = min(max(idle, p.idleTTL(rl)), absolute) // never shorter than an ordinary session
		s.IdleExpires, s.ExpiresAt = s.CreatedAt.Add(remember), s.CreatedAt.Add(absolute)
	}
	if _, err := r.Cookie(rememberCookie); err == nil || remember > 0 {
		p.setRememberCookie(w, rl.Name, "", -1) // used up
	}
	if st == nil || (pol.MaxSessions == 0 && remember == 0) {
		endOld()
		return s, p.cfg.Store.PutSession(ctx, s)
	}
	o := core.NewSessionOptions{Now: s.CreatedAt, MaxLive: pol.MaxSessions,
		DenyNew: pol.OnLimit == core.SessionLimitDenyNew, RememberIdle: remember}
	if hadOld && old.UserID == s.UserID {
		o.Replaces = old.ID
	}
	if pol.MaxSessions > 0 {
		if err := p.endWithdrawnSessions(ctx, rl.Name, s.UserID); err != nil {
			return s, err
		}
	}
	// The new session is stored first: a refused login leaves the browser's
	// previous session alone.
	evicted, err := st.CreateLimitedSession(ctx, s, o)
	if err != nil {
		return s, err
	}
	endOld()
	p.sessions().Ended(ctx, rl.Name, evicted) // revokes refresh tokens, back-channel logout
	for _, e := range evicted {
		core.EmitSignal(ctx, p.cfg.Store, core.Signal{Realm: rl.Name, UserID: e.UserID, SessionID: e.ID, Kind: ssf.EvSessionRevoked})
		p.event(ctx, rl, "LOGOUT", e.UserID, "", p.clientIP(r), "session_limit")
	}
	return s, nil
}

// endWithdrawnSessions ends the user's long sessions that the current policy no
// longer allows, so they cannot occupy slots of the limit.
func (p *Provider) endWithdrawnSessions(ctx context.Context, realm, userID string) error {
	all, err := p.cfg.Store.ListSessions(ctx, realm, userID, maxPrecleanSessions)
	if err != nil {
		return err
	}
	for _, s := range all {
		if !p.longSessionAllowed(ctx, realm, s) {
			_, _ = p.sessions().End(ctx, realm, s.ID)
		}
	}
	return nil
}

// longSessionAllowed re-checks, on every use, a "keep me signed in" session
// that outlives the ordinary absolute cap: it is only valid while the realm
// still offers the option and within the current maximum. Turning the option
// off or shortening it therefore takes effect at once. Errors refuse.
func (p *Provider) longSessionAllowed(ctx context.Context, realm string, s core.Session) bool {
	if s.ExpiresAt.Sub(s.CreatedAt) <= maxSessionLife+time.Minute {
		return true
	}
	st, pol, err := p.sessionPolicy(ctx, realm)
	var remembered time.Duration
	if err == nil && st != nil {
		remembered, err = st.SessionRememberIdle(ctx, realm, s.ID)
	}
	if err != nil {
		p.cfg.Logger.Error("oidc: session policy", "err", err)
		return false
	}
	if remembered <= 0 {
		return true // not created by "keep me signed in"
	}
	if !pol.RememberMe {
		return false
	}
	_, absolute := pol.RememberLifetimes()
	return p.now().Before(s.CreatedAt.Add(absolute))
}

// sessionIdleFor is the idle window a use of session id slides to: the
// realm's, or the longer one of a remembered session. Errors give the shorter.
func (p *Provider) sessionIdleFor(ctx context.Context, rl core.Realm, id string) time.Duration {
	normal := p.idleTTL(rl)
	st, pol, err := p.sessionPolicy(ctx, rl.Name)
	if err != nil || st == nil || !pol.RememberMe {
		return normal
	}
	d, err := st.SessionRememberIdle(ctx, rl.Name, id)
	if err != nil || d <= 0 {
		return normal
	}
	idle, absolute := pol.RememberLifetimes()
	return min(max(min(d, idle), normal), absolute)
}

// sessionLimitPage refuses a fully authenticated login that would exceed the
// realm's session limit.
func (p *Provider) sessionLimitPage(w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) {
	p.event(r.Context(), ar.realm, "LOGIN_ERROR", u.ID, ar.client.ClientID, p.clientIP(r), "session_limit")
	p.simplePage(w, http.StatusForbidden, "Too many sessions",
		"You are already signed in on as many browsers or devices as this realm allows. Sign out on one of them, or ask an administrator to end a session, then try again.")
}

// loginSessionOptions adds the "keep me signed in" checkbox and the
// passkey-only note to the login page. On a store error neither is shown; the
// login itself then fails closed.
func (p *Provider) loginSessionOptions(r *http.Request, ar *authzReq, pd *pageData) {
	if _, pol, err := p.sessionPolicy(r.Context(), ar.realm.Name); err == nil && pol.RememberMe {
		pd.RememberMe = true
		pd.Remembered = r.PostForm.Get(rememberField) == "on"
	}
	if on, err := p.passkeyOnlyOn(r.Context(), ar.realm.Name); err == nil && on {
		pd.Note = passkeyOnlyNote
	}
}
