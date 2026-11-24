// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"net/http"
	"time"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
)

const (
	ssoCookie      = "haven_sso"
	defaultIdle    = 30 * time.Minute
	maxSessionLife = 10 * time.Hour
	maxUALen       = 256
)

func (p *Provider) idleTTL(rl core.Realm) time.Duration {
	if rl.SessionIdleTTL > 0 {
		return rl.SessionIdleTTL
	}
	return defaultIdle
}

func (p *Provider) ssoCookiePath(realm string) string { return "/realms/" + realm }

// startSession creates an SSO session for u after a successful credential
// check and sets the browser cookie. Any session the browser already had in
// this realm is ended first (a fresh login replaces it).
func (p *Provider) startSession(w http.ResponseWriter, r *http.Request, rl core.Realm, u core.User) (core.Session, error) {
	if old, ok := p.currentSession(r, rl); ok {
		_, _ = p.sessions().End(r.Context(), rl.Name, old.ID)
	}
	now := p.now()
	raw := randToken(32)
	ua := r.UserAgent()
	if len(ua) > maxUALen {
		ua = ua[:maxUALen]
	}
	s := core.Session{
		ID: randToken(16), CookieHash: actions.Hash(raw), Realm: rl.Name, UserID: u.ID,
		AuthTime: now, LastSeen: now, IdleExpires: now.Add(p.idleTTL(rl)), ExpiresAt: now.Add(maxSessionLife),
		IP: p.clientIP(r), UserAgent: ua, CreatedAt: now,
	}
	if err := p.cfg.Store.PutSession(r.Context(), s); err != nil {
		return core.Session{}, err
	}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: raw, Path: p.ssoCookiePath(rl.Name),
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteLaxMode, Expires: s.ExpiresAt})
	return s, nil
}

// currentSession returns the live SSO session behind the request's cookie.
// "Live" means present, inside both its idle and absolute lifetime. It does
// not check the user: callers must (disabled users must not ride a session).
func (p *Provider) currentSession(r *http.Request, rl core.Realm) (core.Session, bool) {
	ck, err := r.Cookie(ssoCookie)
	if err != nil || ck.Value == "" || len(ck.Value) > 256 {
		return core.Session{}, false
	}
	s, err := p.cfg.Store.GetSessionByCookie(r.Context(), rl.Name, actions.Hash(ck.Value))
	if err != nil {
		return core.Session{}, false
	}
	now := p.now()
	if !now.Before(s.ExpiresAt) || !now.Before(s.IdleExpires) {
		return core.Session{}, false
	}
	return s, true
}

// sessionAlive reports whether a session id is still live (used to gate
// refresh tokens and introspection). An empty id is "no session".
func (p *Provider) sessionAlive(r *http.Request, realm, id string) bool {
	if id == "" {
		return false
	}
	s, err := p.cfg.Store.GetSession(r.Context(), realm, id)
	if err != nil {
		return false
	}
	now := p.now()
	return now.Before(s.ExpiresAt) && now.Before(s.IdleExpires)
}

// touchSession slides the idle window.
func (p *Provider) touchSession(r *http.Request, rl core.Realm, s core.Session) {
	now := p.now()
	_ = p.cfg.Store.TouchSession(r.Context(), rl.Name, s.ID, now, now.Add(p.idleTTL(rl)))
}

func (p *Provider) clearSSOCookie(w http.ResponseWriter, realm string) {
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: p.ssoCookiePath(realm), MaxAge: -1,
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteLaxMode})
}
