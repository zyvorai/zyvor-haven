// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/password"
)

// The state-changing actions of the account console. acctHandle has already
// checked the session, rate limits, CSRF token and recent authentication.
// Every function here must check that what it changes belongs to c.u.

const (
	acctListMax    = 500 // sessions loaded in one pass
	acctMaxIDLen   = 200
	acctEndRounds  = 20 // passes of "sign out all others"
	acctByUserNote = "by user"
)

// formID returns a form field that is meant to be an identifier, or "" when it
// cannot be one (too long, not UTF-8, control characters). Stores are never
// handed such a value.
func (c *console) formID(name string) string {
	v := c.r.PostForm.Get(name)
	if v == "" || len(v) > acctMaxIDLen || !utf8.ValidString(v) || strings.ContainsFunc(v, unicode.IsControl) {
		return ""
	}
	return v
}

// ---- sessions ----

// ownSessions returns the user's sessions, newest first.
func (c *console) ownSessions(ctx context.Context) ([]core.Session, error) {
	all, err := c.p.cfg.Store.ListSessions(ctx, c.rl.Name, c.u.ID, acctListMax)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, s := range all {
		if s.UserID == c.u.ID { // never rely on the store filter alone
			out = append(out, s)
		}
	}
	return out, nil
}

func (c *console) revokeSession() {
	ctx := c.r.Context()
	id := c.formID("sid")
	if id == "" {
		c.notFound("session")
		return
	}
	s, err := c.p.cfg.Store.GetSession(ctx, c.rl.Name, id)
	switch {
	case errors.Is(err, idp.ErrNotFound):
		c.notFound("session")
		return
	case err != nil:
		c.fail("load session", err)
		return
	case s.UserID != c.u.ID:
		c.notFound("session")
		return
	case s.ID == c.sess.ID:
		c.render(http.StatusBadRequest, "", "That is the session you are using now. Use Sign out to end it.")
		return
	}
	// sessions.Service.End revokes the session's refresh tokens (except
	// offline ones) and sends back-channel logout to its applications. It must
	// finish even if the browser goes away half way through.
	if _, err := c.p.sessions().End(context.WithoutCancel(ctx), c.rl.Name, s.ID); err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			c.notFound("session")
			return
		}
		c.fail("end session", err)
		return
	}
	c.event("ACCOUNT_SESSION_REVOKED", "", "session="+s.ID)
	c.done("session")
}

// endOtherSessions ends every session of the user except the current one and
// returns how many it ended. An error means some may still be live.
func (c *console) endOtherSessions(ctx context.Context) (int, error) {
	ended := 0
	for range acctEndRounds {
		all, err := c.ownSessions(ctx)
		if err != nil {
			return ended, err
		}
		others := 0
		for _, s := range all {
			if s.ID == c.sess.ID {
				continue
			}
			others++
			if _, err := c.p.sessions().End(ctx, c.rl.Name, s.ID); err != nil {
				if errors.Is(err, idp.ErrNotFound) {
					continue // ended meanwhile
				}
				return ended, err
			}
			ended++
		}
		if others == 0 {
			return ended, nil
		}
	}
	return ended, errors.New("sessions remain after repeated passes")
}

func (c *console) revokeOtherSessions() {
	// Finish even if the browser goes away half way through.
	ctx := context.WithoutCancel(c.r.Context())
	n, err := c.endOtherSessions(ctx)
	if n > 0 || err == nil {
		c.event("ACCOUNT_SESSIONS_REVOKED", "", "count="+strconv.Itoa(n))
	}
	if err != nil {
		c.p.cfg.Logger.Error("oidc: account end other sessions", "realm", c.rl.Name, "err", err)
		c.render(http.StatusInternalServerError, "", "Some sessions could not be signed out. Check the list and try again.")
		return
	}
	c.done("sessions")
}

// ---- known devices ----

// deviceHandle is what the page uses to name a known device: it does not
// expose the stored cookie hash and only means something for this user.
func deviceHandle(realm, userID, hash string) string {
	return hexKey("acct-device", realm, userID, hash)[:32]
}

func (c *console) forgetDevice() {
	ctx := c.r.Context()
	st, _ := c.p.stepUpStore()
	handle := c.formID("device")
	list, err := st.ListDevices(ctx, c.rl.Name, c.u.ID)
	if err != nil {
		c.fail("list devices", err)
		return
	}
	for _, d := range list {
		want := deviceHandle(c.rl.Name, c.u.ID, d.Hash)
		if subtle.ConstantTimeCompare([]byte(want), []byte(handle)) != 1 {
			continue
		}
		if err := st.DeleteDevice(ctx, c.rl.Name, c.u.ID, d.Hash); err != nil {
			c.fail("forget device", err)
			return
		}
		c.event("ACCOUNT_DEVICE_REMOVED", "", acctByUserNote)
		c.done("device")
		return
	}
	c.notFound("device")
}

func (c *console) forgetAllDevices() {
	st, _ := c.p.stepUpStore()
	if err := st.DeleteUserDevices(c.r.Context(), c.rl.Name, c.u.ID); err != nil {
		c.fail("forget devices", err)
		return
	}
	c.event("ACCOUNT_DEVICES_REMOVED", "", acctByUserNote)
	c.done("devices")
}

// ---- applications ----

func (c *console) revokeApp() {
	ctx := c.r.Context()
	cs, _ := c.p.consentStore()
	id := c.formID("grant_id")
	if id == "" {
		c.notFound("application access")
		return
	}
	g, err := cs.GetConsentGrant(ctx, c.rl.Name, id)
	switch {
	case errors.Is(err, idp.ErrNotFound):
		c.notFound("application access")
		return
	case err != nil:
		c.fail("load grant", err)
		return
	case g.UserID != c.u.ID: // someone else's grant looks like a missing one
		c.notFound("application access")
		return
	}
	// Grant, refresh tokens and receipt belong together: do not stop between.
	if _, err := core.RevokeConsent(context.WithoutCancel(ctx), cs, g, c.u.ID, c.p.now()); err != nil && !errors.Is(err, idp.ErrConflict) {
		c.fail("revoke consent", err)
		return
	}
	c.event("CONSENT_REVOKE", g.ClientID, acctByUserNote)
	c.done("app")
}

// ---- agents ----

// ownAgent loads the agent named in the form and checks that the signed-in
// user owns it. ok=false: it has responded.
func (c *console) ownAgent(as core.AgentStore) (core.Agent, bool) {
	id := c.formID("agent_id")
	if id == "" {
		c.notFound("agent")
		return core.Agent{}, false
	}
	ag, err := as.GetAgent(c.r.Context(), c.rl.Name, id)
	switch {
	case errors.Is(err, idp.ErrNotFound):
		c.notFound("agent")
		return core.Agent{}, false
	case err != nil:
		c.fail("load agent", err)
		return core.Agent{}, false
	case ag.OwnerUserID != c.u.ID:
		c.notFound("agent")
		return core.Agent{}, false
	}
	return ag, true
}

func (c *console) revokeCredential() {
	as, _ := core.StoreAs[core.AgentStore](c.p.cfg.Store)
	ag, ok := c.ownAgent(as)
	if !ok {
		return
	}
	cid := c.formID("credential_id")
	if cid == "" {
		c.notFound("credential")
		return
	}
	// Scoped to the agent the user owns: another agent's credential id is
	// simply not found.
	cred, err := as.RevokeAgentCredential(c.r.Context(), c.rl.Name, ag.ID, cid, "user:"+c.u.ID, c.p.now())
	switch {
	case errors.Is(err, idp.ErrNotFound):
		c.notFound("credential")
		return
	case errors.Is(err, idp.ErrConflict):
		c.render(http.StatusConflict, "", "That credential has already ended.")
		return
	case err != nil:
		c.fail("revoke credential", err)
		return
	}
	c.event("AGENT_CREDENTIAL_REVOKED", ag.ClientID, "agent "+ag.Name+" credential "+cred.ID+" "+acctByUserNote)
	c.done("cred")
}

func (c *console) revokeAllCredentials() {
	as, _ := core.StoreAs[core.AgentStore](c.p.cfg.Store)
	ag, ok := c.ownAgent(as)
	if !ok {
		return
	}
	n, err := as.RevokeAgentCredentials(c.r.Context(), c.rl.Name, ag.ID, "user:"+c.u.ID, c.p.now())
	if err != nil {
		c.fail("revoke credentials", err)
		return
	}
	c.event("AGENT_CREDENTIAL_REVOKED", ag.ClientID,
		"agent "+ag.Name+" all credentials ("+strconv.Itoa(n)+") "+acctByUserNote)
	c.done("creds")
}

// ---- password ----

// changePassword replaces the local password. It needs recent authentication
// (checked by acctHandle) AND the current password. Afterwards every other
// session ends (with back-channel logout), every refresh token of the user is
// revoked, pending reset and email-change links die, and the current session
// gets a new cookie so a copy of the old one is useless.
func (c *console) changePassword() {
	p, ctx := c.p, c.r.Context()
	if c.u.PasswordHash == "" {
		c.render(http.StatusConflict, "", "This account has no password to change.")
		return
	}
	cur, pw, confirm := c.r.PostForm.Get("current"), c.r.PostForm.Get("password"), c.r.PostForm.Get("confirm")
	if !c.checkPassword(cur, "UPDATE_PASSWORD_ERROR") {
		return
	}
	reject := func(msg, why string) {
		c.event("UPDATE_PASSWORD_ERROR", "", why)
		c.render(http.StatusBadRequest, "", msg)
	}
	switch {
	case pw == "" || len(pw) > 1024:
		reject("Enter a new password.", "empty_or_too_long")
		return
	case pw != confirm:
		reject("The two new passwords do not match.", "mismatch")
		return
	case pw == cur:
		reject("The new password must differ from the current one.", "unchanged")
		return
	}
	if err := password.CheckPolicyFor(c.rl.PasswordPolicy, pw, password.Personal{
		Username: c.u.Username, Email: c.u.Email, FirstName: c.u.FirstName, LastName: c.u.LastName}); err != nil {
		reject("That password is not allowed: "+err.Error(), "policy")
		return
	}
	hash, err := p.cfg.Hasher.Hash(pw)
	if err != nil {
		c.fail("hash new password", err)
		return
	}
	// Reload so an administrator's concurrent change (disable, reset) is not
	// overwritten with what this request read at its start.
	u, err := p.cfg.Store.GetUser(ctx, c.rl.Name, c.u.ID)
	if err != nil {
		c.fail("reload user", err)
		return
	}
	if !u.Enabled || u.PasswordHash != c.u.PasswordHash {
		c.render(http.StatusConflict, "", "Your account changed while you were doing this. Sign in again and retry.")
		return
	}
	u.PasswordHash = hash
	u.FailedLogins, u.LockedUntil = 0, time.Time{}
	pending := []string{}
	for _, a := range u.PendingActions {
		if a != "UPDATE_PASSWORD" {
			pending = append(pending, a)
		}
	}
	u.PendingActions = pending
	// From here on the work must complete even if the browser goes away.
	ctx = context.WithoutCancel(ctx)
	if err := p.cfg.Store.UpdateUser(ctx, u); err != nil {
		c.fail("save new password", err)
		return
	}
	c.u = u

	var failed []error
	// First the current cookie: if somebody copied it, it dies here.
	rotated := true
	if err := c.rotateCookie(ctx); err != nil {
		rotated = false
		failed = append(failed, err)
		if _, eerr := p.sessions().End(ctx, c.rl.Name, c.sess.ID); eerr != nil && !errors.Is(eerr, idp.ErrNotFound) {
			failed = append(failed, eerr)
		}
		p.clearSSOCookie(c.w, c.rl.Name)
	}
	if _, err := p.cfg.Store.RevokeUserRefreshTokens(ctx, c.rl.Name, u.ID); err != nil {
		failed = append(failed, err)
	}
	if _, err := c.endOtherSessions(ctx); err != nil {
		failed = append(failed, err)
	}
	for _, purpose := range []string{core.ActionResetPassword, actions.ActionChangeEmail} {
		if _, err := p.cfg.Store.DeleteActionTokens(ctx, c.rl.Name, u.ID, purpose); err != nil {
			failed = append(failed, err)
		}
	}
	c.event("UPDATE_PASSWORD", "", "account")
	p.notifyPasswordChanged(ctx, c.rl, u)
	if err := errors.Join(failed...); err != nil {
		p.cfg.Logger.Error("oidc: account password change cleanup", "realm", c.rl.Name, "user", u.ID, "err", err)
		msg := "Your password was changed, but not everything else could be signed out. Check your sessions."
		if !rotated {
			msg = "Your password was changed, but this session could not be renewed. Sign in again and check your sessions."
		}
		p.simplePage(c.w, http.StatusInternalServerError, "Password changed", msg)
		return
	}
	c.done("password")
}

// rotateCookie gives the current session a fresh cookie. The session id (sid)
// stays, so the applications of this browser are not signed out.
func (c *console) rotateCookie(ctx context.Context) error {
	p := c.p
	raw := randToken(32)
	if err := c.st.RotateSessionCookie(ctx, c.rl.Name, c.u.ID, c.sess.ID, actions.Hash(raw)); err != nil {
		return err
	}
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(c.w, &http.Cookie{Name: ssoCookie, Value: raw, Path: p.ssoCookiePath(c.rl.Name),
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteLaxMode, Expires: c.sess.ExpiresAt})
	return nil
}

// notifyPasswordChanged sends the security notice (never a link or the
// password). Best effort, off when email is not configured.
func (p *Provider) notifyPasswordChanged(ctx context.Context, rl core.Realm, u core.User) {
	if !p.actionsOn() || u.Email == "" {
		return
	}
	p.bg.Add(1)
	detached := context.WithoutCancel(ctx) // outlives the response, keeps request values
	go func() {
		defer p.bg.Done()
		nctx, cancel := context.WithTimeout(detached, mailTimeout)
		defer cancel()
		if err := p.cfg.Actions.Notify(nctx, rl, u, mail.KindPasswordChanged, "your account page"); err != nil {
			p.cfg.Logger.Error("oidc: password change notification failed", "realm", rl.Name, "user", u.ID, "err", err)
		}
	}()
}
