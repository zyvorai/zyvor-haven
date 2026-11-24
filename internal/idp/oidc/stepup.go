// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Risk-based step-up (migration 0013, docs/login-fallback-and-stepup.md).
//
// The decision itself is the pure core.DecideStepUp. This file gathers the
// signals and acts on the decision in two places:
//
//   - an interactive login (auth step, order authOrderStepUp): when the
//     policy fires and the user has no second factor that the later steps
//     would challenge, the user must enroll one now. A user who already has a
//     factor is always challenged by the existing steps, so nothing more is
//     needed for them.
//   - a silent SSO re-login (ssoReuse): when the policy fires, the SSO
//     session is not reused; the user signs in interactively, factors
//     included. prompt=none then answers login_required, as it already does.
//
// "Known device" is a random cookie (haven_device) whose sha256 is stored per
// user; it is set after a completed login. It is a signal, not a credential:
// presenting it grants nothing.

const (
	deviceCookie = "haven_device"
	deviceTTL    = 400 * 24 * time.Hour

	authOrderStepUp = 20 // before passkeys (50) and TOTP (100)
)

func init() {
	registerAuthStepAt(authOrderStepUp, stepUpStep, nil)
	afterLoginHook = recordDevice
}

// afterLoginHook runs from completeLogin once the session exists and before
// the code is issued. It must not fail the login.
var afterLoginHook func(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User)

func (p *Provider) stepUpStore() (core.StepUpStore, bool) {
	return core.StoreAs[core.StepUpStore](p.cfg.Store)
}

// ipPrefix reduces an address to the network it belongs to: /24 for IPv4, /48
// for IPv6. "" when the address cannot be parsed.
func ipPrefix(ip string) string {
	a := net.ParseIP(strings.TrimSpace(ip))
	if a == nil {
		return ""
	}
	if v4 := a.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return a.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

// ipHash is a salted (realm, user) hash of the network prefix. It keeps raw
// addresses out of the device table but is NOT secret against someone who has
// the table: the IPv4 /24 space is small enough to enumerate.
func ipHash(realm, userID, ip string) string {
	pre := ipPrefix(ip)
	if pre == "" {
		return ""
	}
	return hexKey("stepup-ip", realm, userID, pre)
}

func deviceHash(cookie string) string {
	h := sha256.Sum256([]byte("haven-device|" + cookie))
	return hex.EncodeToString(h[:])
}

func validDeviceCookie(v string) bool {
	if len(v) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil
}

// requestDevice returns the device cookie value of the request when it is
// well formed, and whether it is known for this user.
func (p *Provider) requestDevice(r *http.Request, st core.StepUpStore, realm, userID string) (cookie string, known bool, err error) {
	ck, cerr := r.Cookie(deviceCookie)
	if cerr != nil || !validDeviceCookie(ck.Value) {
		return "", false, nil
	}
	_, err = st.GetDevice(r.Context(), realm, userID, deviceHash(ck.Value))
	switch {
	case err == nil:
		return ck.Value, true, nil
	case errors.Is(err, idp.ErrNotFound):
		return ck.Value, false, nil
	}
	return "", false, err
}

// loginSignals are the signals of an interactive login (password step passed).
func (p *Provider) loginSignals(r *http.Request, st core.StepUpStore, ar *authzReq, u core.User) (core.RiskSignals, error) {
	ctx := r.Context()
	rl := ar.realm
	sig := core.RiskSignals{Scopes: strings.Fields(ar.scope), MaxAgeRequested: r.URL.Query().Has("max_age")}
	_, known, err := p.requestDevice(r, st, rl.Name, u.ID)
	if err != nil {
		return sig, err
	}
	sig.NewDevice = !known
	last, err := st.LatestDevice(ctx, rl.Name, u.ID)
	switch {
	case errors.Is(err, idp.ErrNotFound):
		sig.IPChanged = true // no baseline: unknown counts as changed
	case err != nil:
		return sig, err
	default:
		now := ipHash(rl.Name, u.ID, p.clientIP(r))
		sig.IPChanged = now == "" || last.IPHash == "" || now != last.IPHash
		sig.IdleFor = max(0, p.now().Sub(last.LastSeen))
	}
	return sig, nil
}

// ssoSignals are the signals of a silent re-login on session s.
func (p *Provider) ssoSignals(r *http.Request, st core.StepUpStore, ar *authzReq, u core.User, s core.Session) (core.RiskSignals, error) {
	_, known, err := p.requestDevice(r, st, ar.realm.Name, u.ID)
	if err != nil {
		return core.RiskSignals{}, err
	}
	was, now := ipPrefix(s.IP), ipPrefix(p.clientIP(r))
	return core.RiskSignals{
		NewDevice: !known,
		IPChanged: was == "" || now == "" || was != now,
		IdleFor:   max(0, p.now().Sub(s.LastSeen)),
		Scopes:    strings.Fields(ar.scope),
		AuthAge:   max(0, p.now().Sub(s.AuthTime)),
	}, nil
}

// stepUpBlocksSSO reports whether a silent re-login must not happen (the
// caller then shows the interactive login). Any error blocks: when the policy
// cannot be evaluated the safe answer is to ask for a real login.
func (p *Provider) stepUpBlocksSSO(r *http.Request, ar *authzReq, u core.User, s core.Session) bool {
	st, on := p.stepUpStore()
	if !on {
		return false
	}
	pol, err := st.GetStepUpPolicy(r.Context(), ar.realm.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: step-up policy", "err", err)
		return true
	}
	if !pol.Enabled {
		return false
	}
	sig, err := p.ssoSignals(r, st, ar, u, s)
	if err != nil {
		p.cfg.Logger.Error("oidc: step-up signals", "err", err)
		return true
	}
	dec := core.DecideStepUp(pol, sig)
	if !dec.Required {
		return false
	}
	p.stepUpEvent(r, ar, u, pol, "sso", dec)
	return pol.Enforce
}

func (p *Provider) stepUpEvent(r *http.Request, ar *authzReq, u core.User, pol core.StepUpPolicy, where string, dec core.StepUpDecision) {
	typ := "STEPUP_REPORT"
	if pol.Enforce {
		typ = "STEPUP_REQUIRED"
	}
	p.event(r.Context(), ar.realm, typ, u.ID, ar.client.ClientID, p.clientIP(r), where+":"+strings.Join(dec.Reasons, ","))
}

// stepUpStep is the login auth step. It never issues a code.
func stepUpStep(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) bool {
	st, on := p.stepUpStore()
	if !on {
		return false
	}
	ctx := r.Context()
	fail := func(msg string, err error) bool {
		p.cfg.Logger.Error("oidc: "+msg, "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return true
	}
	pol, err := st.GetStepUpPolicy(ctx, ar.realm.Name)
	if err != nil {
		return fail("step-up policy", err)
	}
	if !pol.Enabled {
		return false
	}
	sig, err := p.loginSignals(r, st, ar, u)
	if err != nil {
		return fail("step-up signals", err)
	}
	dec := core.DecideStepUp(pol, sig)
	if !dec.Required {
		return false
	}
	p.stepUpEvent(r, ar, u, pol, "login", dec)
	if !pol.Enforce {
		return false
	}
	// A user with a factor is challenged by the passkey / TOTP steps that run
	// next; nothing weaker is possible for them.
	has, err := p.hasChallengeableFactor(r, ar.realm.Name, u.ID)
	if err != nil {
		return fail("step-up factor lookup", err)
	}
	if has {
		return false
	}
	mst, mon := p.mfaStore()
	if !mon {
		p.cfg.Logger.Error("oidc: step-up requires a second factor but HAVEN_IDP_SECRET_KEY is not set: refusing the login", "realm", ar.realm.Name)
		p.cfg.Obs.Login(ar.realm.Name, "mfa_unavailable")
		p.event(ctx, ar.realm, "LOGIN_ERROR", u.ID, ar.client.ClientID, p.clientIP(r), "stepup_unavailable")
		p.errorPage(w, http.StatusServiceUnavailable, "This sign-in needs two-step verification, which is currently unavailable. Contact your administrator.")
		return true
	}
	seed, err := p.newEnrollment(r, mst, ar.realm.Name, u.ID)
	if err != nil {
		return fail("step-up start enrollment", err)
	}
	p.enrollPage(w, r, ar, u, seed, http.StatusOK, "")
	return true
}

// hasChallengeableFactor reports whether the existing second-factor steps
// would challenge this user: a confirmed TOTP credential (with the feature on)
// or a registered passkey (with passkeys on).
func (p *Provider) hasChallengeableFactor(r *http.Request, realm, userID string) (bool, error) {
	ctx := r.Context()
	if pst, _, ok := p.passkeys(); ok {
		creds, err := pst.ListPasskeys(ctx, realm, userID)
		if err != nil {
			return false, err
		}
		if len(creds) > 0 {
			return true, nil
		}
	}
	if mst, ok := p.mfaStore(); ok {
		c, err := mst.GetTOTP(ctx, realm, userID)
		switch {
		case err == nil && c.Confirmed:
			return true, nil
		case err != nil && !errors.Is(err, idp.ErrNotFound):
			return false, err
		}
	}
	return false, nil
}

// recordDevice remembers the browser of a completed login and (re)sets its
// cookie. Only while the policy is enabled: with it off nothing is collected.
func recordDevice(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) {
	st, on := p.stepUpStore()
	if !on {
		return
	}
	ctx := r.Context()
	rl := ar.realm
	pol, err := st.GetStepUpPolicy(ctx, rl.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: step-up policy", "err", err)
		return
	}
	if !pol.Enabled {
		return
	}
	cookie, known, err := p.requestDevice(r, st, rl.Name, u.ID)
	if err != nil {
		p.cfg.Logger.Error("oidc: step-up device lookup", "err", err)
		return
	}
	if !known {
		cookie = randToken(32) // never reuse a value another user's record may hold
	}
	now := p.now()
	err = st.TouchDevice(ctx, core.KnownDevice{Realm: rl.Name, UserID: u.ID, Hash: deviceHash(cookie),
		IPHash: ipHash(rl.Name, u.ID, p.clientIP(r)), FirstSeen: now, LastSeen: now}, core.MaxDevicesPerUser)
	if err != nil {
		p.cfg.Logger.Error("oidc: step-up remember device", "err", err)
		return
	}
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(w, &http.Cookie{Name: deviceCookie, Value: cookie, Path: "/realms/" + rl.Name,
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteLaxMode, MaxAge: int(deviceTTL.Seconds())})
}
