// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/webauthn"
)

// WebAuthnConfig overrides the relying party of passkeys. Both fields are
// optional: by default the RP ID is the host of Config.BaseURL (no port) and
// the only allowed origin is its scheme://host[:port]. A loopback IP base URL
// (haven-idp dev) uses RP ID "localhost", which browsers accept as a secure
// context, and allows both origins. Set from HAVEN_IDP_WEBAUTHN_RPID and
// HAVEN_IDP_WEBAUTHN_ORIGINS (comma separated) by serve.
type WebAuthnConfig struct {
	RPID    string
	Origins []string
}

const (
	pkChallengeTTL  = 5 * time.Minute
	pkRecentAuth    = 10 * time.Minute
	pkMaxPerUser    = 20
	pkAssertWindow  = 10 * time.Minute
	pkAssertPerIP   = 30
	pkAssertPerUser = 20
	pkGeneric       = "Passkey sign-in failed. Try again or use your password."

	pkPurposeLogin = "pk-login" // first factor, discoverable credential
	pk2FA          = "pk-2fa"   // second factor after the password
	pkPurposeReg   = "pk-reg"
)

func init() {
	registerAuthStepAt(authOrderPasskey, pkSecondFactorStep, pkContinue)
	registerFeature(registerPasskeyRoutes)
	loginPageHook = pkLoginPageHook
	template.Must(pageTmpl.New("passkey").Parse(pkLoginSnippet))
}

// passkeys returns the feature store and relying party, or false when passkeys
// are off (store without PasskeyStore, or no usable RP ID).
func (p *Provider) passkeys() (core.PasskeyStore, webauthn.RP, bool) {
	st, ok := core.StoreAs[core.PasskeyStore](p.cfg.Store)
	if !ok {
		return nil, webauthn.RP{}, false
	}
	rp, ok := p.webauthnRP()
	if !ok {
		return nil, webauthn.RP{}, false
	}
	return st, rp, true
}

func (p *Provider) webauthnRP() (webauthn.RP, bool) {
	cfg := p.cfg.WebAuthn
	bu, err := url.Parse(p.base)
	if err != nil || bu.Hostname() == "" || (bu.Scheme != "https" && bu.Scheme != "http") {
		return webauthn.RP{}, false
	}
	host := strings.ToLower(bu.Hostname())
	origin := bu.Scheme + "://" + strings.ToLower(bu.Host)
	rp := webauthn.RP{ID: strings.ToLower(cfg.RPID), Origins: nil}
	for _, o := range cfg.Origins {
		ou, err := url.Parse(strings.TrimRight(o, "/"))
		if err != nil || (ou.Scheme != "https" && ou.Scheme != "http") || ou.Host == "" || ou.Path != "" {
			return webauthn.RP{}, false
		}
		rp.Origins = append(rp.Origins, ou.Scheme+"://"+strings.ToLower(ou.Host))
	}
	if len(rp.Origins) == 0 {
		rp.Origins = []string{origin}
	}
	if rp.ID == "" {
		ip := net.ParseIP(host)
		switch {
		case ip == nil:
			rp.ID = host
		case ip.IsLoopback():
			rp.ID = "localhost"
			port := ""
			if bu.Port() != "" {
				port = ":" + bu.Port()
			}
			rp.Origins = append(rp.Origins, bu.Scheme+"://localhost"+port)
		default:
			return webauthn.RP{}, false // browsers refuse IP addresses as RP IDs
		}
	}
	return rp, true
}

// ---- challenges: signed token + single-use marker ----

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pkChallenge makes a fresh challenge and the signed token that carries it.
func (p *Provider) pkChallenge(realm, userID, purpose string) (chal []byte, tok string) {
	chal = randBytes(32)
	return chal, p.signPending(realm, userID, purpose, b64(chal), pkChallengeTTL)
}

func pkDigest(realm, purpose string, chal []byte) string {
	h := sha256.Sum256(append([]byte("webauthn-challenge|"+realm+"|"+purpose+"|"), chal...))
	return hex.EncodeToString(h[:])
}

// pkOpen verifies the token and CONSUMES its challenge: whatever happens next,
// the same token can never be used again. A store failure fails closed.
func (p *Provider) pkOpen(ctx context.Context, st core.PasskeyStore, realm, tok, purpose string) (userID string, chal []byte, ok bool) {
	uid, payload, valid := p.checkPending(realm, tok, purpose)
	if !valid {
		return "", nil, false
	}
	chal, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || len(chal) != 32 {
		return "", nil, false
	}
	now := p.now()
	if err := st.ConsumeChallenge(ctx, pkDigest(realm, purpose, chal), now, now.Add(2*pkChallengeTTL)); err != nil {
		if !errors.Is(err, idp.ErrConflict) {
			p.cfg.Logger.Error("oidc: consume passkey challenge", "err", err)
		}
		return "", nil, false
	}
	return uid, chal, true
}

// pkRate applies the per-IP (and optional per-user) limit. It fails closed.
func (p *Provider) pkRate(ctx context.Context, realm, kind, id string, max int) bool {
	h := sha256.Sum256([]byte("webauthn-" + kind + "|" + realm + "|" + id))
	ok, err := p.cfg.Store.HitRateLimit(ctx, hex.EncodeToString(h[:]), p.now(), pkAssertWindow, max)
	if err != nil {
		p.cfg.Logger.Error("oidc: passkey rate limit", "err", err)
		return false
	}
	return ok
}

// ---- options JSON handed to the browser ----

type pkDescriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type pkAssertionOptions struct {
	Challenge        string         `json:"challenge"`
	RPID             string         `json:"rpId"`
	Timeout          int            `json:"timeout"`
	UserVerification string         `json:"userVerification"`
	AllowCredentials []pkDescriptor `json:"allowCredentials,omitempty"`
}

func pkDescriptors(creds []core.Passkey) []pkDescriptor {
	out := make([]pkDescriptor, 0, len(creds))
	for _, c := range creds {
		out = append(out, pkDescriptor{Type: "public-key", ID: c.CredentialID, Transports: c.Transports})
	}
	return out
}

// ---- login: first factor (button on the login page) ----

// PasskeyLogin is what the login page template sees when passkey sign-in is
// available.
type PasskeyLogin struct {
	Opts, Token string
	Script      template.JS
}

// loginPageHook lets passkeys add themselves to the login page.
var loginPageHook func(p *Provider, w http.ResponseWriter, ar *authzReq, nonce string, pd *pageData)

func pkLoginPageHook(p *Provider, w http.ResponseWriter, ar *authzReq, nonce string, pd *pageData) {
	_, rp, ok := p.passkeys()
	if !ok {
		return
	}
	chal, tok := p.pkChallenge(ar.realm.Name, "", pkPurposeLogin)
	opts := mustJSON(pkAssertionOptions{Challenge: b64(chal), RPID: rp.ID, Timeout: 60000, UserVerification: "required"})
	pd.Passkey = &PasskeyLogin{Opts: opts, Token: tok, Script: pkScript}
	w.Header().Set("Content-Security-Policy", pkCSP(nonce))
}

// ---- login: second factor ----

func pkSecondFactorStep(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) bool {
	st, rp, ok := p.passkeys()
	if !ok {
		return false
	}
	creds, err := st.ListPasskeys(r.Context(), ar.realm.Name, u.ID)
	if err != nil {
		// Fail closed: a user who may have a second factor is not let through.
		p.cfg.Logger.Error("oidc: list passkeys", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return true
	}
	if len(creds) == 0 {
		return false
	}
	p.pkSecondFactorPage(w, r, ar, rp, u.ID, creds, "")
	return true
}

type pkStepData struct {
	Opts, Token string
	Script      template.JS
	Alt         *Fallback // "use another method" (fallback.go)
}

func (p *Provider) pkSecondFactorPage(w http.ResponseWriter, r *http.Request, ar *authzReq, rp webauthn.RP, userID string, creds []core.Passkey, errMsg string) {
	chal, tok := p.pkChallenge(ar.realm.Name, userID, pk2FA)
	// userVerification "preferred": a second factor after the password does not
	// need a PIN or biometric, but it is used when the authenticator offers it.
	opts := mustJSON(pkAssertionOptions{Challenge: b64(chal), RPID: rp.ID, Timeout: 60000,
		UserVerification: "preferred", AllowCredentials: pkDescriptors(creds)})
	p.stepPage(w, r, ar, http.StatusOK, "Use your passkey", errMsg, pkStepBody+altFragment,
		pkStepData{Opts: opts, Token: tok, Script: pkScript, Alt: p.fallbackOffer(r, ar, userID, methodPasskey)})
}

// ---- assertion handling (both modes) ----

func pkContinue(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq) bool {
	mode := r.PostForm.Get("pk_mode")
	if mode == "" {
		return false
	}
	st, rp, ok := p.passkeys()
	if !ok || (mode != "login" && mode != "2fa") {
		p.errorPage(w, http.StatusNotFound, "Not available.")
		return true
	}
	p.pkAssert(w, r, ar, st, rp, mode)
	return true
}

func formB64(r *http.Request, name string, max int) ([]byte, bool) {
	v := r.PostForm.Get(name)
	if v == "" || len(v) > max*4/3+4 {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(b) > max {
		return nil, false
	}
	return b, true
}

func (p *Provider) pkAssert(w http.ResponseWriter, r *http.Request, ar *authzReq, st core.PasskeyStore, rp webauthn.RP, mode string) {
	ctx := r.Context()
	rl := ar.realm
	ip := p.clientIP(r)
	purpose, requireUV := pkPurposeLogin, true
	if mode == "2fa" {
		purpose, requireUV = pk2FA, false
	}

	// Every failure looks the same to the browser: unknown credential, bad
	// signature, wrong user, expired challenge, locked account, rate limit.
	fail := func(uid, why string) {
		p.cfg.Obs.Login(rl.Name, "bad_credentials")
		p.event(ctx, rl, "PASSKEY_FAILED", uid, ar.client.ClientID, ip, why)
		if mode == "2fa" && uid != "" {
			if creds, err := st.ListPasskeys(ctx, rl.Name, uid); err == nil && len(creds) > 0 {
				p.pkSecondFactorPage(w, r, ar, rp, uid, creds, pkGeneric)
				return
			}
		}
		p.loginPage(w, r, ar, pkGeneric, "")
	}
	// The pending token names the user in 2fa mode, for the re-rendered page.
	tokUID, _, _ := p.checkPending(rl.Name, r.PostForm.Get("pk_token"), purpose)

	if !p.pkRate(ctx, rl.Name, "ip", ip, pkAssertPerIP) {
		fail(tokUID, "rate_limited")
		return
	}
	uid, chal, ok := p.pkOpen(ctx, st, rl.Name, r.PostForm.Get("pk_token"), purpose)
	if !ok || (mode == "2fa") != (uid != "") {
		fail(tokUID, "bad_or_replayed_challenge")
		return
	}
	credID, ok1 := formB64(r, "pk_cred", 1023)
	cd, ok2 := formB64(r, "pk_cd", 4096)
	ad, ok3 := formB64(r, "pk_ad", 8192)
	sig, ok4 := formB64(r, "pk_sig", 1024)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		fail(uid, "malformed_response")
		return
	}
	credKey := b64(credID)
	cred, err := st.GetPasskey(ctx, rl.Name, credKey)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load passkey", "err", err)
		}
		fail(uid, "unknown_credential")
		return
	}
	switch mode {
	case "2fa":
		if cred.UserID != uid {
			fail(uid, "credential_of_another_user")
			return
		}
	default:
		uh, ok := formB64(r, "pk_uh", 128)
		if !ok {
			fail("", "missing_user_handle")
			return
		}
		owner, err := st.UserByHandle(ctx, rl.Name, b64(uh))
		if err != nil || owner != cred.UserID {
			fail("", "user_handle_mismatch")
			return
		}
		uid = owner
	}
	if !p.pkRate(ctx, rl.Name, "user", uid, pkAssertPerUser) {
		fail(uid, "rate_limited")
		return
	}
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, uid)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load user", "err", err)
		}
		fail("", "unknown_user")
		return
	}
	now := p.now()
	switch {
	case !u.Enabled:
		p.cfg.Obs.Login(rl.Name, "disabled")
		fail(u.ID, "user_disabled")
		return
	case rl.BruteForceProtection && !u.LockedUntil.IsZero() && now.Before(u.LockedUntil):
		p.cfg.Obs.Login(rl.Name, "locked")
		fail(u.ID, "user_temporarily_disabled")
		return
	case rl.EmailVerificationRequired && !u.EmailVerified:
		p.cfg.Obs.Login(rl.Name, "unverified")
		fail(u.ID, "email_not_verified")
		return
	}

	res, err := webauthn.VerifyAssertion(rp, chal, cd, ad, sig, webauthn.Credential{
		ID: credID, PublicKey: cred.PublicKey, SignCount: cred.SignCount, BackupEligible: cred.BackupEligible}, requireUV)
	if errors.Is(err, webauthn.ErrCounterRegression) {
		p.event(ctx, rl, "PASSKEY_CLONE_SUSPECTED", u.ID, ar.client.ClientID, ip, "credential "+pkShort(credKey))
		fail(u.ID, "signature_counter_regression")
		return
	}
	if err != nil {
		fail(u.ID, "verification_failed")
		return
	}
	if err := st.UpdatePasskeyUse(ctx, rl.Name, credKey, res.SignCount, res.BackupState, now); err != nil {
		p.cfg.Logger.Error("oidc: record passkey use", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	p.event(ctx, rl, "PASSKEY_LOGIN", u.ID, ar.client.ClientID, ip, "credential "+pkShort(credKey))
	detail := "passkey"
	if mode == "2fa" {
		detail = "passkey_2fa"
	}
	p.completeLogin(w, r, ar, u, detail)
}

// pkShort is a log-friendly prefix of a credential id (ids are public values).
func pkShort(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
