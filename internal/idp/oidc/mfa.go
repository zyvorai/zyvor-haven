// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/totp"
)

// TOTP multi-factor authentication (RFC 6238) with recovery codes. See
// docs/mfa-totp.md. This file holds what the login step and the account page
// share: the feature gate, seed handling and the one code-checking function.
//
// The feature is OFF (login unaffected, account pages 404) unless both a
// secretbox key (Config.SecretBox) and a store implementing core.MFAStore are
// present.

const (
	mfaPurpose   = "mfa"            // signPending purpose of every MFA proof
	mfaProofTTL  = 5 * time.Minute  // password step -> code page
	mfaDoneTTL   = 5 * time.Minute  // enrollment confirmed -> "I saved my codes"
	mfaWindow    = 10 * time.Minute // attempt-limit window
	mfaUserMax   = 5                // code attempts per user per window (since the last success)
	mfaIPMax     = 30               // code attempts per IP per window
	mfaFreshAuth = 10 * time.Minute // account changes need a login this recent
	mfaMaxInput  = 64               // longest code input we look at
	mfaIssuerMax = 64
	mfaOff       = "TOTP is not available on this server."
	mfaGeneric   = "Invalid code."
	mfaLimited   = "Too many attempts. Try again later."
	mfaTemporary = "Temporary error. Try again."
)

func init() {
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		mux.HandleFunc("GET /realms/{realm}/account/totp", p.accountTOTP)
		mux.HandleFunc("POST /realms/{realm}/account/totp", p.accountTOTP)
	})
	registerAuthStep(mfaStep, mfaContinue)
}

// mfaStore returns the feature store. ok is false when the feature is off.
func (p *Provider) mfaStore() (core.MFAStore, bool) {
	if p.cfg.SecretBox == nil {
		return nil, false
	}
	return core.StoreAs[core.MFAStore](p.cfg.Store)
}

func sealContext(realm, userID string) string { return "totp|" + realm + "|" + userID }

// openSeed decrypts a credential's seed. The context binds it to realm+user, so
// a ciphertext copied to another user does not open.
func (p *Provider) openSeed(c core.TOTPCredential) ([]byte, error) {
	return p.cfg.SecretBox.Open(c.SealedSeed, sealContext(c.Realm, c.UserID))
}

// newEnrollment creates (or restarts) an unconfirmed credential with a fresh
// seed and returns the seed for display.
func (p *Provider) newEnrollment(r *http.Request, st core.MFAStore, realm, userID string) ([]byte, error) {
	seed := totp.NewSeed()
	err := st.PutTOTP(r.Context(), core.TOTPCredential{
		Realm: realm, UserID: userID, CreatedAt: p.now().UTC(),
		SealedSeed: p.cfg.SecretBox.Seal(seed, sealContext(realm, userID)),
	})
	return seed, err
}

func (p *Provider) issuerName(rl core.Realm) string {
	n := rl.DisplayName
	if n == "" {
		n = rl.Name
	}
	if len(n) > mfaIssuerMax {
		n = n[:mfaIssuerMax]
	}
	return n
}

func hexKey(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}

// mfaThrottle counts one code attempt against the user and the client IP. Both
// are always counted. Any store error is returned: callers fail closed.
func (p *Provider) mfaThrottle(r *http.Request, realm, userID, epoch string) (bool, error) {
	now := p.now()
	ctx := r.Context()
	userOK, err := p.cfg.Store.HitRateLimit(ctx, hexKey("mfa-user", realm, userID, epoch), now, mfaWindow, mfaUserMax)
	if err != nil {
		return false, err
	}
	ipOK, err := p.cfg.Store.HitRateLimit(ctx, hexKey("mfa-ip", realm, p.clientIP(r)), now, mfaWindow, mfaIPMax)
	if err != nil {
		return false, err
	}
	return userOK && ipOK, nil
}

type mfaResult int

const (
	mfaBad     mfaResult = iota // wrong, replayed or malformed code
	mfaOK                       // accepted (method says which)
	mfaDenied                   // attempt limit reached: nothing was checked
	mfaFailure                  // store or crypto error: fail closed
)

// mfaCheck verifies a TOTP code or a recovery code for a user with a confirmed
// credential. It is the only place codes are accepted after enrollment.
//
//   - Attempts are counted (per user and per IP) BEFORE the code is looked at,
//     so once the limit is reached even a correct code is refused until the
//     window passes. The per-user counter is keyed by the credential's last
//     used step and the number of recovery codes left: a successful
//     verification changes both, which starts a fresh counter, while failures
//     (which change neither) accumulate.
//   - A TOTP code is accepted only if its step is newer than the last used step
//     and the store's compare-and-set records it (parallel submissions of one
//     code: one wins).
//   - A recovery code is deleted atomically on use.
//   - The caller shows the same message for every non-OK result; nothing here
//     reveals whether recovery codes exist.
func (p *Provider) mfaCheck(r *http.Request, st core.MFAStore, rl core.Realm, cred core.TOTPCredential, input string) (res mfaResult, method string) {
	ctx := r.Context()
	if len(input) > mfaMaxInput {
		input = input[:mfaMaxInput]
	}
	left, err := st.CountRecoveryCodes(ctx, rl.Name, cred.UserID)
	if err != nil {
		p.cfg.Logger.Error("oidc: mfa count recovery codes", "err", err)
		return mfaFailure, ""
	}
	allowed, err := p.mfaThrottle(r, rl.Name, cred.UserID, fmt.Sprintf("%d|%d", cred.LastUsedStep, left))
	if err != nil {
		p.cfg.Logger.Error("oidc: mfa rate limit", "err", err)
		return mfaFailure, ""
	}
	if !allowed {
		return mfaDenied, ""
	}
	if code, ok := totp.NormalizeCode(input); ok {
		seed, err := p.openSeed(cred)
		if err != nil {
			p.cfg.Logger.Error("oidc: mfa cannot open seed", "realm", rl.Name, "user", cred.UserID)
			return mfaFailure, ""
		}
		step, ok := totp.Verify(seed, code, p.now(), cred.LastUsedStep)
		if !ok {
			return mfaBad, ""
		}
		won, err := st.UseTOTPStep(ctx, rl.Name, cred.UserID, step)
		if err != nil {
			p.cfg.Logger.Error("oidc: mfa record step", "err", err)
			return mfaFailure, ""
		}
		if !won {
			return mfaBad, "" // replay, or lost the race to a parallel submission
		}
		return mfaOK, "totp"
	}
	if h, ok := totp.HashRecovery(input); ok {
		won, err := st.ConsumeRecoveryCode(ctx, rl.Name, cred.UserID, h)
		if err != nil {
			p.cfg.Logger.Error("oidc: mfa consume recovery code", "err", err)
			return mfaFailure, ""
		}
		if won {
			return mfaOK, "recovery"
		}
	}
	return mfaBad, ""
}

// issueRecoveryCodes replaces the user's recovery codes with a fresh set and
// returns it (the only time the plaintext exists).
func (p *Provider) issueRecoveryCodes(r *http.Request, st core.MFAStore, realm, userID string) ([]string, error) {
	codes := totp.NewRecoveryCodes(totp.RecoveryCount)
	hashes := make([]string, len(codes))
	for i, c := range codes {
		h, ok := totp.HashRecovery(c)
		if !ok {
			return nil, errors.New("oidc: generated recovery code has a bad shape")
		}
		hashes[i] = h
	}
	if err := st.ReplaceRecoveryCodes(r.Context(), realm, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// mfaEvent records an MFA audit event. detail is a fixed word, never a code.
func (p *Provider) mfaEvent(r *http.Request, rl core.Realm, typ, userID, clientID, detail string) {
	p.event(r.Context(), rl, typ, userID, clientID, p.clientIP(r), detail)
}

// mfaPage renders a page of the MFA flows: fresh CSRF token and cookie scoped
// to csrfPath, no-store, nonce'd CSP without scripts. body is trusted static
// template text; data is what it renders.
func (p *Provider) mfaPage(w http.ResponseWriter, r *http.Request, rl core.Realm, csrfPath string, status int, title, errMsg, body string, data any) {
	csrf := p.newCSRF(rl.Name)
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: csrfPath,
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	nonce := randToken(16)
	p.pageHeaders(w, nonce)
	disp := rl.DisplayName
	if disp == "" {
		disp = rl.Name
	}
	w.WriteHeader(status)
	_ = stepTemplate(body).Execute(w, StepData{Title: title, Nonce: nonce, CSRF: csrf, Realm: disp,
		Error: errMsg, Action: r.URL.Path, Data: data})
}

// checkFormCSRF is the double-submit check used by the account page.
func (p *Provider) checkFormCSRF(r *http.Request, realm string) bool {
	form := r.PostForm.Get("csrf")
	ck, err := r.Cookie(csrfCookie)
	return err == nil && form != "" && hmac.Equal([]byte(ck.Value), []byte(form)) && p.checkCSRF(realm, form)
}

func isNotFound(err error) bool { return errors.Is(err, idp.ErrNotFound) }
