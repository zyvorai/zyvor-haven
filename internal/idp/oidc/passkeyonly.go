// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/zyvorai/haven/internal/idp/core"
)

// The realm option "passkey-only for users who have a passkey"
// (docs/passkeys.md). Off by default. For a user with at least one passkey it
// means:
//
//   - no sign-in completes without a passkey (no one-time-code fallback, no
//     federated sign-in);
//   - once EVERY passkey of the user has completed a sign-in without a
//     password, the password is not accepted at all.
//
// The second rule is the lock-out guard: registration does not force a
// discoverable credential, and an authenticator without one cannot sign in
// from the passkey button. Until each passkey has proved it can, the password
// still leads to the (mandatory) passkey step. Users without a passkey are
// never affected.

const (
	authOrderPasskeyOnly = 5 // before every other challenging step

	passkeyOnlyNote = "If your account has a passkey, sign in with it: this realm does not accept a password alone for those accounts."
)

func init() { registerAuthStepAt(authOrderPasskeyOnly, passkeyOnlyStep, nil) }

// passkeyOnlyOn reports whether the realm option is on.
func (p *Provider) passkeyOnlyOn(ctx context.Context, realm string) (bool, error) {
	po, ok := core.StoreAs[core.PasskeyOnlyStore](p.cfg.Store)
	if !ok {
		return false, nil
	}
	return po.PasskeyOnly(ctx, realm)
}

// passkeyOnlyFor reports whether the option applies to this user (it is on and
// they have a passkey) and returns their passkeys. It deliberately does not
// depend on the relying party being usable: a misconfiguration must not
// silently re-open the password.
func (p *Provider) passkeyOnlyFor(ctx context.Context, realm, userID string) (bool, []core.Passkey, error) {
	on, err := p.passkeyOnlyOn(ctx, realm)
	if err != nil || !on {
		return false, nil, err
	}
	pks, ok := core.StoreAs[core.PasskeyStore](p.cfg.Store)
	if !ok {
		return false, nil, nil
	}
	creds, err := pks.ListPasskeys(ctx, realm, userID)
	if err != nil {
		return false, nil, err
	}
	return len(creds) > 0, creds, nil
}

// passkeyOnlyStep runs after the password check. It refuses the password of a
// user whose every passkey works without one, with exactly the wrong-password
// answer, so it confirms nothing about the password.
func passkeyOnlyStep(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) bool {
	ctx := r.Context()
	fail := func(err error) bool {
		p.cfg.Logger.Error("oidc: passkey-only policy", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return true
	}
	applies, creds, err := p.passkeyOnlyFor(ctx, ar.realm.Name, u.ID)
	if err != nil {
		return fail(err)
	}
	if !applies {
		return false
	}
	po, _ := core.StoreAs[core.PasskeyOnlyStore](p.cfg.Store)
	proven, err := po.PasswordlessPasskeys(ctx, ar.realm.Name, u.ID)
	if err != nil {
		return fail(err)
	}
	unproven := slices.ContainsFunc(creds, func(c core.Passkey) bool { return !slices.Contains(proven, c.CredentialID) })
	if _, _, usable := p.passkeys(); usable && unproven {
		return false // the passkey step that follows demands the passkey
	}
	p.cfg.Obs.Login(ar.realm.Name, "bad_credentials")
	p.event(ctx, ar.realm, "LOGIN_ERROR", u.ID, ar.client.ClientID, p.clientIP(r), "passkey_only")
	p.loginPage(w, r, ar, badCreds, strings.TrimSpace(r.PostForm.Get("username")))
	return true
}

// passkeyOnlyAllows is the last gate, in completeLogin: whatever route led
// there (one-time code, recovery code, federation, a step added later), a user
// the option applies to only gets a session when a passkey was used.
func (p *Provider) passkeyOnlyAllows(w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User, detail string) bool {
	if detail == "passkey" || detail == "passkey_2fa" {
		return true
	}
	applies, _, err := p.passkeyOnlyFor(r.Context(), ar.realm.Name, u.ID)
	if err != nil {
		p.cfg.Logger.Error("oidc: passkey-only policy", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return false
	}
	if !applies {
		return true
	}
	p.event(r.Context(), ar.realm, "LOGIN_ERROR", u.ID, ar.client.ClientID, p.clientIP(r), "passkey_only")
	p.simplePage(w, http.StatusForbidden, "Use your passkey",
		"This account signs in with a passkey. Start again from the application and choose Sign in with a passkey.")
	return false
}

// markPasswordless remembers that a credential completed a sign-in without a
// password. A failure only delays the moment the password is switched off.
func (p *Provider) markPasswordless(ctx context.Context, realm, credentialID string) {
	po, ok := core.StoreAs[core.PasskeyOnlyStore](p.cfg.Store)
	if !ok {
		return
	}
	if err := po.MarkPasswordlessPasskey(ctx, realm, credentialID, p.now()); err != nil {
		p.cfg.Logger.Error("oidc: record passwordless passkey", "err", err)
	}
}
