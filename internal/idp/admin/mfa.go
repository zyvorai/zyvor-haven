// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"errors"
	"net/http"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/ssf"
)

func isNF(err error) bool { return errors.Is(err, idp.ErrNotFound) }

// TOTP / MFA admin routes (see SPEC.md, "MFA (TOTP)"). Status only: neither a
// seed nor a recovery code is ever returned.
func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}"
		m.HandleFunc("GET "+p+"/users/{id}/mfa", a.userMFAStatus)
		m.HandleFunc("DELETE "+p+"/users/{id}/mfa", a.op("user-mfa", "delete", a.resetUserMFA))
		m.HandleFunc("GET "+p+"/mfa-policy", a.getMFAPolicy)
		m.HandleFunc("PUT "+p+"/mfa-policy", a.op("mfa-policy", "update", a.putMFAPolicy))
	})
}

// mfaStore returns the feature store, or answers 409 (no key) / 501 (store
// without support) and reports false.
func (a *api) mfaStore(w http.ResponseWriter) (core.MFAStore, bool) {
	if a.cfg.SecretBox == nil {
		writeErr(w, http.StatusConflict, "HAVEN_IDP_SECRET_KEY is not set: TOTP is disabled (generate a key with: haven-idp keygen)")
		return nil, false
	}
	st, ok := core.StoreAs[core.MFAStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "this store does not support TOTP")
		return nil, false
	}
	return st, true
}

type mfaStatus struct {
	TOTPEnrolled           bool `json:"totpEnrolled"`
	TOTPPending            bool `json:"totpPending"`
	RecoveryCodesRemaining int  `json:"recoveryCodesRemaining"`
}

func (a *api) userMFAStatus(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.mfaStore(w)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var out mfaStatus
	cred, err := st.GetTOTP(r.Context(), rl.Name, u.ID)
	switch {
	case err == nil:
		out.TOTPEnrolled, out.TOTPPending = cred.Confirmed, !cred.Confirmed
	case !isNF(err):
		a.fail(w, r, err)
		return
	}
	if out.TOTPEnrolled {
		if out.RecoveryCodesRemaining, err = st.CountRecoveryCodes(r.Context(), rl.Name, u.ID); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// resetUserMFA removes the user's TOTP credential and recovery codes (lost
// device) and ends their SSO sessions.
func (a *api) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.mfaStore(w)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := st.DeleteUserMFA(r.Context(), rl.Name, u.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.dropUserSessions(r.Context(), rl.Name, u.ID)
	core.EmitSignal(r.Context(), a.cfg.Store, core.Signal{Realm: rl.Name, UserID: u.ID, Kind: ssf.EvCredentialChange,
		Attrs: map[string]any{"credential_type": "app", "change_type": "delete"}})
	a.audit(r, rl, "ACTION", "user-mfa", u.Username)
	if rl.AuthEventsLogged {
		err := a.cfg.Store.AppendEvent(r.Context(), core.Event{Time: a.cfg.Clock().UTC(), Realm: rl.Name,
			Type: "TOTP_RESET", UserID: u.ID, IP: "", Detail: "admin"})
		if err != nil {
			a.cfg.Logger.Error("admin: append event", "err", err.Error())
		}
	}
	noContent(w)
}

type mfaPolicyBody struct {
	RequireMFA *bool `json:"requireMfa"`
}

func (a *api) getMFAPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.mfaStore(w)
	if !ok {
		return
	}
	p, err := st.GetMFAPolicy(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"requireMfa": p.RequireMFA})
}

func (a *api) putMFAPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.mfaStore(w)
	if !ok {
		return
	}
	var in mfaPolicyBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.RequireMFA == nil {
		a.fail(w, r, bad("requireMfa is required"))
		return
	}
	if err := st.PutMFAPolicy(r.Context(), rl.Name, core.MFAPolicy{RequireMFA: *in.RequireMFA}); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "mfa-policy", rl.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"requireMfa": *in.RequireMFA})
}
