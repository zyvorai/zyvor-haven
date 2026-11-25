// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/ssf"
)

func init() { registerRoutes(passkeyRoutes) }

func passkeyRoutes(a *api, m *http.ServeMux) {
	p := pathPrefix + "/realms/{r}"
	m.HandleFunc("GET "+p+"/users/{id}/passkeys", a.listPasskeys)
	m.HandleFunc("DELETE "+p+"/users/{id}/passkeys/{credId}", a.op("passkey", "delete", a.deletePasskey))
	m.HandleFunc("GET "+p+"/passkey-policy", a.getPasskeyPolicy)
	m.HandleFunc("PUT "+p+"/passkey-policy", a.op("passkey-policy", "update", a.putPasskeyPolicy))
}

// passkeyStore is the optional passkey feature store; without it the routes
// answer 501.
func (a *api) passkeyStore(w http.ResponseWriter) (core.PasskeyStore, bool) {
	st, ok := core.StoreAs[core.PasskeyStore](a.cfg.Store)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "passkeys are not supported by this store")
	}
	return st, ok
}

// passkeyJSON never includes the public key bytes.
type passkeyJSON struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
	BackupEligible bool       `json:"backupEligible"`
	BackupState    bool       `json:"backupState"`
	Transports     []string   `json:"transports"`
	AAGUID         string     `json:"aaguid"`
	SignCount      uint32     `json:"signCount"`
}

func (a *api) listPasskeys(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.passkeyStore(w)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	creds, err := st.ListPasskeys(r.Context(), rl.Name, u.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]passkeyJSON, 0, len(creds))
	for _, c := range creds {
		j := passkeyJSON{ID: c.CredentialID, Name: c.Name, CreatedAt: c.CreatedAt, BackupEligible: c.BackupEligible,
			BackupState: c.BackupState, Transports: c.Transports, AAGUID: c.AAGUID, SignCount: c.SignCount}
		if j.Transports == nil {
			j.Transports = []string{}
		}
		if !c.LastUsedAt.IsZero() {
			t := c.LastUsedAt
			j.LastUsedAt = &t
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

// deletePasskey removes one credential. The realm's "passkeys required" policy
// does not apply to administrators (recovering a locked-out user is the
// point). It does not end the user's sessions.
func (a *api) deletePasskey(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.passkeyStore(w)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := st.DeletePasskey(r.Context(), rl.Name, u.ID, r.PathValue("credId"), false); err != nil {
		a.fail(w, r, err)
		return
	}
	core.EmitSignal(r.Context(), a.cfg.Store, core.Signal{Realm: rl.Name, UserID: u.ID, Kind: ssf.EvCredentialChange,
		Attrs: map[string]any{"credential_type": "fido2-platform", "change_type": "delete"}})
	a.audit(r, rl, "DELETE", "passkey", u.Username)
	noContent(w)
}

type passkeyPolicyJSON struct {
	RequirePasskeys bool `json:"requirePasskeys"`
	// PasskeyOnly is "passkey-only for users who have a passkey". Absent in
	// GET answers of a store without it; absent in a PUT leaves it unchanged.
	PasskeyOnly *bool `json:"passkeyOnly,omitempty"`
}

func (a *api) getPasskeyPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.passkeyStore(w)
	if !ok {
		return
	}
	out, err := a.passkeyPolicy(r.Context(), st, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) passkeyPolicy(ctx context.Context, st core.PasskeyStore, realm string) (passkeyPolicyJSON, error) {
	var out passkeyPolicyJSON
	var err error
	if out.RequirePasskeys, err = st.RealmRequiresPasskeys(ctx, realm); err != nil {
		return out, err
	}
	if po, ok := core.StoreAs[core.PasskeyOnlyStore](a.cfg.Store); ok {
		only, err := po.PasskeyOnly(ctx, realm)
		if err != nil {
			return out, err
		}
		out.PasskeyOnly = &only
	}
	return out, nil
}

func (a *api) putPasskeyPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.passkeyStore(w)
	if !ok {
		return
	}
	var in passkeyPolicyJSON
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.PasskeyOnly != nil {
		po, ok := core.StoreAs[core.PasskeyOnlyStore](a.cfg.Store)
		if !ok {
			notImplemented(w, "this store does not support passkeyOnly")
			return
		}
		if err := po.SetPasskeyOnly(r.Context(), rl.Name, *in.PasskeyOnly); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	if err := st.SetRealmRequiresPasskeys(r.Context(), rl.Name, in.RequirePasskeys); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "passkey-policy", rl.Name)
	out, err := a.passkeyPolicy(r.Context(), st, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
