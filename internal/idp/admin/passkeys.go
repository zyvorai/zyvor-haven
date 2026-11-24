// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/http"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
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
	a.audit(r, rl, "DELETE", "passkey", u.Username)
	noContent(w)
}

type passkeyPolicyJSON struct {
	RequirePasskeys bool `json:"requirePasskeys"`
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
	v, err := st.RealmRequiresPasskeys(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, passkeyPolicyJSON{RequirePasskeys: v})
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
	if err := st.SetRealmRequiresPasskeys(r.Context(), rl.Name, in.RequirePasskeys); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "passkey-policy", rl.Name)
	writeJSON(w, http.StatusOK, in)
}
