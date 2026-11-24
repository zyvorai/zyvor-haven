// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/http"

	"github.com/zyvorai/haven/internal/idp/core"
)

// CIBA per-client opt-in (see SPEC.md, "CIBA", and docs/ciba.md).
func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}/clients/{id}/ciba"
		m.HandleFunc("GET "+p, a.getClientCIBA)
		m.HandleFunc("PUT "+p, a.op("client-ciba", "update", a.putClientCIBA))
	})
}

type cibaBody struct {
	Enabled bool `json:"enabled"`
}

// cibaClient loads the store extension and the client named by {id}.
func (a *api) cibaClient(w http.ResponseWriter, r *http.Request) (core.Realm, core.CIBAStore, core.Client, bool) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return rl, nil, core.Client{}, false
	}
	cs, ok := core.StoreAs[core.CIBAStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "this store does not support CIBA")
		return rl, nil, core.Client{}, false
	}
	c, err := a.cfg.Store.GetClient(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return rl, nil, core.Client{}, false
	}
	return rl, cs, c, true
}

func (a *api) getClientCIBA(w http.ResponseWriter, r *http.Request) {
	rl, cs, c, ok := a.cibaClient(w, r)
	if !ok {
		return
	}
	on, err := cs.CIBAClientEnabled(r.Context(), rl.Name, c.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, cibaBody{Enabled: on})
}

// putClientCIBA switches CIBA on or off for one client. CIBA is for
// confidential clients only (the endpoint authenticates the client; a public
// client could be impersonated by anyone who knows its id).
func (a *api) putClientCIBA(w http.ResponseWriter, r *http.Request) {
	rl, cs, c, ok := a.cibaClient(w, r)
	if !ok {
		return
	}
	var in cibaBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.Enabled && (c.Public || c.ServiceAccount) {
		a.fail(w, r, bad("CIBA needs a confidential client that is not a service account"))
		return
	}
	if err := cs.SetCIBAClient(r.Context(), rl.Name, c.ID, in.Enabled); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "client-ciba", c.ClientID)
	writeJSON(w, http.StatusOK, in)
}
