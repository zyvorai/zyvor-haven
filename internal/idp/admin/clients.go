// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/http"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/oidc"
)

func (a *api) clientRoutes(m *http.ServeMux) {
	p := pathPrefix + "/realms/{r}/clients"
	m.HandleFunc("GET "+p, a.listClients)
	m.HandleFunc("POST "+p, a.op("client", "create", a.createClient))
	m.HandleFunc("GET "+p+"/{id}", a.getClient)
	m.HandleFunc("PUT "+p+"/{id}", a.op("client", "update", a.updateClient))
	m.HandleFunc("DELETE "+p+"/{id}", a.op("client", "delete", a.deleteClient))
	m.HandleFunc("POST "+p+"/{id}/secret", a.op("secret", "action", a.regenerateSecret))
	m.HandleFunc("GET "+p+"/{id}/secret", func(w http.ResponseWriter, _ *http.Request) {
		notImplemented(w, "client secrets are stored hashed and cannot be read; regenerate instead")
	})
	m.HandleFunc("GET "+p+"/{id}/secret/rotated", rotatedNotFound)
	m.HandleFunc("DELETE "+p+"/{id}/secret/rotated", rotatedNotFound)
}

func rotatedNotFound(w http.ResponseWriter, _ *http.Request) {
	writeErr(w, http.StatusNotFound, "rotated secrets are not supported")
}

func (a *api) listClients(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	cs, err := a.cfg.Store.ListClients(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	want := r.URL.Query().Get("clientId")
	out := make([]idp.Client, 0, len(cs))
	for _, c := range cs {
		if want != "" && c.ClientID != want {
			continue
		}
		out = append(out, clientToWire(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) getClient(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	c, err := a.cfg.Store.GetClient(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, clientToWire(c))
}

func (a *api) createClient(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	var in idp.Client
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := clientFromWire(in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c.Realm = rl.Name
	if !a.guardClient(w, r, rl, c) {
		return
	}
	var secret string
	if !c.Public {
		if secret, err = newSecret(); err != nil {
			a.fail(w, r, err)
			return
		}
		c.SecretHash = oidc.HashSecret(secret)
	}
	if err := a.cfg.Store.CreateClient(r.Context(), c); err != nil {
		a.fail(w, r, err)
		return
	}
	// The store may assign the ID, so look it up.
	stored, err := a.cfg.Store.GetClientByClientID(r.Context(), rl.Name, c.ClientID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "CREATE", "client", stored.ClientID)
	body := map[string]string{"id": stored.ID}
	if secret != "" {
		body["secret"] = secret
	}
	created(w, pathPrefix+"/realms/"+rl.Name+"/clients/"+stored.ID, body)
}

func (a *api) updateClient(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	cur, err := a.cfg.Store.GetClient(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in idp.Client
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	next, err := clientFromWire(in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if next.ClientID != cur.ClientID {
		a.fail(w, r, bad("clientId cannot be changed"))
		return
	}
	next.ID, next.Realm, next.CreatedAt = cur.ID, cur.Realm, cur.CreatedAt
	if !next.Public {
		next.SecretHash = cur.SecretHash
	}
	if !a.guardClient(w, r, rl, next) {
		return
	}
	if err := a.cfg.Store.UpdateClient(r.Context(), next); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "client", next.ClientID)
	noContent(w)
}

func (a *api) deleteClient(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	cur, err := a.cfg.Store.GetClient(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if strings.EqualFold(rl.Name, a.cfg.AdminRealm) {
		for _, id := range a.cfg.AdminClients {
			if id == cur.ClientID {
				writeErr(w, http.StatusConflict, "the admin client cannot be deleted")
				return
			}
		}
	}
	if err := a.cfg.Store.DeleteClient(r.Context(), rl.Name, cur.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "client", cur.ClientID)
	noContent(w)
}

func (a *api) regenerateSecret(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	cur, err := a.cfg.Store.GetClient(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if cur.Public {
		a.fail(w, r, bad("public clients have no secret"))
		return
	}
	if strong, err := a.strongClientAuth(r, rl.Name, cur); err != nil {
		a.fail(w, r, err)
		return
	} else if strong {
		writeErr(w, http.StatusConflict, "this client authenticates with a key or certificate; change its authentication settings first")
		return
	}
	secret, err := newSecret()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cur.SecretHash = oidc.HashSecret(secret)
	if err := a.cfg.Store.UpdateClient(r.Context(), cur); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "ACTION", "client-secret", cur.ClientID)
	writeJSON(w, http.StatusOK, idp.ClientSecret{Type: "secret", Value: secret})
}
