// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/oidc"
)

// Admin side of dynamic client registration (RFC 7591): initial access
// tokens, the per-realm registration policy and the list of clients that were
// created through the registration endpoint.

const (
	iatDefaultTTL   = 24 * time.Hour
	iatMaxTTL       = 30 * 24 * time.Hour
	iatDefaultCount = 1
	iatMaxCount     = 1000
	policyMaxCap    = 100000
)

func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}"
		m.HandleFunc("POST "+p+"/initial-access-tokens", a.op("initial-access-token", "create", a.createIAT))
		m.HandleFunc("GET "+p+"/initial-access-tokens", a.listIATs)
		m.HandleFunc("DELETE "+p+"/initial-access-tokens/{id}", a.op("initial-access-token", "delete", a.deleteIAT))
		m.HandleFunc("GET "+p+"/registration-policy", a.getRegPolicy)
		m.HandleFunc("PUT "+p+"/registration-policy", a.op("registration-policy", "update", a.putRegPolicy))
		m.HandleFunc("GET "+p+"/registered-clients", a.listRegistered)
	})
}

func (a *api) dcr(w http.ResponseWriter) (core.DCRStore, bool) {
	st, ok := core.StoreAs[core.DCRStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "dynamic client registration is not available on this store")
	}
	return st, ok
}

type iatRequest struct {
	ExpirationSeconds int    `json:"expirationSeconds"`
	Count             int    `json:"count"`
	Note              string `json:"note"`
}

func (a *api) createIAT(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.dcr(w)
	if !ok {
		return
	}
	in := iatRequest{ExpirationSeconds: int(iatDefaultTTL / time.Second), Count: iatDefaultCount}
	if r.ContentLength != 0 {
		if _, err := decode(r, &in); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	if in.ExpirationSeconds < 1 || time.Duration(in.ExpirationSeconds)*time.Second > iatMaxTTL {
		a.fail(w, r, bad("expirationSeconds must be between 1 and 2592000 (30 days)"))
		return
	}
	if in.Count < 1 || in.Count > iatMaxCount {
		a.fail(w, r, bad("count must be between 1 and 1000"))
		return
	}
	if !validText(in.Note, 255) {
		a.fail(w, r, bad("invalid note"))
		return
	}
	token, err := newSecret()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	token = "hiat_" + token
	now := a.cfg.Clock().UTC()
	id := uuid.NewString()
	t := core.InitialAccessToken{
		ID: id, Realm: rl.Name, TokenHash: oidc.HashSecret(token), Note: in.Note, Count: in.Count, Remaining: in.Count,
		CreatedAt: now, ExpiresAt: now.Add(time.Duration(in.ExpirationSeconds) * time.Second),
	}
	if err := st.PutInitialAccessToken(r.Context(), t); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "CREATE", "initial-access-token", id)
	w.Header().Set("Location", pathPrefix+"/realms/"+rl.Name+"/initial-access-tokens")
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "token": token, "count": t.Count, "expiresAt": t.ExpiresAt, "note": t.Note,
	})
}

func (a *api) listIATs(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.dcr(w)
	if !ok {
		return
	}
	ts, err := st.ListInitialAccessTokens(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(ts))
	for _, t := range ts { // never the token or its hash
		out = append(out, map[string]any{"id": t.ID, "note": t.Note, "createdAt": t.CreatedAt,
			"expiresAt": t.ExpiresAt, "count": t.Count, "remaining": t.Remaining})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) deleteIAT(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.dcr(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := st.DeleteInitialAccessToken(r.Context(), rl.Name, id); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "initial-access-token", id)
	noContent(w)
}

type policyBody struct {
	MaxClients        int      `json:"maxClients"`
	AllowedGrantTypes []string `json:"allowedGrantTypes"`
}

func (a *api) policyOf(r *http.Request, st core.DCRStore, realm string) (policyBody, error) {
	p, err := st.GetRegistrationPolicy(r.Context(), realm)
	if errors.Is(err, idp.ErrNotFound) {
		return policyBody{MaxClients: core.DCRDefaultMaxClients, AllowedGrantTypes: slices.Clone(core.DCRGrantTypes)}, nil
	}
	if err != nil {
		return policyBody{}, err
	}
	if len(p.AllowedGrantTypes) == 0 {
		p.AllowedGrantTypes = slices.Clone(core.DCRGrantTypes)
	}
	return policyBody{MaxClients: p.MaxClients, AllowedGrantTypes: p.AllowedGrantTypes}, nil
}

func (a *api) getRegPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.dcr(w)
	if !ok {
		return
	}
	p, err := a.policyOf(r, st, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// putRegPolicy replaces the policy. Omitted allowedGrantTypes means all three
// DCR grant types; omitted maxClients is rejected so a typo cannot silently
// reset the cap.
func (a *api) putRegPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.dcr(w)
	if !ok {
		return
	}
	var in policyBody
	present, err := decode(r, &in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !present["maxClients"] || in.MaxClients < 0 || in.MaxClients > policyMaxCap {
		a.fail(w, r, bad("maxClients is required and must be between 0 and 100000"))
		return
	}
	allowed := in.AllowedGrantTypes
	if present["allowedGrantTypes"] {
		if len(allowed) == 0 {
			a.fail(w, r, bad("allowedGrantTypes must not be empty"))
			return
		}
		seen := map[string]bool{}
		for _, g := range allowed {
			if !slices.Contains(core.DCRGrantTypes, g) || seen[g] {
				a.fail(w, r, bad("allowedGrantTypes may contain authorization_code, refresh_token and client_credentials, each once"))
				return
			}
			seen[g] = true
		}
	} else {
		allowed = slices.Clone(core.DCRGrantTypes)
	}
	if err := st.PutRegistrationPolicy(r.Context(), core.RegistrationPolicy{Realm: rl.Name, MaxClients: in.MaxClients, AllowedGrantTypes: allowed}); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "registration-policy", rl.Name)
	writeJSON(w, http.StatusOK, policyBody{MaxClients: in.MaxClients, AllowedGrantTypes: allowed})
}

// listRegistered lists the clients created through the registration endpoint
// (still existing as the same client), so operators can tell them apart from
// admin-created ones.
func (a *api) listRegistered(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.dcr(w)
	if !ok {
		return
	}
	rows, err := st.ListRegisteredClients(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cs, err := a.cfg.Store.ListClients(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	byID := make(map[string]core.Client, len(cs))
	for _, c := range cs {
		byID[c.ClientID] = c
	}
	out := []map[string]any{}
	for _, rc := range rows {
		c, ok := byID[rc.ClientID]
		if !ok || c.ID != rc.ClientUUID {
			continue
		}
		out = append(out, map[string]any{"id": c.ID, "clientId": c.ClientID, "name": c.Name, "enabled": c.Enabled,
			"createdVia": rc.CreatedVia, "initialTokenId": rc.InitialTokenID, "createdAt": rc.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}
