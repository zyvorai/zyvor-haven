// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/oidc"
)

// Per-client FAPI settings: require PAR, require DPoP, signed request objects
// and RFC 9396 detail types (see SPEC.md, "FAPI building blocks").
func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}/clients/{id}/fapi"
		m.HandleFunc("GET "+p, a.getClientFAPI)
		m.HandleFunc("PUT "+p, a.op("client-fapi", "update", a.putClientFAPI))
	})
}

type clientFAPIBody struct {
	RequirePAR           bool            `json:"requirePar"`
	RequireDPoP          bool            `json:"requireDpop"`
	RequireSignedRequest bool            `json:"requireSignedRequest"`
	JWKS                 json.RawMessage `json:"jwks"`
	AuthzDetailTypes     []string        `json:"authorizationDetailTypes"`
}

const maxDetailTypes = 20

func (a *api) fapiStore(w http.ResponseWriter) (core.FAPIStore, bool) {
	st, ok := core.StoreAs[core.FAPIStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "this store does not support FAPI client settings")
		return nil, false
	}
	return st, true
}

func toClientFAPIBody(c core.ClientFAPI) clientFAPIBody {
	types := c.AuthzDetailTypes
	if types == nil {
		types = []string{}
	}
	b := clientFAPIBody{RequirePAR: c.RequirePAR, RequireDPoP: c.RequireDPoP, RequireSignedRequest: c.RequireSignedRequest,
		AuthzDetailTypes: types, JWKS: json.RawMessage("null")}
	if c.JWKS != "" {
		b.JWKS = json.RawMessage(c.JWKS)
	}
	return b
}

func (a *api) getClientFAPI(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.fapiStore(w)
	if !ok {
		return
	}
	cl, err := a.cfg.Store.GetClient(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := st.GetClientFAPI(r.Context(), rl.Name, cl.ID)
	if err != nil && !errors.Is(err, idp.ErrNotFound) {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toClientFAPIBody(c))
}

func (a *api) putClientFAPI(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.fapiStore(w)
	if !ok {
		return
	}
	cl, err := a.cfg.Store.GetClient(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in clientFAPIBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	jwks := ""
	if t := bytes.TrimSpace(in.JWKS); len(t) > 0 && !bytes.Equal(t, []byte("null")) {
		jwks = string(t)
		if err := oidc.ValidateJARKeys(jwks); err != nil {
			a.fail(w, r, bad("jwks must be a JWKS document with at least one usable public key (EC P-256, or RSA 2048-8192 bits; no private members)"))
			return
		}
	}
	if (in.RequirePAR || in.RequireSignedRequest) && cl.Public {
		a.fail(w, r, bad("requirePar and requireSignedRequest need a confidential client: the PAR endpoint authenticates the client"))
		return
	}
	if in.RequireSignedRequest && jwks == "" {
		a.fail(w, r, bad("requireSignedRequest needs jwks"))
		return
	}
	if len(in.AuthzDetailTypes) > maxDetailTypes {
		a.fail(w, r, bad("too many authorizationDetailTypes"))
		return
	}
	seen := map[string]bool{}
	var types []string
	for _, t := range in.AuthzDetailTypes {
		if !oidc.ValidAuthzDetailType(t) {
			a.fail(w, r, bad("invalid authorizationDetailTypes entry"))
			return
		}
		if !seen[t] {
			seen[t] = true
			types = append(types, t)
		}
	}
	c := core.ClientFAPI{Realm: rl.Name, ClientRef: cl.ID, RequirePAR: in.RequirePAR, RequireDPoP: in.RequireDPoP,
		RequireSignedRequest: in.RequireSignedRequest, JWKS: jwks, AuthzDetailTypes: types}
	if err := st.PutClientFAPI(r.Context(), c); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "client-fapi", cl.ClientID) // never the keys
	writeJSON(w, http.StatusOK, toClientFAPIBody(c))
}
