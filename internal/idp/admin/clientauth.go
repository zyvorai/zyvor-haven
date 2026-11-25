// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/oidc"
)

// Per-client authentication method: private_key_jwt, mutual TLS and
// certificate-bound access tokens (see SPEC.md, "Client authentication").
func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}/clients/{id}/authentication"
		m.HandleFunc("GET "+p, a.getClientAuth)
		m.HandleFunc("PUT "+p, a.op("client-authentication", "update", a.putClientAuth))
		m.HandleFunc("DELETE "+p, a.op("client-authentication", "delete", a.deleteClientAuth))
	})
}

type clientAuthBody struct {
	Method          string          `json:"method"`
	JWKS            json.RawMessage `json:"jwks"`
	JWKSURI         string          `json:"jwksUri"`
	SigningAlg      string          `json:"signingAlg"`
	TLSSubjectDN    string          `json:"tlsSubjectDn"`
	TLSSANDNS       string          `json:"tlsSanDns"`
	TLSSANURI       string          `json:"tlsSanUri"`
	TLSSANIP        string          `json:"tlsSanIp"`
	TLSSANEmail     string          `json:"tlsSanEmail"`
	CertBoundTokens bool            `json:"certificateBoundTokens"`
}

func toClientAuthBody(c core.ClientAuth) clientAuthBody {
	b := clientAuthBody{Method: c.Method, JWKS: json.RawMessage("null"), JWKSURI: c.JWKSURI, SigningAlg: c.SigningAlg,
		TLSSubjectDN: c.TLSSubjectDN, TLSSANDNS: c.TLSSANDNS, TLSSANURI: c.TLSSANURI, TLSSANIP: c.TLSSANIP,
		TLSSANEmail: c.TLSSANEmail, CertBoundTokens: c.CertBoundTokens}
	if c.JWKS != "" {
		b.JWKS = json.RawMessage(c.JWKS)
	}
	return b
}

// clientAuthOf loads the realm, the store and the client of a request.
func (a *api) clientAuthOf(w http.ResponseWriter, r *http.Request) (core.Realm, core.ClientAuthStore, core.Client, bool) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return rl, nil, core.Client{}, false
	}
	st, ok := core.StoreAs[core.ClientAuthStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "this store does not support client authentication settings")
		return rl, nil, core.Client{}, false
	}
	cl, err := a.cfg.Store.GetClient(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return rl, nil, core.Client{}, false
	}
	return rl, st, cl, true
}

func (a *api) getClientAuth(w http.ResponseWriter, r *http.Request) {
	rl, st, cl, ok := a.clientAuthOf(w, r)
	if !ok {
		return
	}
	c, err := st.GetClientAuth(r.Context(), rl.Name, cl.ID)
	if err != nil { // 404 when the client has no method configured
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toClientAuthBody(c))
}

func (a *api) putClientAuth(w http.ResponseWriter, r *http.Request) {
	rl, st, cl, ok := a.clientAuthOf(w, r)
	if !ok {
		return
	}
	var in clientAuthBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	jwks := ""
	if t := bytes.TrimSpace(in.JWKS); len(t) > 0 && !bytes.Equal(t, []byte("null")) {
		jwks = string(t)
	}
	c, err := oidc.ValidateClientAuth(core.ClientAuth{Method: in.Method, JWKS: jwks, JWKSURI: in.JWKSURI,
		SigningAlg: in.SigningAlg, TLSSubjectDN: in.TLSSubjectDN, TLSSANDNS: in.TLSSANDNS, TLSSANURI: in.TLSSANURI,
		TLSSANIP: in.TLSSANIP, TLSSANEmail: in.TLSSANEmail, CertBoundTokens: in.CertBoundTokens},
		cl.Public, a.cfg.AllowPrivateUpstreams)
	if err != nil {
		a.fail(w, r, bad(err.Error()))
		return
	}
	strong := core.StrongClientAuth(c.Method)
	// The console and bootstrap sign in with the admin client's secret: taking
	// it away would lock the operator out.
	if (strong || c.CertBoundTokens) && strings.EqualFold(rl.Name, a.cfg.AdminRealm) && slices.Contains(a.cfg.AdminClients, cl.ClientID) {
		writeErr(w, http.StatusConflict, "the admin client must keep secret authentication")
		return
	}
	c.Realm, c.ClientRef = rl.Name, cl.ID
	if err := st.PutClientAuth(r.Context(), c); err != nil {
		a.fail(w, r, err)
		return
	}
	// A key or certificate client keeps no secret: nothing to fall back to,
	// not even after these settings are deleted.
	if strong && cl.SecretHash != "" {
		cl.SecretHash = ""
		if err := a.cfg.Store.UpdateClient(r.Context(), cl); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	a.audit(r, rl, "UPDATE", "client-authentication", cl.ClientID+" "+c.Method) // never the keys
	writeJSON(w, http.StatusOK, toClientAuthBody(c))
}

func (a *api) deleteClientAuth(w http.ResponseWriter, r *http.Request) {
	rl, st, cl, ok := a.clientAuthOf(w, r)
	if !ok {
		return
	}
	if _, err := st.GetClientAuth(r.Context(), rl.Name, cl.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := st.DeleteClientAuth(r.Context(), rl.Name, cl.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "client-authentication", cl.ClientID)
	noContent(w)
}

// strongClientAuth reports whether the client authenticates with a key or
// certificate, in which case it must not be given a secret. An error means
// "cannot tell" and must refuse the change.
func (a *api) strongClientAuth(r *http.Request, realm string, cl core.Client) (bool, error) {
	st, ok := core.StoreAs[core.ClientAuthStore](a.cfg.Store)
	if !ok {
		return false, nil
	}
	c, err := st.GetClientAuth(r.Context(), realm, cl.ID)
	if errors.Is(err, idp.ErrNotFound) {
		return false, nil
	}
	return err == nil && core.StrongClientAuth(c.Method), err
}
