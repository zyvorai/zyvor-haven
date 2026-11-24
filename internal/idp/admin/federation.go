// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/upstream"
)

// Identity brokering Admin API (see SPEC.md "Identity providers").

const (
	secretMask       = "**********"
	maxProvidersPer  = 50
	maxSecretLen     = 4096
	secretUnsetError = "HAVEN_IDP_SECRET_KEY is not set: identity-provider client secrets cannot be stored"
)

func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}"
		m.HandleFunc("GET "+p+"/identity-providers", a.listIdPs)
		m.HandleFunc("POST "+p+"/identity-providers", a.op("identity-provider", "create", a.createIdP))
		m.HandleFunc("GET "+p+"/identity-providers/{alias}", a.getIdP)
		m.HandleFunc("PUT "+p+"/identity-providers/{alias}", a.op("identity-provider", "update", a.updateIdP))
		m.HandleFunc("DELETE "+p+"/identity-providers/{alias}", a.op("identity-provider", "delete", a.deleteIdP))
		m.HandleFunc("GET "+p+"/users/{id}/federated-identities", a.listFedIdentities)
		m.HandleFunc("DELETE "+p+"/users/{id}/federated-identities/{alias}", a.op("federated-identity", "delete", a.unlinkFedIdentity))
	})
}

func (a *api) fedStore() (core.FedStore, bool) { return core.StoreAs[core.FedStore](a.cfg.Store) }

// fedWire maps a stored provider to the wire shape. The client secret is
// write-only: only the mask is shown, and only when one is stored.
func (a *api) fedWire(p core.FedProvider) idp.IdentityProvider {
	cfg := make(map[string]string, len(p.Config)+2)
	for k, v := range p.Config {
		cfg[k] = v
	}
	if spec, _, err := upstream.ParseConfig(p.ProviderType, p.Config, a.cfg.AllowPrivateUpstreams); err == nil && p.ProviderType != upstream.TypeOIDC {
		cfg[upstream.KeyIssuer] = strings.Replace(spec.Issuer, "{tenantid}", spec.Tenant, 1)
	}
	if p.ClientSecretSealed != "" {
		cfg[upstream.KeyClientSecret] = secretMask
	}
	return idp.IdentityProvider{Alias: p.Alias, DisplayName: p.DisplayName, ProviderID: p.ProviderType,
		Enabled: p.Enabled, TrustEmail: p.TrustEmail, Config: cfg}
}

func (a *api) listIdPs(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	out := []idp.IdentityProvider{}
	if fs, have := a.fedStore(); have {
		ps, err := fs.ListFedProviders(r.Context(), rl.Name)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		for _, p := range ps {
			out = append(out, a.fedWire(p))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) getIdP(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	fs, have := a.fedStore()
	if !have {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	p, err := fs.GetFedProvider(r.Context(), rl.Name, r.PathValue("alias"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.fedWire(p))
}

// fedInput validates a wire provider and returns the stored form (without a
// sealed secret) and the plaintext secret to store ("" = none supplied).
func (a *api) fedInput(in idp.IdentityProvider) (core.FedProvider, string, error) {
	if in.StoreToken {
		return core.FedProvider{}, "", bad("storeToken is not supported: upstream tokens are never stored")
	}
	if in.FirstBrokerLoginFlowAlias != "" {
		return core.FedProvider{}, "", bad("firstBrokerLoginFlowAlias is not supported")
	}
	if !upstream.ValidAlias(in.Alias) {
		return core.FedProvider{}, "", bad("alias must match [a-z0-9-]{1,32}")
	}
	if !validText(in.DisplayName, 64) {
		return core.FedProvider{}, "", bad("invalid displayName")
	}
	cfg := make(map[string]string, len(in.Config))
	secret := ""
	for k, v := range in.Config {
		if k == upstream.KeyClientSecret {
			if v != secretMask {
				secret = v
			}
			continue
		}
		cfg[k] = v
	}
	if len(secret) > maxSecretLen || strings.ContainsAny(secret, "\x00\r\n") {
		return core.FedProvider{}, "", bad("invalid clientSecret")
	}
	_, canon, err := upstream.ParseConfig(in.ProviderID, cfg, a.cfg.AllowPrivateUpstreams)
	if err != nil {
		return core.FedProvider{}, "", bad(err.Error())
	}
	name := in.DisplayName
	if name == "" {
		name = map[string]string{upstream.TypeGoogle: "Google", upstream.TypeMicrosoft: "Microsoft"}[in.ProviderID]
	}
	if name == "" {
		name = in.Alias
	}
	return core.FedProvider{Alias: in.Alias, DisplayName: name, ProviderType: in.ProviderID,
		Enabled: in.Enabled, TrustEmail: in.TrustEmail, Config: canon}, secret, nil
}

func (a *api) sealSecret(realm, alias, secret string) (string, error) {
	if a.cfg.SecretBox == nil {
		return "", &httpErr{http.StatusConflict, secretUnsetError}
	}
	return a.cfg.SecretBox.Seal([]byte(secret), "idp|"+realm+"|"+alias), nil
}

func (a *api) createIdP(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	fs, have := a.fedStore()
	if !have {
		notImplemented(w, "identity federation is not available on this store")
		return
	}
	var in idp.IdentityProvider
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	p, secret, err := a.fedInput(in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	p.Realm = rl.Name
	if secret != "" {
		if p.ClientSecretSealed, err = a.sealSecret(rl.Name, p.Alias, secret); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	if existing, err := fs.ListFedProviders(r.Context(), rl.Name); err == nil && len(existing) >= maxProvidersPer {
		a.fail(w, r, bad("too many identity providers in this realm"))
		return
	}
	now := a.cfg.Clock().UTC()
	p.CreatedAt, p.UpdatedAt = now, now
	if err := fs.CreateFedProvider(r.Context(), p); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "CREATE", "identity-provider", p.Alias)
	created(w, pathPrefix+"/realms/"+rl.Name+"/identity-providers/"+p.Alias, map[string]string{"alias": p.Alias})
}

func (a *api) updateIdP(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	fs, have := a.fedStore()
	if !have {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	cur, err := fs.GetFedProvider(r.Context(), rl.Name, r.PathValue("alias"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in idp.IdentityProvider
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.Alias == "" {
		in.Alias = cur.Alias
	}
	if in.Alias != cur.Alias {
		a.fail(w, r, bad("alias cannot be changed"))
		return
	}
	p, secret, err := a.fedInput(in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	p.Realm, p.CreatedAt, p.UpdatedAt = rl.Name, cur.CreatedAt, a.cfg.Clock().UTC()
	p.ClientSecretSealed = cur.ClientSecretSealed // absent or masked: keep the stored secret
	if secret != "" {
		if p.ClientSecretSealed, err = a.sealSecret(rl.Name, p.Alias, secret); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	if err := fs.UpdateFedProvider(r.Context(), p); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "identity-provider", p.Alias)
	noContent(w)
}

func (a *api) deleteIdP(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	fs, have := a.fedStore()
	if !have {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	alias := r.PathValue("alias")
	if err := fs.DeleteFedProvider(r.Context(), rl.Name, alias); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "identity-provider", alias)
	noContent(w)
}

// fedIdentityWire follows the standard federated-identity representation:
// identityProvider is the alias, userId the upstream subject.
type fedIdentityWire struct {
	IdentityProvider string `json:"identityProvider"`
	UserID           string `json:"userId"`
	UserName         string `json:"userName"`
	CreatedAt        int64  `json:"createdAt"`
	LastLoginAt      int64  `json:"lastLoginAt"`
}

func (a *api) listFedIdentities(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := []fedIdentityWire{}
	if fs, have := a.fedStore(); have {
		ls, err := fs.ListFedLinksByUser(r.Context(), rl.Name, u.ID)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		for _, l := range ls {
			out = append(out, fedIdentityWire{IdentityProvider: l.Alias, UserID: l.Subject,
				CreatedAt: l.CreatedAt.UnixMilli(), LastLoginAt: l.LastLoginAt.UnixMilli()})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) unlinkFedIdentity(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	fs, have := a.fedStore()
	if !have {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err := fs.DeleteFedLink(r.Context(), rl.Name, r.PathValue("alias"), u.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "federated-identity", u.Username+" "+r.PathValue("alias"))
	noContent(w)
}

// dropFedLinks removes a deleted user's federated identities. The pg schema
// cascades already; this covers stores without foreign keys.
func (a *api) dropFedLinks(ctx context.Context, realm, userID string) {
	fs, have := a.fedStore()
	if !have {
		return
	}
	if _, err := fs.DeleteFedLinksForUser(ctx, realm, userID); err != nil && !errors.Is(err, idp.ErrNotFound) {
		a.cfg.Logger.Error("admin: drop federated identities", "err", err.Error())
	}
}
