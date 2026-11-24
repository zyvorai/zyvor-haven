// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/safehttp"
	"github.com/zyvorai/haven/internal/idp/upstream"
)

// Workload identities and agent/MCP identities (see SPEC.md and
// docs/workload-identity.md, docs/agent-identities.md). Credential secrets are
// returned once, at creation, and never again.

func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		w := pathPrefix + "/realms/{r}/workload-identities"
		m.HandleFunc("GET "+w, a.listWorkloads)
		m.HandleFunc("POST "+w, a.op("workload-identity", "create", a.createWorkload))
		m.HandleFunc("GET "+w+"/{id}", a.getWorkload)
		m.HandleFunc("POST "+w+"/{id}/enable", a.op("workload-identity", "update", a.setWorkloadEnabled(true)))
		m.HandleFunc("POST "+w+"/{id}/disable", a.op("workload-identity", "update", a.setWorkloadEnabled(false)))
		m.HandleFunc("DELETE "+w+"/{id}", a.op("workload-identity", "delete", a.deleteWorkload))

		g := pathPrefix + "/realms/{r}/agents"
		m.HandleFunc("GET "+g, a.listAgents)
		m.HandleFunc("POST "+g, a.op("agent", "create", a.createAgent))
		m.HandleFunc("GET "+g+"/{id}", a.getAgent)
		m.HandleFunc("POST "+g+"/{id}/enable", a.op("agent", "update", a.setAgentEnabled(true)))
		m.HandleFunc("POST "+g+"/{id}/disable", a.op("agent", "update", a.setAgentEnabled(false)))
		m.HandleFunc("DELETE "+g+"/{id}", a.op("agent", "delete", a.deleteAgent))
		m.HandleFunc("GET "+g+"/{id}/credentials", a.listAgentCreds)
		m.HandleFunc("POST "+g+"/{id}/credentials", a.op("agent-credential", "create", a.createAgentCred))
		m.HandleFunc("DELETE "+g+"/{id}/credentials/{cid}", a.op("agent-credential", "delete", a.revokeAgentCred))
		m.HandleFunc("POST "+g+"/{id}/revoke-credentials", a.op("agent-credential", "delete", a.revokeAllAgentCreds))
	})
}

var identNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func (a *api) identEvent(r *http.Request, rl core.Realm, typ, userID, clientID, detail string) {
	if !rl.AdminEventsLogged {
		return
	}
	err := a.cfg.Store.AppendEvent(r.Context(), core.Event{
		Time: a.cfg.Clock().UTC(), Realm: rl.Name, Type: typ, UserID: userID, ClientID: clientID,
		Detail: detail + " by " + actorOf(r),
	})
	if err != nil {
		a.cfg.Logger.Error("admin: append event", "err", err.Error())
	}
}

// checkScopes validates a scope allow-list: non-empty, bounded, well formed,
// no openid/offline_access (these identities never get ID or refresh tokens).
func checkScopes(in []string, max int) ([]string, error) {
	if len(in) == 0 || len(in) > max {
		return nil, bad("scopes must list 1 to " + itoa(max) + " scopes")
	}
	out := []string{}
	for _, s := range in {
		if !core.ScopeRE.MatchString(s) || s == "openid" || s == "offline_access" {
			return nil, bad("invalid scope " + quoteShort(s))
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

func quoteShort(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return "\"" + strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s) + "\""
}

func itoa(n int) string { return strconv.Itoa(n) }

// backingClient builds the inert public client behind an identity: no secret,
// no redirect URIs, every interactive flow off.
func backingClient(realm, clientID, name string) core.Client {
	return core.Client{Realm: realm, ClientID: clientID, Name: name, Enabled: true, Public: true}
}

// ---- workload identities ----

type workloadWire struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ClientID   string    `json:"clientId"`
	Issuer     string    `json:"issuer"`
	JWKSURI    string    `json:"jwksUri,omitempty"`
	InlineJWKS bool      `json:"inlineJwks"`
	Audience   string    `json:"audience"`
	Subject    string    `json:"subject"`
	Scopes     []string  `json:"scopes"`
	TTLSeconds int       `json:"ttlSeconds"`
	Enabled    bool      `json:"enabled"`
	CreatedBy  string    `json:"createdBy"`
	CreatedAt  time.Time `json:"createdAt"`
}

func workloadToWire(w core.WorkloadIdentity) workloadWire {
	return workloadWire{w.ID, w.Name, w.ClientID, w.Issuer, w.JWKSURI, w.JWKS != "", w.Audience, w.Subject,
		append([]string{}, w.AllowedScopes...), w.TTLSeconds, w.Enabled, w.CreatedBy, w.CreatedAt}
}

func (a *api) workloadStore(w http.ResponseWriter) (core.WorkloadStore, bool) {
	ws, ok := core.StoreAs[core.WorkloadStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "workload identities are not available on this store")
	}
	return ws, ok
}

func (a *api) listWorkloads(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	ws, ok := a.workloadStore(w)
	if !ok {
		return
	}
	list, err := ws.ListWorkloadIdentities(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]workloadWire, 0, len(list))
	for _, x := range list {
		out = append(out, workloadToWire(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) getWorkload(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	ws, ok := a.workloadStore(w)
	if !ok {
		return
	}
	x, err := ws.GetWorkloadIdentity(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, workloadToWire(x))
}

func (a *api) createWorkload(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	ws, ok := a.workloadStore(w)
	if !ok {
		return
	}
	var in struct {
		Name       string   `json:"name"`
		ClientID   string   `json:"clientId"`
		Issuer     string   `json:"issuer"`
		JWKSURI    string   `json:"jwksUri"`
		JWKS       string   `json:"jwks"`
		Audience   string   `json:"audience"`
		Subject    string   `json:"subject"`
		Scopes     []string `json:"scopes"`
		TTLSeconds int      `json:"ttlSeconds"`
	}
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if !identNameRE.MatchString(in.Name) {
		a.fail(w, r, bad("name must match "+identNameRE.String()))
		return
	}
	if in.ClientID == "" {
		in.ClientID = "wl-" + in.Name
	}
	if !identNameRE.MatchString(in.ClientID) {
		a.fail(w, r, bad("clientId must match "+identNameRE.String()))
		return
	}
	if _, err := safehttp.ValidateURL(in.Issuer, a.cfg.AllowPrivateUpstreams, "issuer", 512); err != nil {
		a.fail(w, r, bad(err.Error()))
		return
	}
	// Strict, exact pins: no wildcards anywhere.
	for what, v := range map[string]string{"audience": in.Audience, "subject": in.Subject} {
		if v == "" || len(v) > 255 || !validText(v, 255) || strings.ContainsAny(v, "*?") || strings.TrimSpace(v) != v {
			a.fail(w, r, bad(what+" is required, exact (no wildcards), at most 255 characters"))
			return
		}
	}
	switch {
	case (in.JWKSURI == "") == (in.JWKS == ""):
		a.fail(w, r, bad("exactly one of jwksUri and jwks is required"))
		return
	case in.JWKSURI != "":
		if _, err := safehttp.ValidateURL(in.JWKSURI, a.cfg.AllowPrivateUpstreams, "jwksUri", 512); err != nil {
			a.fail(w, r, bad(err.Error()))
			return
		}
	default:
		if len(in.JWKS) > core.MaxWorkloadJWKSBytes {
			a.fail(w, r, bad("jwks is too large"))
			return
		}
		if _, err := upstream.ParseStaticJWKS(in.JWKS); err != nil {
			a.fail(w, r, bad("jwks: "+err.Error()))
			return
		}
	}
	scopes, err := checkScopes(in.Scopes, core.MaxWorkloadScopes)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if in.TTLSeconds == 0 {
		in.TTLSeconds = core.DefaultWorkloadTTLSeconds
	}
	if in.TTLSeconds < 30 || in.TTLSeconds > core.MaxWorkloadTTLSeconds {
		a.fail(w, r, bad("ttlSeconds must be between 30 and "+itoa(core.MaxWorkloadTTLSeconds)))
		return
	}
	if cur, _ := ws.ListWorkloadIdentities(r.Context(), rl.Name); len(cur) >= core.MaxWorkloadsPerRealm {
		a.fail(w, r, &httpErr{http.StatusConflict, "too many workload identities in this realm"})
		return
	}
	ctx := r.Context()
	if err := a.cfg.Store.CreateClient(ctx, backingClient(rl.Name, in.ClientID, "workload: "+in.Name)); err != nil {
		a.fail(w, r, err) // a clientId that already exists is a 409: an existing client is never adopted
		return
	}
	x, err := ws.CreateWorkloadIdentity(ctx, core.WorkloadIdentity{Realm: rl.Name, Name: in.Name, ClientID: in.ClientID,
		Issuer: in.Issuer, JWKSURI: in.JWKSURI, JWKS: in.JWKS, Audience: in.Audience, Subject: in.Subject,
		AllowedScopes: scopes, TTLSeconds: in.TTLSeconds, Enabled: true, CreatedBy: actorOf(r), CreatedAt: a.cfg.Clock().UTC()})
	if err != nil {
		a.dropClient(r, rl.Name, in.ClientID)
		a.fail(w, r, err)
		return
	}
	a.identEvent(r, rl, "WORKLOAD_IDENTITY_CREATE", "", x.ClientID, "workload "+x.Name+" subject "+x.Subject)
	writeJSON(w, http.StatusCreated, workloadToWire(x))
}

// dropClient removes a backing client (best effort, logged).
func (a *api) dropClient(r *http.Request, realm, clientID string) {
	c, err := a.cfg.Store.GetClientByClientID(r.Context(), realm, clientID)
	if err == nil {
		err = a.cfg.Store.DeleteClient(r.Context(), realm, c.ID)
	}
	if err != nil && !errors.Is(err, idp.ErrNotFound) {
		a.cfg.Logger.Error("admin: delete identity client", "err", err.Error())
	}
}

func (a *api) setWorkloadEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rl, ok := a.realmOf(w, r)
		if !ok {
			return
		}
		ws, ok := a.workloadStore(w)
		if !ok {
			return
		}
		x, err := ws.SetWorkloadEnabled(r.Context(), rl.Name, r.PathValue("id"), enabled)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		typ := "WORKLOAD_IDENTITY_DISABLE"
		if enabled {
			typ = "WORKLOAD_IDENTITY_ENABLE"
		}
		a.identEvent(r, rl, typ, "", x.ClientID, "workload "+x.Name)
		writeJSON(w, http.StatusOK, workloadToWire(x))
	}
}

func (a *api) deleteWorkload(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	ws, ok := a.workloadStore(w)
	if !ok {
		return
	}
	x, err := ws.GetWorkloadIdentity(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := ws.DeleteWorkloadIdentity(r.Context(), rl.Name, x.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.dropClient(r, rl.Name, x.ClientID)
	a.identEvent(r, rl, "WORKLOAD_IDENTITY_DELETE", "", x.ClientID, "workload "+x.Name)
	noContent(w)
}

// ---- agents ----

type agentWire struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	ClientID    string    `json:"clientId"`
	OwnerUserID string    `json:"ownerUserId"`
	Scopes      []string  `json:"scopes"`
	Roles       []string  `json:"roles"`
	Audiences   []string  `json:"audiences"`
	TokenTTL    int       `json:"tokenTtlSeconds"`
	Enabled     bool      `json:"enabled"`
	CreatedBy   string    `json:"createdBy"`
	CreatedAt   time.Time `json:"createdAt"`
}

func agentToWire(g core.Agent) agentWire {
	return agentWire{g.ID, g.Name, g.Kind, g.ClientID, g.OwnerUserID, append([]string{}, g.AllowedScopes...),
		append([]string{}, g.AllowedRoles...), append([]string{}, g.Audiences...), g.TokenTTL, g.Enabled, g.CreatedBy, g.CreatedAt}
}

type credWire struct {
	ID         string     `json:"id"`
	Scopes     []string   `json:"scopes"`
	Note       string     `json:"note"`
	State      string     `json:"state"` // active | revoked | expired
	CreatedBy  string     `json:"createdBy"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	RevokedBy  string     `json:"revokedBy,omitempty"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

func credToWire(c core.AgentCredential, now time.Time) credWire {
	out := credWire{ID: c.ID, Scopes: append([]string{}, c.Scopes...), Note: c.Note, State: "active", CreatedBy: c.CreatedBy,
		CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt, RevokedBy: c.RevokedBy}
	if !c.RevokedAt.IsZero() {
		t := c.RevokedAt
		out.RevokedAt, out.State = &t, "revoked"
	} else if !now.Before(c.ExpiresAt) {
		out.State = "expired"
	}
	if !c.LastUsedAt.IsZero() {
		t := c.LastUsedAt
		out.LastUsedAt = &t
	}
	return out
}

func (a *api) agentStore(w http.ResponseWriter) (core.AgentStore, bool) {
	as, ok := core.StoreAs[core.AgentStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "agent identities are not available on this store")
	}
	return as, ok
}

func (a *api) listAgents(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	as, ok := a.agentStore(w)
	if !ok {
		return
	}
	list, err := as.ListAgents(r.Context(), rl.Name, r.URL.Query().Get("owner"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]agentWire, 0, len(list))
	for _, x := range list {
		out = append(out, agentToWire(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) getAgent(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	as, ok := a.agentStore(w)
	if !ok {
		return
	}
	x, err := as.GetAgent(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, agentToWire(x))
}

func (a *api) createAgent(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	as, ok := a.agentStore(w)
	if !ok {
		return
	}
	var in struct {
		Name        string   `json:"name"`
		OwnerUserID string   `json:"ownerUserId"`
		Scopes      []string `json:"scopes"`
		Roles       []string `json:"roles"`
		Audiences   []string `json:"audiences"`
		TokenTTL    int      `json:"tokenTtlSeconds"`
	}
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if !identNameRE.MatchString(in.Name) {
		a.fail(w, r, bad("name must match "+identNameRE.String()))
		return
	}
	ctx := r.Context()
	owner, err := a.cfg.Store.GetUser(ctx, rl.Name, in.OwnerUserID)
	if err != nil {
		if isNF(err) {
			a.fail(w, r, bad("ownerUserId does not name a user of this realm"))
		} else {
			a.fail(w, r, err)
		}
		return
	}
	if !owner.Enabled {
		a.fail(w, r, bad("the owner is disabled"))
		return
	}
	scopes, err := checkScopes(in.Scopes, core.MaxAgentScopes)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// Roles must be existing realm roles the OWNER holds (permanent roles):
	// an agent can never be given more than its owner has.
	roles := []string{}
	for _, role := range in.Roles {
		if !slices.Contains(owner.Roles, role) {
			a.fail(w, r, bad("the owner does not hold role "+quoteShort(role)))
			return
		}
		if !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	if len(in.Audiences) > core.MaxAgentAudiences {
		a.fail(w, r, bad("too many audiences"))
		return
	}
	auds := []string{}
	for _, au := range in.Audiences {
		if au == "" || len(au) > 255 || !validText(au, 255) || strings.ContainsAny(au, "* \t") {
			a.fail(w, r, bad("invalid audience "+quoteShort(au)))
			return
		}
		if !slices.Contains(auds, au) {
			auds = append(auds, au)
		}
	}
	if in.TokenTTL == 0 {
		in.TokenTTL = core.DefaultAgentTokenTTLSeconds
	}
	if in.TokenTTL < 30 || in.TokenTTL > core.MaxAgentTokenTTLSeconds {
		a.fail(w, r, bad("tokenTtlSeconds must be between 30 and "+itoa(core.MaxAgentTokenTTLSeconds)))
		return
	}
	if cur, _ := as.ListAgents(ctx, rl.Name, ""); len(cur) >= core.MaxAgentsPerRealm {
		a.fail(w, r, &httpErr{http.StatusConflict, "too many agents in this realm"})
		return
	}
	suffix := make([]byte, 9)
	if _, err := rand.Read(suffix); err != nil {
		a.fail(w, r, err)
		return
	}
	clientID := "agent-" + strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(base64.RawURLEncoding.EncodeToString(suffix)))
	if err := a.cfg.Store.CreateClient(ctx, backingClient(rl.Name, clientID, "agent: "+in.Name)); err != nil {
		a.fail(w, r, err)
		return
	}
	x, err := as.CreateAgent(ctx, core.Agent{Realm: rl.Name, Name: in.Name, Kind: "agent", ClientID: clientID,
		OwnerUserID: owner.ID, AllowedScopes: scopes, AllowedRoles: roles, Audiences: auds, TokenTTL: in.TokenTTL,
		Enabled: true, CreatedBy: actorOf(r), CreatedAt: a.cfg.Clock().UTC()})
	if err != nil {
		a.dropClient(r, rl.Name, clientID)
		a.fail(w, r, err)
		return
	}
	a.identEvent(r, rl, "AGENT_CREATE", owner.ID, x.ClientID, "agent "+x.Name+" scopes "+strings.Join(scopes, " "))
	writeJSON(w, http.StatusCreated, agentToWire(x))
}

func (a *api) setAgentEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rl, ok := a.realmOf(w, r)
		if !ok {
			return
		}
		as, ok := a.agentStore(w)
		if !ok {
			return
		}
		x, err := as.SetAgentEnabled(r.Context(), rl.Name, r.PathValue("id"), enabled)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		typ := "AGENT_DISABLE"
		if enabled {
			typ = "AGENT_ENABLE"
		}
		a.identEvent(r, rl, typ, x.OwnerUserID, x.ClientID, "agent "+x.Name)
		writeJSON(w, http.StatusOK, agentToWire(x))
	}
}

func (a *api) deleteAgent(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	as, ok := a.agentStore(w)
	if !ok {
		return
	}
	x, err := as.GetAgent(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := as.DeleteAgent(r.Context(), rl.Name, x.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.dropClient(r, rl.Name, x.ClientID)
	a.identEvent(r, rl, "AGENT_DELETE", x.OwnerUserID, x.ClientID, "agent "+x.Name)
	noContent(w)
}

func (a *api) agentOf(w http.ResponseWriter, r *http.Request) (core.Realm, core.AgentStore, core.Agent, bool) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return rl, nil, core.Agent{}, false
	}
	as, ok := a.agentStore(w)
	if !ok {
		return rl, nil, core.Agent{}, false
	}
	x, err := as.GetAgent(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return rl, nil, core.Agent{}, false
	}
	return rl, as, x, true
}

func (a *api) listAgentCreds(w http.ResponseWriter, r *http.Request) {
	rl, as, x, ok := a.agentOf(w, r)
	if !ok {
		return
	}
	list, err := as.ListAgentCredentials(r.Context(), rl.Name, x.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	now := a.cfg.Clock().UTC()
	out := make([]credWire, 0, len(list))
	for _, c := range list {
		out = append(out, credToWire(c, now))
	}
	writeJSON(w, http.StatusOK, out)
}

// createAgentCred issues a credential. The secret is in this response only.
func (a *api) createAgentCred(w http.ResponseWriter, r *http.Request) {
	rl, as, x, ok := a.agentOf(w, r)
	if !ok {
		return
	}
	var in struct {
		TTLSeconds int      `json:"ttlSeconds"`
		Scopes     []string `json:"scopes"`
		Note       string   `json:"note"`
	}
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if !x.Enabled {
		a.fail(w, r, &httpErr{http.StatusConflict, "the agent is disabled"})
		return
	}
	if in.TTLSeconds == 0 {
		in.TTLSeconds = core.DefaultCredentialTTLSeconds
	}
	if in.TTLSeconds < 60 || in.TTLSeconds > core.MaxCredentialTTLSeconds {
		a.fail(w, r, bad("ttlSeconds must be between 60 and "+itoa(core.MaxCredentialTTLSeconds)))
		return
	}
	if !validText(in.Note, 200) {
		a.fail(w, r, bad("note is too long or has control characters"))
		return
	}
	scopes := slices.Clone(x.AllowedScopes)
	if len(in.Scopes) > 0 {
		scopes = []string{}
		for _, s := range in.Scopes {
			if !slices.Contains(x.AllowedScopes, s) {
				a.fail(w, r, bad("scope "+quoteShort(s)+" is not allowed for this agent"))
				return
			}
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		a.fail(w, r, err)
		return
	}
	secret := oidc.AgentCredentialPrefix + base64.RawURLEncoding.EncodeToString(raw)
	now := a.cfg.Clock().UTC()
	c, err := as.CreateAgentCredential(r.Context(), core.AgentCredential{Realm: rl.Name, AgentID: x.ID,
		SecretHash: oidc.HashSecret(secret), Scopes: scopes, Note: in.Note, CreatedBy: actorOf(r), CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(in.TTLSeconds) * time.Second)}, core.MaxActiveCredentialsPerAgent, now)
	if errors.Is(err, core.ErrCredentialLimit) {
		a.fail(w, r, &httpErr{http.StatusConflict, "the agent already has the maximum number of active credentials"})
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.identEvent(r, rl, "AGENT_CREDENTIAL_ISSUED", x.OwnerUserID, x.ClientID,
		"agent "+x.Name+" credential "+c.ID+" scopes "+strings.Join(c.Scopes, " ")+" until "+c.ExpiresAt.Format(time.RFC3339))
	writeJSON(w, http.StatusCreated, map[string]any{"credential": credToWire(c, now), "secret": secret,
		"tokenType": "urn:haven:params:oauth:token-type:agent-credential", "clientId": x.ClientID})
}

func (a *api) revokeAgentCred(w http.ResponseWriter, r *http.Request) {
	rl, as, x, ok := a.agentOf(w, r)
	if !ok {
		return
	}
	c, err := as.RevokeAgentCredential(r.Context(), rl.Name, x.ID, r.PathValue("cid"), actorOf(r), a.cfg.Clock().UTC())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.identEvent(r, rl, "AGENT_CREDENTIAL_REVOKED", x.OwnerUserID, x.ClientID, "agent "+x.Name+" credential "+c.ID)
	noContent(w)
}

func (a *api) revokeAllAgentCreds(w http.ResponseWriter, r *http.Request) {
	rl, as, x, ok := a.agentOf(w, r)
	if !ok {
		return
	}
	n, err := as.RevokeAgentCredentials(r.Context(), rl.Name, x.ID, actorOf(r), a.cfg.Clock().UTC())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.identEvent(r, rl, "AGENT_CREDENTIAL_REVOKED", x.OwnerUserID, x.ClientID, "agent "+x.Name+" all credentials")
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}
