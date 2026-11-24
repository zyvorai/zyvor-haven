// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
	"github.com/zyvorai/haven/internal/idp/upstream"
)

// Workload identities and agent/MCP identities (docs/workload-identity.md,
// docs/agent-identities.md). Both are served by the RFC 8693 token-exchange
// grant, dispatched on subject_token_type:
//
//	urn:ietf:params:oauth:token-type:jwt                  a platform JWT (workload)
//	urn:haven:params:oauth:token-type:agent-credential    an agent credential
//
// Workloads can also use the RFC 7523 jwt-bearer grant (assertion=<JWT>).
// Both client kinds are public, secretless clients with every interactive
// flow switched off; the proof of identity is the subject token / assertion.
// Everything is OFF unless the store has the matching extension, and every
// check fails closed.

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	grantJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	ttJWT              = "urn:ietf:params:oauth:token-type:jwt"
	ttAccess           = "urn:ietf:params:oauth:token-type:access_token"
	ttAgentCredential  = "urn:haven:params:oauth:token-type:agent-credential"

	// AgentCredentialPrefix starts every agent credential secret.
	AgentCredentialPrefix = "hvag_"

	identLimitWindow = time.Minute
	identLimitMax    = 60
	maxAgentSecret   = 128
)

func init() {
	registerGrant(grantTokenExchange, (*Provider).grantTokenExchange)
	registerGrant(grantJWTBearer, (*Provider).grantJWTBearer)
	registerFeature(func(p *Provider, _ *http.ServeMux) {
		if p.cfg.Federation == nil {
			p.cfg.Federation = upstream.NewManager(safehttp.Options{}, p.cfg.Clock)
		}
	})
	registerDiscovery(func(p *Provider, _ string, doc map[string]any) {
		_, wl := core.StoreAs[core.WorkloadStore](p.cfg.Store)
		_, ag := core.StoreAs[core.AgentStore](p.cfg.Store)
		if !wl && !ag {
			return
		}
		if g, ok := doc["grant_types_supported"].([]string); ok {
			g = slices.Clone(g)
			g = append(g, grantTokenExchange)
			if wl {
				g = append(g, grantJWTBearer)
			}
			doc["grant_types_supported"] = g
		}
	})
}

// identClient requires the calling client to be a plain public client: no
// secret, no interactive flow. If an administrator turns a flow on for the
// backing client, the identity stops working (fail closed).
func identClient(cl core.Client, confidential bool) bool {
	return cl.Enabled && cl.Public && !confidential &&
		!cl.AuthCodeFlow && !cl.PasswordFlow && !cl.ServiceAccount && !cl.DeviceFlow
}

func serverErr() *tokenErr {
	return &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
}

// identLimit counts one attempt for (purpose, realm, ip, client). It reports
// false when over the limit; a store error is an error (callers fail closed).
func (p *Provider) identLimit(r *http.Request, purpose, realm, client string) (bool, error) {
	sum := sha256.Sum256([]byte(purpose + "|" + realm + "|" + p.clientIP(r) + "|" + client))
	return p.cfg.Store.HitRateLimit(r.Context(), hex.EncodeToString(sum[:]), p.now(), identLimitWindow, identLimitMax)
}

// parseScopes splits and validates a requested scope list. ok is false when
// any entry is malformed (it never silently drops one).
func parseScopes(raw string) ([]string, bool) {
	var out []string
	for _, s := range strings.Fields(raw) {
		if !core.ScopeRE.MatchString(s) {
			return nil, false
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, true
}

// narrowScopes returns the scopes to issue: the request (or, when absent, all
// of allowed), which must be a subset of allowed. ok=false: scope exceeds.
func narrowScopes(requested string, allowed []string) ([]string, bool) {
	want, ok := parseScopes(requested)
	if !ok {
		return nil, false
	}
	if len(want) == 0 {
		return slices.Clone(allowed), len(allowed) > 0
	}
	for _, s := range want {
		if !slices.Contains(allowed, s) {
			return nil, false
		}
	}
	return want, true
}

func (p *Provider) accessTTL(rl core.Realm, want int) time.Duration {
	ttl := rl.AccessTokenTTL
	if ttl <= 0 {
		ttl = defaultAccess
	}
	if want > 0 && time.Duration(want)*time.Second < ttl {
		ttl = time.Duration(want) * time.Second
	}
	return ttl
}

// ---- grant entry points ----

func (p *Provider) grantTokenExchange(r *http.Request, rl core.Realm, cl core.Client, confidential bool) (map[string]any, *tokenErr) {
	f := r.PostForm
	// Only impersonation-free exchanges of our two subject token types are
	// supported; anything else is refused instead of ignored.
	for _, k := range []string{"actor_token", "actor_token_type"} {
		if f.Get(k) != "" {
			return nil, oerr("invalid_request", "actor_token is not supported")
		}
	}
	if t := f.Get("requested_token_type"); t != "" && t != ttAccess {
		return nil, oerr("invalid_request", "only access_token can be requested")
	}
	if len(f["subject_token"]) != 1 || f.Get("subject_token") == "" {
		return nil, oerr("invalid_request", "exactly one subject_token is required")
	}
	switch f.Get("subject_token_type") {
	case ttJWT:
		return p.exchangeWorkload(r, rl, cl, confidential, f.Get("subject_token"), grantTokenExchange)
	case ttAgentCredential:
		return p.exchangeAgent(r, rl, cl, confidential, f.Get("subject_token"))
	}
	return nil, oerr("invalid_request", "unsupported subject_token_type")
}

func (p *Provider) grantJWTBearer(r *http.Request, rl core.Realm, cl core.Client, confidential bool) (map[string]any, *tokenErr) {
	if len(r.PostForm["assertion"]) != 1 || r.PostForm.Get("assertion") == "" {
		return nil, oerr("invalid_request", "exactly one assertion is required")
	}
	return p.exchangeWorkload(r, rl, cl, confidential, r.PostForm.Get("assertion"), grantJWTBearer)
}

// ---- workload identities ----

func (p *Provider) exchangeWorkload(r *http.Request, rl core.Realm, cl core.Client, confidential bool, subjectToken, grant string) (map[string]any, *tokenErr) {
	ws, ok := core.StoreAs[core.WorkloadStore](p.cfg.Store)
	if !ok {
		return nil, &tokenErr{http.StatusNotImplemented, "feature_unavailable", "workload identity is not available"}
	}
	ctx := r.Context()
	ip := p.clientIP(r)
	if !identClient(cl, confidential) {
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	if allowed, err := p.identLimit(r, "workload", rl.Name, cl.ClientID); err != nil {
		p.cfg.Logger.Error("oidc: workload rate limit", "err", err)
		return nil, serverErr()
	} else if !allowed {
		return nil, &tokenErr{http.StatusTooManyRequests, "slow_down", "too many attempts"}
	}
	w, err := ws.GetWorkloadIdentityByClient(ctx, rl.Name, cl.ClientID)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load workload identity", "err", err)
			return nil, serverErr()
		}
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	deny := func(reason string) (map[string]any, *tokenErr) {
		p.event(ctx, rl, "WORKLOAD_TOKEN_ERROR", "", cl.ClientID, ip, "workload="+w.Name+" reason="+reason)
		return nil, oerr("invalid_grant", "subject token rejected")
	}
	if !w.Enabled {
		return deny("disabled")
	}
	scopes, sok := narrowScopes(r.PostForm.Get("scope"), w.AllowedScopes)
	if !sok {
		p.event(ctx, rl, "WORKLOAD_TOKEN_ERROR", "", cl.ClientID, ip, "workload="+w.Name+" reason=scope")
		return nil, oerr("invalid_scope", "scope exceeds what this workload may request")
	}
	if r.PostForm.Get("audience") != "" || r.PostForm.Get("resource") != "" {
		return nil, oerr("invalid_target", "audience and resource are not supported for workload tokens")
	}
	_, verr := p.cfg.Federation.VerifyJWT(ctx, upstream.JWTSpec{
		Issuer: w.Issuer, Audience: w.Audience, Subject: w.Subject, JWKSURI: w.JWKSURI, StaticJWKS: w.JWKS,
	}, subjectToken)
	if verr != nil {
		kind := "invalid"
		var ue *upstream.Error
		if errors.As(verr, &ue) {
			kind = ue.Kind
		}
		return deny(kind)
	}
	if err := p.ensureKey(ctx, rl.Name); err != nil {
		p.cfg.Logger.Error("oidc: ensure key", "err", err)
		return nil, serverErr()
	}
	now := p.now()
	wantTTL := w.TTLSeconds
	if wantTTL <= 0 {
		wantTTL = core.DefaultWorkloadTTLSeconds
	}
	ttl := p.accessTTL(rl, min(wantTTL, core.MaxWorkloadTTLSeconds))
	scope := strings.Join(scopes, " ")
	at, err := p.cfg.Signer.Sign(ctx, rl.Name, core.Claims{
		"iss": p.issuer(rl.Name), "sub": "workload-" + cl.ClientID, "aud": cl.ClientID, "azp": cl.ClientID,
		"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "jti": randToken(16),
		"typ": "Bearer", "scope": scope, "client_id": cl.ClientID,
		"workload_issuer": w.Issuer, "workload_subject": w.Subject,
		"realm_access": map[string]any{"roles": []string{}},
	})
	if err != nil {
		p.cfg.Logger.Error("oidc: sign workload token", "err", err)
		return nil, serverErr()
	}
	p.event(ctx, rl, "WORKLOAD_TOKEN", "", cl.ClientID, ip, "workload="+w.Name+" scope="+scope)
	p.cfg.Obs.TokenIssued(rl.Name, "token_exchange", "access")
	return exchangeResponse(at, ttl, scope), nil
}

func exchangeResponse(at string, ttl time.Duration, scope string) map[string]any {
	return map[string]any{"access_token": at, "issued_token_type": ttAccess, "token_type": "Bearer",
		"expires_in": int(ttl.Seconds()), "scope": scope}
}

// ---- agent identities ----

func (p *Provider) exchangeAgent(r *http.Request, rl core.Realm, cl core.Client, confidential bool, secret string) (map[string]any, *tokenErr) {
	as, ok := core.StoreAs[core.AgentStore](p.cfg.Store)
	if !ok {
		return nil, &tokenErr{http.StatusNotImplemented, "feature_unavailable", "agent identities are not available"}
	}
	ctx := r.Context()
	ip := p.clientIP(r)
	if !identClient(cl, confidential) {
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	if allowed, err := p.identLimit(r, "agent", rl.Name, cl.ClientID); err != nil {
		p.cfg.Logger.Error("oidc: agent rate limit", "err", err)
		return nil, serverErr()
	} else if !allowed {
		return nil, &tokenErr{http.StatusTooManyRequests, "slow_down", "too many attempts"}
	}
	ag, err := as.GetAgentByClient(ctx, rl.Name, cl.ClientID)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load agent", "err", err)
			return nil, serverErr()
		}
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	deny := func(reason string) (map[string]any, *tokenErr) {
		p.event(ctx, rl, "AGENT_TOKEN_ERROR", ag.OwnerUserID, cl.ClientID, ip, "agent="+ag.Name+" reason="+reason)
		return nil, oerr("invalid_grant", "agent credential rejected")
	}
	if !ag.Enabled || ag.Kind != "agent" {
		return deny("disabled")
	}
	if !strings.HasPrefix(secret, AgentCredentialPrefix) || len(secret) > maxAgentSecret {
		return deny("malformed")
	}
	cred, err := as.GetAgentCredentialBySecret(ctx, rl.Name, ag.ID, HashSecret(secret))
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load agent credential", "err", err)
			return nil, serverErr()
		}
		return deny("unknown_credential")
	}
	now := p.now()
	if !cred.RevokedAt.IsZero() {
		return deny("revoked")
	}
	if !now.Before(cred.ExpiresAt) {
		return deny("expired")
	}
	// The agent acts for its owner; a missing or disabled owner ends it.
	owner, err := p.cfg.Store.GetUser(ctx, rl.Name, ag.OwnerUserID)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load agent owner", "err", err)
			return nil, serverErr()
		}
		return deny("owner_missing")
	}
	if !owner.Enabled {
		return deny("owner_disabled")
	}
	// Scopes: the credential's scopes, narrowed to what the agent may still
	// have (the agent's list can shrink after a credential was issued).
	allowed := slices.DeleteFunc(slices.Clone(cred.Scopes), func(s string) bool { return !slices.Contains(ag.AllowedScopes, s) })
	scopes, sok := narrowScopes(r.PostForm.Get("scope"), allowed)
	if !sok {
		p.event(ctx, rl, "AGENT_TOKEN_ERROR", ag.OwnerUserID, cl.ClientID, ip, "agent="+ag.Name+" reason=scope")
		return nil, oerr("invalid_scope", "scope exceeds what this credential allows")
	}
	// Audience: at most one, exactly one of the agent's allow-list; default is
	// the agent's own client id.
	aud := cl.ClientID
	req := append(slices.Clone(r.PostForm["audience"]), r.PostForm["resource"]...)
	if len(req) > 1 || (len(req) == 1 && req[0] == "") {
		return nil, oerr("invalid_target", "exactly one audience may be requested")
	}
	if len(req) == 1 {
		if !slices.Contains(ag.Audiences, req[0]) {
			p.event(ctx, rl, "AGENT_TOKEN_ERROR", ag.OwnerUserID, cl.ClientID, ip, "agent="+ag.Name+" reason=audience")
			return nil, oerr("invalid_target", "audience is not allowed for this agent")
		}
		aud = req[0]
	}
	// Roles: only roles the agent is allowed AND the owner holds right now.
	roles := []string{}
	if len(ag.AllowedRoles) > 0 {
		for _, role := range p.effectiveRoles(ctx, rl, owner) {
			if slices.Contains(ag.AllowedRoles, role) {
				roles = append(roles, role)
			}
		}
	}
	if err := p.ensureKey(ctx, rl.Name); err != nil {
		p.cfg.Logger.Error("oidc: ensure key", "err", err)
		return nil, serverErr()
	}
	wantTTL := ag.TokenTTL
	if wantTTL <= 0 {
		wantTTL = core.DefaultAgentTokenTTLSeconds
	}
	ttl := p.accessTTL(rl, min(wantTTL, core.MaxAgentTokenTTLSeconds))
	if left := cred.ExpiresAt.Sub(now); left < ttl {
		ttl = left // never outlive the credential
	}
	scope := strings.Join(scopes, " ")
	at, err := p.cfg.Signer.Sign(ctx, rl.Name, core.Claims{
		"iss": p.issuer(rl.Name), "sub": owner.ID, "aud": aud, "azp": cl.ClientID,
		"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "jti": randToken(16),
		"typ": "Bearer", "scope": scope, "client_id": cl.ClientID, "preferred_username": owner.Username,
		// RFC 8693 section 4.1: the actor is the agent; the subject is the owner it acts for.
		"act":          map[string]any{"sub": "agent:" + cl.ClientID, "iss": p.issuer(rl.Name)},
		"realm_access": map[string]any{"roles": roles},
	})
	if err != nil {
		p.cfg.Logger.Error("oidc: sign agent token", "err", err)
		return nil, serverErr()
	}
	if err := as.TouchAgentCredential(ctx, rl.Name, ag.ID, cred.ID, now); err != nil {
		p.cfg.Logger.Error("oidc: touch agent credential", "err", err)
	}
	p.event(ctx, rl, "AGENT_TOKEN", owner.ID, cl.ClientID, ip, "agent="+ag.Name+" credential="+cred.ID+" scope="+scope+" aud="+aud)
	p.cfg.Obs.TokenIssued(rl.Name, "token_exchange", "access")
	return exchangeResponse(at, ttl, scope), nil
}
