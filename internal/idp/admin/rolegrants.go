// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Time-boxed (just-in-time) access: roles granted to a user that expire on
// their own. See docs/time-boxed-access.md and the "Time-boxed access" section
// of SPEC.md.

func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}"
		m.HandleFunc("GET "+p+"/grants-policy", a.getGrantPolicy)
		m.HandleFunc("PUT "+p+"/grants-policy", a.op("grants-policy", "update", a.putGrantPolicy))
		m.HandleFunc("GET "+p+"/grants", a.listRealmGrants)
		m.HandleFunc("GET "+p+"/users/{id}/grants", a.listUserGrants)
		m.HandleFunc("POST "+p+"/users/{id}/grants", a.op("role-grant", "create", a.createGrant))
		m.HandleFunc("DELETE "+p+"/users/{id}/grants/{gid}", a.op("role-grant", "delete", a.revokeGrant))
	})
}

const maxGrantList = 1000

// grantStore returns the grant store or answers 501 (feature off).
func (a *api) grantStore(w http.ResponseWriter) (core.GrantStore, bool) {
	gs, ok := core.StoreAs[core.GrantStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "time-boxed access is not available on this store")
	}
	return gs, ok
}

func grantToWire(g core.RoleGrant, now time.Time) idp.RoleGrant {
	out := idp.RoleGrant{ID: g.ID, UserID: g.UserID, Role: g.Role, GrantedBy: g.GrantedBy, Reason: g.Reason,
		CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt, RevokedBy: g.RevokedBy, State: "active"}
	switch {
	case !g.RevokedAt.IsZero():
		t := g.RevokedAt
		out.RevokedAt, out.State = &t, "revoked"
	case !now.Before(g.ExpiresAt):
		out.State = "expired"
	}
	return out
}

// grantEvent audits a grant change. Detail names the role and the expiry and
// the acting admin, never the reason text or any secret.
func (a *api) grantEvent(r *http.Request, rl core.Realm, typ string, g core.RoleGrant) {
	if !rl.AdminEventsLogged {
		return
	}
	err := a.cfg.Store.AppendEvent(r.Context(), core.Event{
		Time: a.cfg.Clock().UTC(), Realm: rl.Name, Type: typ, UserID: g.UserID,
		Detail: "grant " + g.Role + " until " + g.ExpiresAt.UTC().Format(time.RFC3339) + " by " + actorOf(r),
	})
	if err != nil {
		a.cfg.Logger.Error("admin: append event", "err", err.Error())
	}
}

// ---- policy ----

type grantPolicyWire struct {
	MaxDurationSeconds int      `json:"maxDurationSeconds"`
	RequireReason      bool     `json:"requireReason"`
	AllowedRoles       []string `json:"allowedRoles"`
}

func policyToWire(p core.GrantPolicy) grantPolicyWire {
	return grantPolicyWire{p.MaxDurationSeconds, p.RequireReason, append([]string{}, p.AllowedRoles...)}
}

func (a *api) getGrantPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	gs, ok := a.grantStore(w)
	if !ok {
		return
	}
	p, err := gs.GetGrantPolicy(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policyToWire(p))
}

// putGrantPolicy updates the policy; omitted fields keep their current value.
// Narrowing the policy does not touch grants that already exist.
func (a *api) putGrantPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	gs, ok := a.grantStore(w)
	if !ok {
		return
	}
	var in struct {
		MaxDurationSeconds *int      `json:"maxDurationSeconds"`
		RequireReason      *bool     `json:"requireReason"`
		AllowedRoles       *[]string `json:"allowedRoles"`
	}
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	cur, err := gs.GetGrantPolicy(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if in.MaxDurationSeconds != nil {
		if *in.MaxDurationSeconds < 60 || *in.MaxDurationSeconds > core.HardMaxGrantSeconds {
			a.fail(w, r, bad("maxDurationSeconds must be between 60 and 2592000 (30 days)"))
			return
		}
		cur.MaxDurationSeconds = *in.MaxDurationSeconds
	}
	if in.RequireReason != nil {
		cur.RequireReason = *in.RequireReason
	}
	if in.AllowedRoles != nil {
		roles := *in.AllowedRoles
		if len(roles) > 100 {
			a.fail(w, r, bad("too many allowedRoles"))
			return
		}
		known, err := a.cfg.Store.ListRoles(r.Context(), rl.Name)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		seen := map[string]bool{}
		clean := []string{}
		for _, n := range roles {
			if !roleNameRE.MatchString(n) || n == adminRole || !slices.ContainsFunc(known, func(k core.Role) bool { return k.Name == n }) {
				a.fail(w, r, bad("allowedRoles must be existing roles that may be granted"))
				return
			}
			if !seen[n] {
				seen[n] = true
				clean = append(clean, n)
			}
		}
		cur.AllowedRoles = clean
	}
	if err := gs.PutGrantPolicy(r.Context(), rl.Name, cur); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "grants-policy", rl.Name)
	writeJSON(w, http.StatusOK, policyToWire(cur))
}

// ---- grants ----

type grantIn struct {
	Role            string     `json:"role"`
	ExpiresAt       *time.Time `json:"expiresAt"`
	DurationSeconds *int       `json:"durationSeconds"`
	Reason          string     `json:"reason"`
}

func (a *api) createGrant(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	gs, ok := a.grantStore(w)
	if !ok {
		return
	}
	ctx := r.Context()
	u, err := a.cfg.Store.GetUser(ctx, rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in grantIn
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if !u.Enabled {
		a.fail(w, r, bad("user is disabled"))
		return
	}
	if !roleNameRE.MatchString(in.Role) {
		a.fail(w, r, bad("invalid role"))
		return
	}
	// The admin API itself trusts the permanent role: a temporary admin role
	// would be refused there anyway, so do not pretend it works.
	if in.Role == adminRole {
		a.fail(w, r, bad("role "+adminRole+" cannot be granted temporarily"))
		return
	}
	known, err := a.cfg.Store.ListRoles(ctx, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !slices.ContainsFunc(known, func(k core.Role) bool { return k.Name == in.Role }) {
		a.fail(w, r, bad("role does not exist in this realm"))
		return
	}
	pol, err := gs.GetGrantPolicy(ctx, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !pol.Allows(in.Role) {
		a.fail(w, r, bad("role is not allowed by the realm grants policy"))
		return
	}
	reason := strings.TrimSpace(in.Reason)
	if pol.RequireReason && reason == "" {
		a.fail(w, r, bad("reason is required"))
		return
	}
	if utf8.RuneCountInString(reason) > core.MaxGrantReason || !validText(reason, 4*core.MaxGrantReason) {
		a.fail(w, r, bad("reason must be at most 500 characters without control characters"))
		return
	}

	now := a.cfg.Clock().UTC().Truncate(time.Second)
	var exp time.Time
	switch {
	case (in.ExpiresAt == nil) == (in.DurationSeconds == nil):
		a.fail(w, r, bad("exactly one of expiresAt and durationSeconds is required"))
		return
	case in.DurationSeconds != nil:
		if *in.DurationSeconds <= 0 {
			a.fail(w, r, bad("durationSeconds must be positive"))
			return
		}
		if *in.DurationSeconds > pol.MaxDurationSeconds {
			a.fail(w, r, bad("duration exceeds the realm maximum"))
			return
		}
		exp = now.Add(time.Duration(*in.DurationSeconds) * time.Second)
	default:
		exp = in.ExpiresAt.UTC().Truncate(time.Second)
		if !exp.After(now) {
			a.fail(w, r, bad("expiresAt must be in the future"))
			return
		}
		if exp.Sub(now) > time.Duration(pol.MaxDurationSeconds)*time.Second {
			a.fail(w, r, bad("expiresAt exceeds the realm maximum duration"))
			return
		}
	}

	g, err := gs.CreateRoleGrant(ctx, core.RoleGrant{
		Realm: rl.Name, UserID: u.ID, Role: in.Role, GrantedBy: actorOf(r), Reason: reason, CreatedAt: now, ExpiresAt: exp,
	}, core.MaxActiveGrantsPerUser, now)
	if err != nil {
		if errors.Is(err, core.ErrGrantLimit) {
			a.fail(w, r, &httpErr{http.StatusTooManyRequests, "user already has the maximum number of active grants"})
			return
		}
		a.fail(w, r, err)
		return
	}
	a.grantEvent(r, rl, "ROLE_GRANT_CREATED", g)
	w.Header().Set("Location", pathPrefix+"/realms/"+rl.Name+"/users/"+u.ID+"/grants")
	writeJSON(w, http.StatusCreated, grantToWire(g, now))
}

func stateParam(r *http.Request, def string) (activeOnly bool, err error) {
	switch s := r.URL.Query().Get("state"); s {
	case "":
		return def == "active", nil
	case "active":
		return true, nil
	case "all":
		return false, nil
	}
	return false, bad("state must be active or all")
}

func (a *api) writeGrants(w http.ResponseWriter, r *http.Request, realm, userID string) {
	gs, ok := a.grantStore(w)
	if !ok {
		return
	}
	activeOnly, err := stateParam(r, "active")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	max, err := intParam(r, "max", 200, 1, maxGrantList)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	now := a.cfg.Clock().UTC()
	gl, err := gs.ListRoleGrants(r.Context(), realm, userID, activeOnly, now, max)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]idp.RoleGrant, 0, len(gl))
	for _, g := range gl {
		out = append(out, grantToWire(g, now))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) listUserGrants(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeGrants(w, r, rl.Name, u.ID)
}

func (a *api) listRealmGrants(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	a.writeGrants(w, r, rl.Name, "")
}

// revokeGrant ends a grant now. It does not touch SSO sessions unless
// ?endSessions=true: the next refresh drops the role either way, and access
// tokens already issued keep it until they expire.
func (a *api) revokeGrant(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	gs, ok := a.grantStore(w)
	if !ok {
		return
	}
	end := false
	switch r.URL.Query().Get("endSessions") {
	case "", "false":
	case "true":
		end = true
	default:
		a.fail(w, r, bad("endSessions must be true or false"))
		return
	}
	now := a.cfg.Clock().UTC()
	g, err := gs.RevokeRoleGrant(r.Context(), rl.Name, r.PathValue("id"), r.PathValue("gid"), actorOf(r), now)
	if err != nil {
		if errors.Is(err, idp.ErrConflict) {
			a.fail(w, r, &httpErr{http.StatusConflict, "grant already ended"})
			return
		}
		a.fail(w, r, err)
		return
	}
	a.grantEvent(r, rl, "ROLE_GRANT_REVOKED", g)
	if end {
		a.dropUserSessions(r.Context(), rl.Name, g.UserID)
	}
	noContent(w)
}
