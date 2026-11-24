// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"errors"
	"slices"
	"time"
)

// Time-boxed (just-in-time) access. A RoleGrant gives a user a realm role
// until ExpiresAt. The role is added to the token roles at ISSUE time (see
// oidc effectiveRoles), so a grant takes effect on the next token and stops
// with the next refresh after expiry or revocation.

// Grant limits and defaults.
const (
	MaxActiveGrantsPerUser = 20
	MaxGrantReason         = 500
	DefaultGrantMaxSeconds = 8 * 3600
	// HardMaxGrantSeconds caps what a realm policy may allow (30 days).
	HardMaxGrantSeconds = 30 * 24 * 3600
	// GrantRetention is how long an ended (expired or revoked) grant row is
	// kept for audit before PurgeExpiredGrants deletes it.
	GrantRetention = 90 * 24 * time.Hour
)

// ErrGrantLimit: the user already holds MaxActiveGrantsPerUser active grants.
var ErrGrantLimit = errors.New("idp: too many active grants for this user")

// RoleGrant is one time-boxed role assignment. It is effective while it is
// not revoked and now is before ExpiresAt (at exactly ExpiresAt it is over).
type RoleGrant struct {
	ID        string
	Realm     string
	UserID    string
	Role      string
	GrantedBy string // admin actor (audit only)
	Reason    string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt time.Time // zero = not revoked
	RevokedBy string
}

// Active reports whether the grant is effective at now.
func (g RoleGrant) Active(now time.Time) bool {
	return g.RevokedAt.IsZero() && now.Before(g.ExpiresAt)
}

// EndedAt is when the grant stopped being effective (revocation or expiry,
// whichever came first).
func (g RoleGrant) EndedAt() time.Time {
	if !g.RevokedAt.IsZero() && g.RevokedAt.Before(g.ExpiresAt) {
		return g.RevokedAt
	}
	return g.ExpiresAt
}

// GrantPolicy is the per-realm policy for new grants.
type GrantPolicy struct {
	MaxDurationSeconds int
	RequireReason      bool
	AllowedRoles       []string // empty = any role
}

// DefaultGrantPolicy is what a realm without a stored policy uses.
func DefaultGrantPolicy() GrantPolicy {
	return GrantPolicy{MaxDurationSeconds: DefaultGrantMaxSeconds, RequireReason: true, AllowedRoles: []string{}}
}

// Allows reports whether role may be granted under the policy.
func (p GrantPolicy) Allows(role string) bool {
	return len(p.AllowedRoles) == 0 || slices.Contains(p.AllowedRoles, role)
}

// GrantPurge is the outcome of PurgeExpiredGrants.
type GrantPurge struct {
	// Expired lists grants that expired (were not revoked) since the previous
	// purge; each is reported exactly once so callers can audit ROLE_GRANT_EXPIRED.
	Expired []RoleGrant
	// Deleted counts ended grants removed because they are older than GrantRetention.
	Deleted int
}

// GrantStore is the optional store extension for time-boxed access; reach it
// with StoreAs[GrantStore]. Absent = feature off.
//
// Expired and revoked rows are kept for GrantRetention (audit) but are NEVER
// effective: ActiveRoles and the active filters check expiry against now on
// every call, independent of whether the purge loop has run.
type GrantStore interface {
	// CreateRoleGrant inserts g (ID and CreatedAt are filled when empty) unless
	// the user already has maxActive active grants at now (ErrGrantLimit); the
	// check and insert are atomic. ErrNotFound when the realm does not exist.
	CreateRoleGrant(ctx context.Context, g RoleGrant, maxActive int, now time.Time) (RoleGrant, error)
	// ListRoleGrants returns grants newest first, at most limit (<=0: 200).
	// userID "" lists the whole realm. activeOnly filters at now.
	ListRoleGrants(ctx context.Context, realm, userID string, activeOnly bool, now time.Time, limit int) ([]RoleGrant, error)
	// RevokeRoleGrant ends an active grant now. ErrNotFound if it does not
	// exist in that realm for that user; ErrConflict if it already ended.
	RevokeRoleGrant(ctx context.Context, realm, userID, id, by string, now time.Time) (RoleGrant, error)
	// ActiveRoles returns the distinct roles of the user's active grants.
	ActiveRoles(ctx context.Context, realm, userID string, now time.Time) ([]string, error)
	// PurgeExpiredGrants reports newly expired grants once and deletes ended
	// grants older than GrantRetention.
	PurgeExpiredGrants(ctx context.Context, now time.Time) (GrantPurge, error)
	// GetGrantPolicy returns the realm policy, or the default when none is stored.
	GetGrantPolicy(ctx context.Context, realm string) (GrantPolicy, error)
	PutGrantPolicy(ctx context.Context, realm string, p GrantPolicy) error
}

// PurgeGrants runs the grant purge on st (a no-op when the store has no
// grant support) and appends one ROLE_GRANT_EXPIRED event per newly expired
// grant when the realm logs admin events. It returns how many rows were
// reported expired or deleted.
func PurgeGrants(ctx context.Context, st Store, now time.Time) (int, error) {
	gs, ok := StoreAs[GrantStore](st)
	if !ok {
		return 0, nil
	}
	res, err := gs.PurgeExpiredGrants(ctx, now)
	logged := map[string]bool{}
	for _, g := range res.Expired {
		on, seen := logged[g.Realm]
		if !seen {
			if rl, gerr := st.GetRealm(ctx, g.Realm); gerr == nil {
				on = rl.AdminEventsLogged
			}
			logged[g.Realm] = on
		}
		if !on {
			continue
		}
		_ = st.AppendEvent(ctx, Event{Time: now, Realm: g.Realm, Type: "ROLE_GRANT_EXPIRED", UserID: g.UserID,
			Detail: "grant " + g.Role + " until " + g.ExpiresAt.UTC().Format(time.RFC3339)})
	}
	return len(res.Expired) + res.Deleted, err
}
