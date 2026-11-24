// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Time-boxed access (core.GrantStore). The state lives beside the Store, keyed
// by its pointer, so memstore.go stays untouched. Each row remembers the ID of
// the realm it was created in: a deleted and re-created realm of the same
// name never sees the old grants (the Postgres store uses ON DELETE CASCADE).

type grantRow struct {
	core.RoleGrant
	realmID string
	noticed bool // ROLE_GRANT_EXPIRED already reported
}

type grantState struct {
	mu       sync.Mutex
	rows     []*grantRow
	policies map[string]policyRow // key: realm ID
}

type policyRow struct {
	p core.GrantPolicy
}

var grantStates sync.Map // *Store -> *grantState

var _ core.GrantStore = (*Store)(nil)

func (s *Store) gstate() *grantState {
	v, _ := grantStates.LoadOrStore(s, &grantState{policies: map[string]policyRow{}})
	return v.(*grantState)
}

func (s *Store) realmID(ctx context.Context, name string) (string, error) {
	r, err := s.GetRealm(ctx, name)
	return r.ID, err
}

func clonePolicy(p core.GrantPolicy) core.GrantPolicy {
	p.AllowedRoles = append([]string{}, p.AllowedRoles...)
	return p
}

func (s *Store) CreateRoleGrant(ctx context.Context, g core.RoleGrant, maxActive int, now time.Time) (core.RoleGrant, error) {
	rid, err := s.realmID(ctx, g.Realm)
	if err != nil {
		return core.RoleGrant{}, err
	}
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = now
	}
	g.CreatedAt, g.ExpiresAt = g.CreatedAt.UTC(), g.ExpiresAt.UTC()
	g.RevokedAt, g.RevokedBy = time.Time{}, ""
	st := s.gstate()
	st.mu.Lock()
	defer st.mu.Unlock()
	active := 0
	for _, r := range st.rows {
		if r.realmID == rid && r.UserID == g.UserID && r.Active(now) {
			active++
		}
	}
	if maxActive > 0 && active >= maxActive {
		return core.RoleGrant{}, core.ErrGrantLimit
	}
	st.rows = append(st.rows, &grantRow{RoleGrant: g, realmID: rid})
	return g, nil
}

func (s *Store) ListRoleGrants(ctx context.Context, realm, userID string, activeOnly bool, now time.Time, limit int) ([]core.RoleGrant, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 200
	}
	st := s.gstate()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []core.RoleGrant{}
	for _, r := range st.rows {
		if r.realmID != rid || (userID != "" && r.UserID != userID) || (activeOnly && !r.Active(now)) {
			continue
		}
		out = append(out, r.RoleGrant)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) RevokeRoleGrant(ctx context.Context, realm, userID, id, by string, now time.Time) (core.RoleGrant, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return core.RoleGrant{}, err
	}
	st := s.gstate()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range st.rows {
		if r.realmID != rid || r.ID != id || r.UserID != userID {
			continue
		}
		if !r.Active(now) {
			return core.RoleGrant{}, dup("grant already ended")
		}
		r.RevokedAt, r.RevokedBy = now.UTC(), by
		return r.RoleGrant, nil
	}
	return core.RoleGrant{}, nf("grant " + id)
}

func (s *Store) ActiveRoles(ctx context.Context, realm, userID string, now time.Time) ([]string, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return nil, err
	}
	st := s.gstate()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []string{}
	for _, r := range st.rows {
		if r.realmID == rid && r.UserID == userID && r.Active(now) && !slices.Contains(out, r.Role) {
			out = append(out, r.Role)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) PurgeExpiredGrants(_ context.Context, now time.Time) (core.GrantPurge, error) {
	st := s.gstate()
	st.mu.Lock()
	defer st.mu.Unlock()
	var res core.GrantPurge
	keep := st.rows[:0]
	for _, r := range st.rows {
		if r.RevokedAt.IsZero() && !r.noticed && !now.Before(r.ExpiresAt) {
			r.noticed = true
			res.Expired = append(res.Expired, r.RoleGrant)
		}
		if !now.Before(r.EndedAt().Add(core.GrantRetention)) && !r.Active(now) {
			res.Deleted++
			continue
		}
		keep = append(keep, r)
	}
	for i := len(keep); i < len(st.rows); i++ {
		st.rows[i] = nil
	}
	st.rows = keep
	return res, nil
}

func (s *Store) GetGrantPolicy(ctx context.Context, realm string) (core.GrantPolicy, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return core.GrantPolicy{}, err
	}
	st := s.gstate()
	st.mu.Lock()
	defer st.mu.Unlock()
	if p, ok := st.policies[rid]; ok {
		return clonePolicy(p.p), nil
	}
	return core.DefaultGrantPolicy(), nil
}

func (s *Store) PutGrantPolicy(ctx context.Context, realm string, p core.GrantPolicy) error {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return err
	}
	st := s.gstate()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.policies[rid] = policyRow{p: clonePolicy(p)}
	return nil
}
