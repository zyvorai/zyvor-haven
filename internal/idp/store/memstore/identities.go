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

// Workload and agent identities (core.WorkloadStore, core.AgentStore). The
// state lives beside the Store keyed by its pointer, like grants. Each row
// remembers the ID of the realm it was created in, so a deleted and
// re-created realm of the same name never sees old rows.

type wlRow struct {
	core.WorkloadIdentity
	realmID string
}

type agRow struct {
	core.Agent
	realmID string
}

type credRow struct {
	core.AgentCredential
	realmID string
}

type identState struct {
	mu    sync.Mutex
	wl    []*wlRow
	ag    []*agRow
	creds []*credRow
}

var identStates sync.Map // *Store -> *identState

var (
	_ core.WorkloadStore = (*Store)(nil)
	_ core.AgentStore    = (*Store)(nil)
)

func (s *Store) istate() *identState {
	v, _ := identStates.LoadOrStore(s, &identState{})
	return v.(*identState)
}

func cloneWL(w core.WorkloadIdentity) core.WorkloadIdentity {
	w.AllowedScopes = append([]string{}, w.AllowedScopes...)
	return w
}

func cloneAgent(a core.Agent) core.Agent {
	a.AllowedScopes = append([]string{}, a.AllowedScopes...)
	a.AllowedRoles = append([]string{}, a.AllowedRoles...)
	a.Audiences = append([]string{}, a.Audiences...)
	return a
}

func cloneCred(c core.AgentCredential) core.AgentCredential {
	c.Scopes = append([]string{}, c.Scopes...)
	return c
}

// ---- workload identities ----

func (s *Store) CreateWorkloadIdentity(ctx context.Context, w core.WorkloadIdentity) (core.WorkloadIdentity, error) {
	rid, err := s.realmID(ctx, w.Realm)
	if err != nil {
		return core.WorkloadIdentity{}, err
	}
	if w.ID == "" {
		w.ID = uuid.NewString()
	}
	if w.CreatedAt.IsZero() {
		w.CreatedAt = time.Now()
	}
	w.CreatedAt = w.CreatedAt.UTC()
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range st.wl {
		if r.realmID == rid && (r.Name == w.Name || r.ClientID == w.ClientID) {
			return core.WorkloadIdentity{}, dup("workload identity")
		}
	}
	st.wl = append(st.wl, &wlRow{WorkloadIdentity: cloneWL(w), realmID: rid})
	return cloneWL(w), nil
}

func (s *Store) findWL(ctx context.Context, realm string, match func(*wlRow) bool) (*wlRow, *identState, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return nil, nil, err
	}
	st := s.istate()
	for _, r := range st.wl {
		if r.realmID == rid && match(r) {
			return r, st, nil
		}
	}
	return nil, st, nf("workload identity")
}

func (s *Store) GetWorkloadIdentity(ctx context.Context, realm, id string) (core.WorkloadIdentity, error) {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, _, err := s.findWL(ctx, realm, func(r *wlRow) bool { return r.ID == id })
	if err != nil {
		return core.WorkloadIdentity{}, err
	}
	return cloneWL(r.WorkloadIdentity), nil
}

func (s *Store) GetWorkloadIdentityByClient(ctx context.Context, realm, clientID string) (core.WorkloadIdentity, error) {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, _, err := s.findWL(ctx, realm, func(r *wlRow) bool { return r.ClientID == clientID })
	if err != nil {
		return core.WorkloadIdentity{}, err
	}
	return cloneWL(r.WorkloadIdentity), nil
}

func (s *Store) ListWorkloadIdentities(ctx context.Context, realm string) ([]core.WorkloadIdentity, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return nil, err
	}
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []core.WorkloadIdentity{}
	for _, r := range st.wl {
		if r.realmID == rid {
			out = append(out, cloneWL(r.WorkloadIdentity))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) SetWorkloadEnabled(ctx context.Context, realm, id string, enabled bool) (core.WorkloadIdentity, error) {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, _, err := s.findWL(ctx, realm, func(r *wlRow) bool { return r.ID == id })
	if err != nil {
		return core.WorkloadIdentity{}, err
	}
	r.Enabled = enabled
	return cloneWL(r.WorkloadIdentity), nil
}

func (s *Store) DeleteWorkloadIdentity(ctx context.Context, realm, id string) error {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, _, err := s.findWL(ctx, realm, func(r *wlRow) bool { return r.ID == id })
	if err != nil {
		return err
	}
	st.wl = slices.DeleteFunc(st.wl, func(x *wlRow) bool { return x == r })
	return nil
}

// ---- agents ----

func (s *Store) CreateAgent(ctx context.Context, a core.Agent) (core.Agent, error) {
	rid, err := s.realmID(ctx, a.Realm)
	if err != nil {
		return core.Agent{}, err
	}
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	a.CreatedAt = a.CreatedAt.UTC()
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range st.ag {
		if r.realmID == rid && (r.Name == a.Name || r.ClientID == a.ClientID) {
			return core.Agent{}, dup("agent")
		}
	}
	st.ag = append(st.ag, &agRow{Agent: cloneAgent(a), realmID: rid})
	return cloneAgent(a), nil
}

func (s *Store) findAgent(ctx context.Context, realm string, match func(*agRow) bool) (*agRow, string, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return nil, "", err
	}
	for _, r := range s.istate().ag {
		if r.realmID == rid && match(r) {
			return r, rid, nil
		}
	}
	return nil, rid, nf("agent")
}

func (s *Store) GetAgent(ctx context.Context, realm, id string) (core.Agent, error) {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, _, err := s.findAgent(ctx, realm, func(r *agRow) bool { return r.ID == id })
	if err != nil {
		return core.Agent{}, err
	}
	return cloneAgent(r.Agent), nil
}

func (s *Store) GetAgentByClient(ctx context.Context, realm, clientID string) (core.Agent, error) {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, _, err := s.findAgent(ctx, realm, func(r *agRow) bool { return r.ClientID == clientID })
	if err != nil {
		return core.Agent{}, err
	}
	return cloneAgent(r.Agent), nil
}

func (s *Store) ListAgents(ctx context.Context, realm, ownerID string) ([]core.Agent, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return nil, err
	}
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []core.Agent{}
	for _, r := range st.ag {
		if r.realmID == rid && (ownerID == "" || r.OwnerUserID == ownerID) {
			out = append(out, cloneAgent(r.Agent))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) SetAgentEnabled(ctx context.Context, realm, id string, enabled bool) (core.Agent, error) {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, _, err := s.findAgent(ctx, realm, func(r *agRow) bool { return r.ID == id })
	if err != nil {
		return core.Agent{}, err
	}
	r.Enabled = enabled
	return cloneAgent(r.Agent), nil
}

func (s *Store) DeleteAgent(ctx context.Context, realm, id string) error {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	r, _, err := s.findAgent(ctx, realm, func(r *agRow) bool { return r.ID == id })
	if err != nil {
		return err
	}
	st.ag = slices.DeleteFunc(st.ag, func(x *agRow) bool { return x == r })
	st.creds = slices.DeleteFunc(st.creds, func(c *credRow) bool { return c.AgentID == id })
	return nil
}

// ---- credentials ----

func (s *Store) CreateAgentCredential(ctx context.Context, c core.AgentCredential, maxActive int, now time.Time) (core.AgentCredential, error) {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	_, rid, err := s.findAgent(ctx, c.Realm, func(r *agRow) bool { return r.ID == c.AgentID })
	if err != nil {
		return core.AgentCredential{}, err
	}
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.CreatedAt, c.ExpiresAt = c.CreatedAt.UTC(), c.ExpiresAt.UTC()
	c.RevokedAt, c.RevokedBy, c.LastUsedAt = time.Time{}, "", time.Time{}
	active := 0
	for _, r := range st.creds {
		if r.SecretHash == c.SecretHash {
			return core.AgentCredential{}, dup("credential")
		}
		if r.realmID == rid && r.AgentID == c.AgentID && r.Active(now) {
			active++
		}
	}
	if maxActive > 0 && active >= maxActive {
		return core.AgentCredential{}, core.ErrCredentialLimit
	}
	st.creds = append(st.creds, &credRow{AgentCredential: cloneCred(c), realmID: rid})
	return cloneCred(c), nil
}

func (s *Store) GetAgentCredentialBySecret(ctx context.Context, realm, agentID, secretHash string) (core.AgentCredential, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return core.AgentCredential{}, err
	}
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range st.creds {
		if r.realmID == rid && r.AgentID == agentID && r.SecretHash == secretHash {
			return cloneCred(r.AgentCredential), nil
		}
	}
	return core.AgentCredential{}, nf("credential")
}

func (s *Store) ListAgentCredentials(ctx context.Context, realm, agentID string) ([]core.AgentCredential, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return nil, err
	}
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	out := []core.AgentCredential{}
	for _, r := range st.creds {
		if r.realmID == rid && r.AgentID == agentID {
			out = append(out, cloneCred(r.AgentCredential))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *Store) RevokeAgentCredential(ctx context.Context, realm, agentID, id, by string, now time.Time) (core.AgentCredential, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return core.AgentCredential{}, err
	}
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range st.creds {
		if r.realmID != rid || r.AgentID != agentID || r.ID != id {
			continue
		}
		if !r.Active(now) {
			return core.AgentCredential{}, dup("credential already ended")
		}
		r.RevokedAt, r.RevokedBy = now.UTC(), by
		return cloneCred(r.AgentCredential), nil
	}
	return core.AgentCredential{}, nf("credential")
}

func (s *Store) RevokeAgentCredentials(ctx context.Context, realm, agentID, by string, now time.Time) (int, error) {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return 0, err
	}
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	n := 0
	for _, r := range st.creds {
		if r.realmID == rid && r.AgentID == agentID && r.Active(now) {
			r.RevokedAt, r.RevokedBy = now.UTC(), by
			n++
		}
	}
	return n, nil
}

func (s *Store) TouchAgentCredential(ctx context.Context, realm, agentID, id string, now time.Time) error {
	rid, err := s.realmID(ctx, realm)
	if err != nil {
		return err
	}
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range st.creds {
		if r.realmID == rid && r.AgentID == agentID && r.ID == id {
			r.LastUsedAt = now.UTC()
			return nil
		}
	}
	return nf("credential")
}

func (s *Store) PurgeAgentCredentials(_ context.Context, now time.Time) (int, error) {
	st := s.istate()
	st.mu.Lock()
	defer st.mu.Unlock()
	before := len(st.creds)
	st.creds = slices.DeleteFunc(st.creds, func(c *credRow) bool {
		return !c.Active(now) && !now.Before(c.EndedAt().Add(core.CredentialRetention))
	})
	return before - len(st.creds), nil
}
