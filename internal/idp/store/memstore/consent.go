// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.ConsentStore = (*Store)(nil)

// consentState lives outside the Store struct (a side table keyed by the
// store) so the shared struct needs no edit; it is guarded by s.mu.
type consentState struct {
	policies map[string]core.ConsentPolicy // realm
	clients  map[string]core.ConsentClient // realm \x00 client_id
	grants   map[string]core.ConsentGrant  // id
	blocks   map[string]core.ConsentBlock  // realm \x00 client_id
	receipts map[string][]core.ConsentReceipt
}

var consentStates sync.Map // *Store -> *consentState

func newConsentState() *consentState {
	return &consentState{policies: map[string]core.ConsentPolicy{}, clients: map[string]core.ConsentClient{},
		grants: map[string]core.ConsentGrant{}, blocks: map[string]core.ConsentBlock{},
		receipts: map[string][]core.ConsentReceipt{}}
}

// consentLocked returns the state; call with s.mu held.
func (s *Store) consentLocked() *consentState {
	if v, ok := consentStates.Load(s); ok {
		return v.(*consentState)
	}
	v, _ := consentStates.LoadOrStore(s, newConsentState())
	return v.(*consentState)
}

// consentDropRealm forgets everything of a realm (called by DeleteRealm).
func (s *Store) consentDropRealm(realm string) {
	c := s.consentLocked()
	delete(c.policies, realm)
	delete(c.receipts, realm)
	for k, v := range c.clients {
		if v.Realm == realm {
			delete(c.clients, k)
		}
	}
	for k, v := range c.grants {
		if v.Realm == realm {
			delete(c.grants, k)
		}
	}
	for k, v := range c.blocks {
		if v.Realm == realm {
			delete(c.blocks, k)
		}
	}
}

func (s *Store) GetConsentPolicy(_ context.Context, realm string) (core.ConsentPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.consentLocked().policies[realm]
	if !ok {
		return core.ConsentPolicy{}, nf("consent policy")
	}
	return cloneConsentPolicy(p), nil
}

func cloneConsentPolicy(p core.ConsentPolicy) core.ConsentPolicy {
	p.CIMDHosts, p.SkipClients = slices.Clone(p.CIMDHosts), slices.Clone(p.SkipClients)
	return p
}

func (s *Store) PutConsentPolicy(_ context.Context, p core.ConsentPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(p.Realm); err != nil {
		return err
	}
	s.consentLocked().policies[p.Realm] = cloneConsentPolicy(p)
	return nil
}

func (s *Store) PutConsentClient(_ context.Context, c core.ConsentClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(c.Realm); err != nil {
		return err
	}
	c.RedirectURIs = slices.Clone(c.RedirectURIs)
	s.consentLocked().clients[dkey(c.Realm, c.ClientID)] = c
	return nil
}

func (s *Store) GetConsentClient(_ context.Context, realm, clientID string) (core.ConsentClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.consentLocked().clients[dkey(realm, clientID)]
	if !ok {
		return core.ConsentClient{}, nf("consent client")
	}
	c.RedirectURIs = slices.Clone(c.RedirectURIs)
	return c, nil
}

func (s *Store) ListConsentClients(_ context.Context, realm string) ([]core.ConsentClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.ConsentClient{}
	for _, c := range s.consentLocked().clients {
		if c.Realm == realm {
			c.RedirectURIs = slices.Clone(c.RedirectURIs)
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

func cloneConsentGrant(g core.ConsentGrant) core.ConsentGrant {
	g.Scopes, g.Resources = slices.Clone(g.Scopes), slices.Clone(g.Resources)
	return g
}

func (s *Store) PutConsentGrant(_ context.Context, g core.ConsentGrant, now time.Time) (core.ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(g.Realm); err != nil {
		return core.ConsentGrant{}, err
	}
	c := s.consentLocked()
	for id, o := range c.grants {
		if o.Realm == g.Realm && o.UserID == g.UserID && o.ClientID == g.ClientID && o.RevokedAt.IsZero() {
			g.ID, g.CreatedAt = o.ID, o.CreatedAt
			g.UpdatedAt = now
			g.RevokedAt, g.RevokedBy = time.Time{}, ""
			c.grants[id] = cloneConsentGrant(g)
			return cloneConsentGrant(g), nil
		}
	}
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = now
	}
	g.UpdatedAt = now
	if _, ok := c.grants[g.ID]; ok {
		return core.ConsentGrant{}, dup("consent grant")
	}
	c.grants[g.ID] = cloneConsentGrant(g)
	return cloneConsentGrant(g), nil
}

func (s *Store) GetActiveConsentGrant(_ context.Context, realm, userID, clientID string, now time.Time) (core.ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.consentLocked().grants {
		if g.Realm == realm && g.UserID == userID && g.ClientID == clientID && g.Active(now) {
			return cloneConsentGrant(g), nil
		}
	}
	return core.ConsentGrant{}, nf("consent grant")
}

func (s *Store) GetConsentGrant(_ context.Context, realm, id string) (core.ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.consentLocked().grants[id]
	if !ok || g.Realm != realm {
		return core.ConsentGrant{}, nf("consent grant")
	}
	return cloneConsentGrant(g), nil
}

func (s *Store) ListConsentGrants(_ context.Context, realm, userID, clientID string, includeEnded bool, now time.Time, limit int) ([]core.ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.ConsentGrant{}
	for _, g := range s.consentLocked().grants {
		if g.Realm != realm || (userID != "" && g.UserID != userID) || (clientID != "" && g.ClientID != clientID) {
			continue
		}
		if !includeEnded && !g.Active(now) {
			continue
		}
		out = append(out, cloneConsentGrant(g))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) RevokeConsentGrant(_ context.Context, realm, id, by string, now time.Time) (core.ConsentGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.consentLocked()
	g, ok := c.grants[id]
	if !ok || g.Realm != realm {
		return core.ConsentGrant{}, nf("consent grant")
	}
	if !g.RevokedAt.IsZero() {
		return core.ConsentGrant{}, dup("consent grant already revoked")
	}
	g.RevokedAt, g.RevokedBy = now, by
	c.grants[id] = g
	return cloneConsentGrant(g), nil
}

func (s *Store) RevokeClientConsentGrants(_ context.Context, realm, clientID, by string, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, n := s.consentLocked(), 0
	for id, g := range c.grants {
		if g.Realm == realm && g.ClientID == clientID && g.RevokedAt.IsZero() {
			g.RevokedAt, g.RevokedBy = now, by
			c.grants[id] = g
			n++
		}
	}
	return n, nil
}

func (s *Store) RevokeClientRefreshTokens(_ context.Context, realm, clientID, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, t := range s.refresh {
		if t.Realm == realm && t.ClientID == clientID && (userID == "" || t.UserID == userID) && !t.Revoked {
			t.Revoked = true
			s.refresh[k] = t
			n++
		}
	}
	return n, nil
}

func (s *Store) PutConsentBlock(_ context.Context, b core.ConsentBlock) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(b.Realm); err != nil {
		return err
	}
	s.consentLocked().blocks[dkey(b.Realm, b.ClientID)] = b
	return nil
}

func (s *Store) GetConsentBlock(_ context.Context, realm, clientID string) (core.ConsentBlock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.consentLocked().blocks[dkey(realm, clientID)]
	if !ok {
		return core.ConsentBlock{}, nf("consent block")
	}
	return b, nil
}

func (s *Store) DeleteConsentBlock(_ context.Context, realm, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.consentLocked()
	if _, ok := c.blocks[dkey(realm, clientID)]; !ok {
		return nf("consent block")
	}
	delete(c.blocks, dkey(realm, clientID))
	return nil
}

func (s *Store) ListConsentBlocks(_ context.Context, realm string) ([]core.ConsentBlock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.ConsentBlock{}
	for _, b := range s.consentLocked().blocks {
		if b.Realm == realm {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

func cloneConsentReceipt(r core.ConsentReceipt) core.ConsentReceipt {
	r.Scopes, r.Resources = slices.Clone(r.Scopes), slices.Clone(r.Resources)
	return r
}

func (s *Store) AppendConsentReceipt(_ context.Context, r core.ConsentReceipt) (core.ConsentReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(r.Realm); err != nil {
		return core.ConsentReceipt{}, err
	}
	c := s.consentLocked()
	chain := c.receipts[r.Realm]
	r.Seq, r.PrevHash = 1, ""
	if n := len(chain); n > 0 {
		r.Seq, r.PrevHash = chain[n-1].Seq+1, chain[n-1].Hash
	}
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	r.Time = r.Time.UTC().Truncate(time.Microsecond)
	r.Hash = core.ConsentReceiptHash(r)
	c.receipts[r.Realm] = append(chain, cloneConsentReceipt(r))
	return cloneConsentReceipt(r), nil
}

func (s *Store) ListConsentReceipts(_ context.Context, realm, userID string, afterSeq int64, limit int) ([]core.ConsentReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.ConsentReceipt{}
	for _, r := range s.consentLocked().receipts[realm] {
		if r.Seq <= afterSeq || (userID != "" && r.UserID != userID) {
			continue
		}
		out = append(out, cloneConsentReceipt(r))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) HeadConsentReceipt(_ context.Context, realm string) (core.ConsentReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.consentLocked().receipts[realm]
	if len(chain) == 0 {
		return core.ConsentReceipt{}, nf("consent receipt")
	}
	return cloneConsentReceipt(chain[len(chain)-1]), nil
}

// TamperConsentReceipt rewrites a stored receipt WITHOUT fixing the chain. It
// exists only so tests can prove the chain detects tampering.
func (s *Store) TamperConsentReceipt(realm string, seq int64, mut func(*core.ConsentReceipt)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	chain := s.consentLocked().receipts[realm]
	for i := range chain {
		if chain[i].Seq == seq {
			mut(&chain[i])
		}
	}
}

func init() {
	type snap struct {
		Policies map[string]core.ConsentPolicy    `json:"policies"`
		Clients  map[string]core.ConsentClient    `json:"clients"`
		Grants   map[string]core.ConsentGrant     `json:"grants"`
		Blocks   map[string]core.ConsentBlock     `json:"blocks"`
		Receipts map[string][]core.ConsentReceipt `json:"receipts"`
	}
	RegisterPersist("consent", func(s *Store) (any, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		c := s.consentLocked()
		return snap{copyMap(c.policies), copyMap(c.clients), copyMap(c.grants), copyMap(c.blocks), copyMap(c.receipts)}, nil
	}, func(s *Store, raw json.RawMessage) error {
		var v snap
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		c := s.consentLocked()
		c.policies, c.clients, c.grants, c.blocks, c.receipts = orEmpty(v.Policies), orEmpty(v.Clients), orEmpty(v.Grants),
			orEmpty(v.Blocks), orEmpty(v.Receipts)
		return nil
	})
}
