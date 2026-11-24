// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// cibaState holds the CIBA rows. It lives in a side table keyed by the Store
// (instead of a field on Store) so the feature adds no line to the shared
// struct. It is not persisted by dev persistence: requests live a few minutes
// and the opt-in is re-applied through the Admin API. Rows of a deleted realm
// or client expire on their own and are realm- and client-scoped.
type cibaState struct {
	mu      sync.Mutex
	clients map[string]bool // realm|client uuid -> enabled
	rows    map[string]core.CIBARequest
}

var cibaStates sync.Map // *Store -> *cibaState

func (s *Store) ciba() *cibaState {
	v, _ := cibaStates.LoadOrStore(s, &cibaState{clients: map[string]bool{}, rows: map[string]core.CIBARequest{}})
	return v.(*cibaState)
}

var _ core.CIBAStore = (*Store)(nil)

func (s *Store) CIBAClientEnabled(_ context.Context, realm, clientUUID string) (bool, error) {
	c := s.ciba()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clients[realm+"|"+clientUUID], nil
}

func (s *Store) SetCIBAClient(ctx context.Context, realm, clientUUID string, enabled bool) error {
	if _, err := s.GetClient(ctx, realm, clientUUID); err != nil {
		return err
	}
	c := s.ciba()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients[realm+"|"+clientUUID] = enabled
	return nil
}

func (s *Store) PutCIBARequest(_ context.Context, r core.CIBARequest) error {
	c := s.ciba()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.rows[r.AuthReqHash]; dup {
		return idp.ErrConflict
	}
	for _, x := range c.rows {
		if x.Realm == r.Realm && x.ApprovalHash == r.ApprovalHash {
			return idp.ErrConflict
		}
	}
	if r.Status == "" {
		r.Status = core.CIBAPending
	}
	r.Resources = slices.Clone(r.Resources)
	c.rows[r.AuthReqHash] = r
	return nil
}

func (s *Store) GetCIBAByApproval(_ context.Context, realm, approvalHash string) (core.CIBARequest, error) {
	c := s.ciba()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.rows {
		if x.Realm == realm && x.ApprovalHash == approvalHash {
			x.Resources = slices.Clone(x.Resources)
			return x, nil
		}
	}
	return core.CIBARequest{}, idp.ErrNotFound
}

func (s *Store) DecideCIBA(_ context.Context, realm, approvalHash, userID string, now time.Time, d core.CIBADecision) (core.CIBARequest, error) {
	c := s.ciba()
	c.mu.Lock()
	defer c.mu.Unlock()
	if userID == "" {
		return core.CIBARequest{}, idp.ErrNotFound
	}
	for k, x := range c.rows {
		if x.Realm != realm || x.ApprovalHash != approvalHash {
			continue
		}
		if x.UserID != userID || x.Status != core.CIBAPending || !now.Before(x.ExpiresAt) {
			return core.CIBARequest{}, idp.ErrNotFound
		}
		x.Status = core.CIBADenied
		if d.Approve {
			x.Status = core.CIBAApproved
			x.SessionID, x.AuthTime = d.SessionID, d.AuthTime
		}
		c.rows[k] = x
		x.Resources = slices.Clone(x.Resources)
		return x, nil
	}
	return core.CIBARequest{}, idp.ErrNotFound
}

func (s *Store) PollCIBA(_ context.Context, realm, clientID, authReqHash string, now time.Time) (core.CIBARequest, bool, error) {
	c := s.ciba()
	c.mu.Lock()
	defer c.mu.Unlock()
	x, ok := c.rows[authReqHash]
	if !ok || x.Realm != realm || x.ClientID != clientID {
		return core.CIBARequest{}, false, idp.ErrNotFound
	}
	fast := !x.LastPoll.IsZero() && now.Before(x.LastPoll.Add(time.Duration(x.Interval)*time.Second))
	if fast {
		x.Interval = min(x.Interval+core.CIBASlowDownStep, core.CIBAMaxInterval)
	}
	x.LastPoll = now
	c.rows[authReqHash] = x
	x.Resources = slices.Clone(x.Resources)
	return x, fast, nil
}

func (s *Store) ConsumeCIBA(_ context.Context, realm, clientID, authReqHash string, now time.Time) (core.CIBARequest, error) {
	c := s.ciba()
	c.mu.Lock()
	defer c.mu.Unlock()
	x, ok := c.rows[authReqHash]
	if !ok || x.Realm != realm || x.ClientID != clientID || x.Status != core.CIBAApproved || !now.Before(x.ExpiresAt) {
		return core.CIBARequest{}, idp.ErrNotFound
	}
	delete(c.rows, authReqHash)
	return x, nil
}

func (s *Store) PurgeExpiredCIBA(_ context.Context, now time.Time) (int, error) {
	c := s.ciba()
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, x := range c.rows {
		if !x.ExpiresAt.After(now) {
			delete(c.rows, k)
			n++
		}
	}
	return n, nil
}
