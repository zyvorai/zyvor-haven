// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// FAPI state (core.FAPIStore) lives beside the Store, keyed by its pointer.
// Only the per-client settings are persisted by `dev --persist`; pushed
// requests and bindings are short lived and are not.
type fapiState struct {
	mu       sync.Mutex
	clients  map[string]core.ClientFAPI // client_ref
	requests map[string]core.FAPIRequest
	bindings map[string]core.FAPIBinding
}

var fapiStates sync.Map // *Store -> *fapiState

var _ core.FAPIStore = (*Store)(nil)

func (s *Store) fapi() *fapiState {
	if v, ok := fapiStates.Load(s); ok {
		return v.(*fapiState)
	}
	v, _ := fapiStates.LoadOrStore(s, &fapiState{clients: map[string]core.ClientFAPI{},
		requests: map[string]core.FAPIRequest{}, bindings: map[string]core.FAPIBinding{}})
	return v.(*fapiState)
}

func fapiReqKey(realm, kind, id string) string { return realm + "\x00" + kind + "\x00" + id }

func (s *Store) GetClientFAPI(_ context.Context, realm, clientRef string) (core.ClientFAPI, error) {
	s.mu.Lock()
	cl, alive := s.clients[clientRef] // settings die with their client (as ON DELETE CASCADE in Postgres)
	s.mu.Unlock()
	f := s.fapi()
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.clients[clientRef]
	if !ok || !alive || c.Realm != realm || cl.Realm != realm {
		return core.ClientFAPI{}, idp.ErrNotFound
	}
	c.AuthzDetailTypes = slices.Clone(c.AuthzDetailTypes)
	return c, nil
}

func (s *Store) PutClientFAPI(_ context.Context, c core.ClientFAPI) error {
	s.mu.Lock()
	cl, ok := s.clients[c.ClientRef]
	s.mu.Unlock()
	if !ok || cl.Realm != c.Realm {
		return nf("client " + c.ClientRef)
	}
	c.AuthzDetailTypes = slices.Clone(c.AuthzDetailTypes)
	f := s.fapi()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients[c.ClientRef] = c
	return nil
}

func (s *Store) DeleteClientFAPI(_ context.Context, realm, clientRef string) error {
	f := s.fapi()
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[clientRef]; ok && c.Realm == realm {
		delete(f.clients, clientRef)
	}
	return nil
}

func (s *Store) PutFAPIRequest(_ context.Context, r core.FAPIRequest) error {
	if err := s.realmExists(r.Realm); err != nil {
		return err
	}
	f := s.fapi()
	f.mu.Lock()
	defer f.mu.Unlock()
	k := fapiReqKey(r.Realm, r.Kind, r.IDHash)
	if _, dupe := f.requests[k]; dupe {
		return dup("fapi request")
	}
	if len(f.requests) > 4096 { // opportunistic cleanup keeps the map bounded
		now := time.Now()
		for key, v := range f.requests {
			if !now.Before(v.ExpiresAt) {
				delete(f.requests, key)
			}
		}
	}
	f.requests[k] = r
	return nil
}

func (s *Store) ConsumeFAPIRequest(_ context.Context, realm, kind, idHash string, now time.Time) (core.FAPIRequest, error) {
	f := s.fapi()
	f.mu.Lock()
	defer f.mu.Unlock()
	k := fapiReqKey(realm, kind, idHash)
	r, ok := f.requests[k]
	if !ok {
		return core.FAPIRequest{}, idp.ErrNotFound
	}
	delete(f.requests, k) // an expired request is gone either way
	if !now.Before(r.ExpiresAt) {
		return core.FAPIRequest{}, idp.ErrNotFound
	}
	return r, nil
}

func (s *Store) GetFAPIRequest(_ context.Context, realm, kind, idHash string, now time.Time) (core.FAPIRequest, error) {
	f := s.fapi()
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.requests[fapiReqKey(realm, kind, idHash)]
	if !ok || !now.Before(r.ExpiresAt) {
		return core.FAPIRequest{}, idp.ErrNotFound
	}
	return r, nil
}

func (s *Store) PutFAPIBinding(_ context.Context, b core.FAPIBinding) error {
	f := s.fapi()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bindings[b.Kind+"\x00"+b.KeyHash] = b
	return nil
}

func (s *Store) GetFAPIBinding(_ context.Context, kind, keyHash string, now time.Time) (core.FAPIBinding, error) {
	f := s.fapi()
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.bindings[kind+"\x00"+keyHash]
	if !ok || !now.Before(b.ExpiresAt) {
		return core.FAPIBinding{}, idp.ErrNotFound
	}
	return b, nil
}

func (s *Store) PurgeExpiredFAPI(_ context.Context, now time.Time) (int, error) {
	f := s.fapi()
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k, r := range f.requests {
		if !now.Before(r.ExpiresAt) {
			delete(f.requests, k)
			n++
		}
	}
	for k, b := range f.bindings {
		if !now.Before(b.ExpiresAt) {
			delete(f.bindings, k)
			n++
		}
	}
	return n, nil
}

func init() {
	RegisterPersist("fapi", func(s *Store) (any, error) {
		f := s.fapi()
		f.mu.Lock()
		defer f.mu.Unlock()
		return copyMap(f.clients), nil
	}, func(s *Store, raw json.RawMessage) error {
		var v map[string]core.ClientFAPI
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		f := s.fapi()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.clients = orEmpty(v)
		return nil
	})
}
