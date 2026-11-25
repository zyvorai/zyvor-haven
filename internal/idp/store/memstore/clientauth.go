// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Client authentication state (core.ClientAuthStore) lives beside the Store,
// keyed by its pointer. The per-client configuration is persisted by
// `dev --persist`; the short-lived assertion replay cache is not.
type clientAuthState struct {
	mu      sync.Mutex
	clients map[string]core.ClientAuth // client_ref
	seen    map[string]time.Time       // realm \x00 hash -> expiry
}

var clientAuthStates sync.Map // *Store -> *clientAuthState

var _ core.ClientAuthStore = (*Store)(nil)

func (s *Store) clientAuth() *clientAuthState {
	if v, ok := clientAuthStates.Load(s); ok {
		return v.(*clientAuthState)
	}
	v, _ := clientAuthStates.LoadOrStore(s, &clientAuthState{clients: map[string]core.ClientAuth{}, seen: map[string]time.Time{}})
	return v.(*clientAuthState)
}

func (s *Store) GetClientAuth(_ context.Context, realm, clientRef string) (core.ClientAuth, error) {
	s.mu.Lock()
	cl, alive := s.clients[clientRef] // settings die with their client (as ON DELETE CASCADE in Postgres)
	s.mu.Unlock()
	a := s.clientAuth()
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.clients[clientRef]
	if !ok || !alive || c.Realm != realm || cl.Realm != realm {
		return core.ClientAuth{}, idp.ErrNotFound
	}
	return c, nil
}

func (s *Store) PutClientAuth(_ context.Context, c core.ClientAuth) error {
	s.mu.Lock()
	cl, ok := s.clients[c.ClientRef]
	s.mu.Unlock()
	if !ok || cl.Realm != c.Realm {
		return nf("client " + c.ClientRef)
	}
	a := s.clientAuth()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clients[c.ClientRef] = c
	return nil
}

func (s *Store) DeleteClientAuth(_ context.Context, realm, clientRef string) error {
	a := s.clientAuth()
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.clients[clientRef]; ok && c.Realm == realm {
		delete(a.clients, clientRef)
	}
	return nil
}

func (s *Store) RememberClientAssertion(_ context.Context, realm, hash string, now, expires time.Time) error {
	a := s.clientAuth()
	a.mu.Lock()
	defer a.mu.Unlock()
	k := realm + "\x00" + hash
	if exp, ok := a.seen[k]; ok && now.Before(exp) {
		return dup("client assertion")
	}
	if len(a.seen) > 8192 { // opportunistic cleanup of expired entries only
		for key, exp := range a.seen {
			if !now.Before(exp) {
				delete(a.seen, key)
			}
		}
	}
	a.seen[k] = expires
	return nil
}

func (s *Store) PurgeExpiredClientAssertions(_ context.Context, now time.Time) (int, error) {
	a := s.clientAuth()
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for k, exp := range a.seen {
		if !now.Before(exp) {
			delete(a.seen, k)
			n++
		}
	}
	return n, nil
}

func init() {
	RegisterPersist("clientauth", func(s *Store) (any, error) {
		a := s.clientAuth()
		a.mu.Lock()
		defer a.mu.Unlock()
		return copyMap(a.clients), nil
	}, func(s *Store, raw json.RawMessage) error {
		var v map[string]core.ClientAuth
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		a := s.clientAuth()
		a.mu.Lock()
		defer a.mu.Unlock()
		a.clients = orEmpty(v)
		return nil
	})
}
