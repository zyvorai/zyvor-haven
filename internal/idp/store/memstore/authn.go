// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// acr ladders and per-session authentication methods (core.AuthnStore), kept
// beside the Store like the other feature stores.
type authnState struct {
	mu       sync.Mutex
	policy   map[string]core.ACRPolicy    // realm
	sessions map[string]core.SessionAuthn // session id
}

var authnStates sync.Map // *Store -> *authnState

var _ core.AuthnStore = (*Store)(nil)

func (s *Store) authn() *authnState {
	if v, ok := authnStates.Load(s); ok {
		return v.(*authnState)
	}
	v, _ := authnStates.LoadOrStore(s, &authnState{
		policy: map[string]core.ACRPolicy{}, sessions: map[string]core.SessionAuthn{}})
	return v.(*authnState)
}

// liveSessions is the set of session ids that still exist, by realm.
func (s *Store) liveSessions() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.sess))
	for id, v := range s.sess {
		out[id] = v.Realm
	}
	return out
}

func (s *Store) sessionIn(realm, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sess[id]
	return ok && v.Realm == realm
}

// GetACRPolicy implements core.AuthnStore.
func (s *Store) GetACRPolicy(_ context.Context, realm string) (core.ACRPolicy, error) {
	m := s.authn()
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.policy[realm]
	if !ok {
		return core.ACRPolicy{}, nf("acr policy")
	}
	return p.Clone(), nil
}

// PutACRPolicy implements core.AuthnStore.
func (s *Store) PutACRPolicy(_ context.Context, realm string, p core.ACRPolicy) error {
	if err := s.realmExists(realm); err != nil {
		return err
	}
	m := s.authn()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy[realm] = p.Clone()
	return nil
}

// DeleteACRPolicy implements core.AuthnStore.
func (s *Store) DeleteACRPolicy(_ context.Context, realm string) error {
	m := s.authn()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policy, realm)
	return nil
}

// PutSessionAuthn implements core.AuthnStore. Records of ended sessions are
// dropped here, so the map does not grow without bound.
func (s *Store) PutSessionAuthn(_ context.Context, a core.SessionAuthn) error {
	live := s.liveSessions()
	if live[a.SessionID] != a.Realm || a.SessionID == "" {
		return nf("session")
	}
	m := s.authn()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.sessions[a.SessionID]; dup {
		return fmt.Errorf("session authn: %w", idp.ErrConflict)
	}
	for id := range m.sessions {
		if _, ok := live[id]; !ok {
			delete(m.sessions, id)
		}
	}
	a.AMR = slices.Clone(a.AMR)
	m.sessions[a.SessionID] = a
	return nil
}

// GetSessionAuthn implements core.AuthnStore.
func (s *Store) GetSessionAuthn(_ context.Context, realm, sessionID string) (core.SessionAuthn, error) {
	if !s.sessionIn(realm, sessionID) {
		return core.SessionAuthn{}, nf("session authn")
	}
	m := s.authn()
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.sessions[sessionID]
	if !ok || a.Realm != realm {
		return core.SessionAuthn{}, nf("session authn")
	}
	a.AMR = slices.Clone(a.AMR)
	if len(a.AMR) == 0 {
		a.AMR = nil
	}
	return a, nil
}

// authnDropRealm is called by DeleteRealm so a re-created realm starts with the
// default ladder.
func (s *Store) authnDropRealm(realm string) {
	m := s.authn()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policy, realm)
	for k, a := range m.sessions {
		if a.Realm == realm {
			delete(m.sessions, k)
		}
	}
}

type authnSnapshot struct {
	Policy   map[string]core.ACRPolicy    `json:"policy,omitempty"`
	Sessions map[string]core.SessionAuthn `json:"sessions,omitempty"`
}

func init() {
	RegisterPersist("authn", func(s *Store) (any, error) {
		m := s.authn()
		m.mu.Lock()
		defer m.mu.Unlock()
		if len(m.policy) == 0 && len(m.sessions) == 0 {
			return nil, nil
		}
		return authnSnapshot{Policy: copyMap(m.policy), Sessions: copyMap(m.sessions)}, nil
	}, func(s *Store, raw json.RawMessage) error {
		var sn authnSnapshot
		if err := json.Unmarshal(raw, &sn); err != nil {
			return err
		}
		m := s.authn()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.policy, m.sessions = orEmpty(sn.Policy), orEmpty(sn.Sessions)
		return nil
	})
}
