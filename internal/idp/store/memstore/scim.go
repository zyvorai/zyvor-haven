// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"sync"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// SCIM token and externalId rows (core.SCIMStore), kept beside the Store,
// keyed by it, so the shared Store struct gains no field.
type scimState struct {
	mu     sync.Mutex
	tokens map[string]core.SCIMToken    // realm
	ext    map[string]map[string]string // realm -> user id -> external id
}

var scimStates sync.Map // *Store -> *scimState

var _ core.SCIMStore = (*Store)(nil)

func (s *Store) scim() *scimState {
	if v, ok := scimStates.Load(s); ok {
		return v.(*scimState)
	}
	v, _ := scimStates.LoadOrStore(s, &scimState{tokens: map[string]core.SCIMToken{}, ext: map[string]map[string]string{}})
	return v.(*scimState)
}

func (s *Store) PutSCIMToken(_ context.Context, t core.SCIMToken) error {
	m := s.scim()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.Realm] = t
	return nil
}

func (s *Store) GetSCIMToken(_ context.Context, realm string) (core.SCIMToken, error) {
	m := s.scim()
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[realm]
	if !ok {
		return core.SCIMToken{}, idp.ErrNotFound
	}
	return t, nil
}

func (s *Store) DeleteSCIMToken(_ context.Context, realm string) error {
	m := s.scim()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[realm]; !ok {
		return idp.ErrNotFound
	}
	delete(m.tokens, realm)
	return nil
}

func (s *Store) SetSCIMExternalID(_ context.Context, realm, userID, externalID string) error {
	m := s.scim()
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.ext[realm]
	if externalID == "" {
		delete(r, userID)
		return nil
	}
	for uid, e := range r {
		if e == externalID && uid != userID {
			return idp.ErrConflict
		}
	}
	if r == nil {
		r = map[string]string{}
		m.ext[realm] = r
	}
	r[userID] = externalID
	return nil
}

func (s *Store) SCIMExternalIDs(_ context.Context, realm string, ids []string) (map[string]string, error) {
	m := s.scim()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	if len(ids) == 0 {
		for k, v := range m.ext[realm] {
			out[k] = v
		}
		return out, nil
	}
	for _, id := range ids {
		if e, ok := m.ext[realm][id]; ok {
			out[id] = e
		}
	}
	return out, nil
}

func (s *Store) FindSCIMExternalID(_ context.Context, realm, externalID string) (string, error) {
	m := s.scim()
	m.mu.Lock()
	defer m.mu.Unlock()
	for uid, e := range m.ext[realm] {
		if e == externalID {
			return uid, nil
		}
	}
	return "", idp.ErrNotFound
}

// scimDropUser forgets a deleted user's externalId.
func (s *Store) scimDropUser(realm, id string) {
	m := s.scim()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ext[realm], id)
}

// scimDropRealm forgets a deleted realm's token and externalIds.
func (s *Store) scimDropRealm(realm string) {
	m := s.scim()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, realm)
	delete(m.ext, realm)
}
