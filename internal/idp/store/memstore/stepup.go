// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"slices"
	"sync"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Step-up policy and known devices (core.StepUpStore). Kept beside the Store,
// keyed by it, so the shared Store struct gains no field.
type stepUpState struct {
	mu      sync.Mutex
	policy  map[string]core.StepUpPolicy // realm
	devices map[string]core.KnownDevice  // realm \x00 user \x00 hash
}

var stepUpStates sync.Map // *Store -> *stepUpState

var _ core.StepUpStore = (*Store)(nil)

func (s *Store) stepUp() *stepUpState {
	if v, ok := stepUpStates.Load(s); ok {
		return v.(*stepUpState)
	}
	v, _ := stepUpStates.LoadOrStore(s, &stepUpState{
		policy: map[string]core.StepUpPolicy{}, devices: map[string]core.KnownDevice{}})
	return v.(*stepUpState)
}

func devKey(realm, user, hash string) string { return realm + "\x00" + user + "\x00" + hash }

// GetStepUpPolicy implements core.StepUpStore.
func (s *Store) GetStepUpPolicy(_ context.Context, realm string) (core.StepUpPolicy, error) {
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.policy[realm]
	p.SensitiveScopes = slices.Clone(p.SensitiveScopes)
	return p, nil
}

// PutStepUpPolicy implements core.StepUpStore.
func (s *Store) PutStepUpPolicy(_ context.Context, realm string, p core.StepUpPolicy) error {
	if err := s.realmExists(realm); err != nil {
		return err
	}
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	p.SensitiveScopes = slices.Clone(p.SensitiveScopes)
	m.policy[realm] = p
	return nil
}

// GetDevice implements core.StepUpStore.
func (s *Store) GetDevice(_ context.Context, realm, userID, hash string) (core.KnownDevice, error) {
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[devKey(realm, userID, hash)]
	if !ok {
		return core.KnownDevice{}, nf("device")
	}
	return d, nil
}

// userDevices returns the user's devices, most recently seen first (hash breaks ties).
func (m *stepUpState) userDevices(realm, userID string) []core.KnownDevice {
	var out []core.KnownDevice
	for _, d := range m.devices {
		if d.Realm == realm && d.UserID == userID {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b core.KnownDevice) int {
		if c := b.LastSeen.Compare(a.LastSeen); c != 0 {
			return c
		}
		if a.Hash < b.Hash {
			return -1
		} else if a.Hash > b.Hash {
			return 1
		}
		return 0
	})
	return out
}

// LatestDevice implements core.StepUpStore.
func (s *Store) LatestDevice(_ context.Context, realm, userID string) (core.KnownDevice, error) {
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	ds := m.userDevices(realm, userID)
	if len(ds) == 0 {
		return core.KnownDevice{}, nf("device")
	}
	return ds[0], nil
}

// TouchDevice implements core.StepUpStore.
func (s *Store) TouchDevice(_ context.Context, d core.KnownDevice, max int) error {
	if err := s.realmExists(d.Realm); err != nil {
		return err
	}
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	k := devKey(d.Realm, d.UserID, d.Hash)
	if old, ok := m.devices[k]; ok {
		d.FirstSeen = old.FirstSeen
	} else if d.FirstSeen.IsZero() {
		d.FirstSeen = d.LastSeen
	}
	m.devices[k] = d
	if max > 0 {
		ds := m.userDevices(d.Realm, d.UserID)
		for i := max; i < len(ds); i++ {
			delete(m.devices, devKey(ds[i].Realm, ds[i].UserID, ds[i].Hash))
		}
	}
	return nil
}

// ListDevices implements core.StepUpStore.
func (s *Store) ListDevices(_ context.Context, realm, userID string) ([]core.KnownDevice, error) {
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.userDevices(realm, userID), nil
}

// DeleteDevice implements core.StepUpStore.
func (s *Store) DeleteDevice(_ context.Context, realm, userID, hash string) error {
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.devices, devKey(realm, userID, hash))
	return nil
}

// DeleteUserDevices implements core.StepUpStore.
func (s *Store) DeleteUserDevices(_ context.Context, realm, userID string) error {
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.userDevices(realm, userID) {
		delete(m.devices, devKey(d.Realm, d.UserID, d.Hash))
	}
	return nil
}

// stepUpDropRealm and stepUpDropUser are called by DeleteRealm / DeleteUser
// (with Store.mu held) so a re-created realm or user starts clean.
func (s *Store) stepUpDropRealm(realm string) {
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policy, realm)
	for k, d := range m.devices {
		if d.Realm == realm {
			delete(m.devices, k)
		}
	}
}

func (s *Store) stepUpDropUser(realm, userID string) {
	m := s.stepUp()
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, d := range m.devices {
		if d.Realm == realm && d.UserID == userID {
			delete(m.devices, k)
		}
	}
}
