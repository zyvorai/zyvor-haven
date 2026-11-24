// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// TOTP and recovery codes (core.MFAStore). The state lives beside the Store,
// keyed by it, so this feature adds no field to the shared Store struct.
// Orphans of a deleted user or realm are unreachable (ids are never reused);
// memstore is for tests and dev mode.
type mfaState struct {
	mu       sync.Mutex
	creds    map[string]core.TOTPCredential // realm|user
	recovery map[string]map[string]bool     // realm|user -> hashes
	policy   map[string]core.MFAPolicy      // realm
}

var mfaStates sync.Map // *Store -> *mfaState

var _ core.MFAStore = (*Store)(nil)

func (s *Store) mfa() *mfaState {
	if v, ok := mfaStates.Load(s); ok {
		return v.(*mfaState)
	}
	v, _ := mfaStates.LoadOrStore(s, &mfaState{
		creds: map[string]core.TOTPCredential{}, recovery: map[string]map[string]bool{}, policy: map[string]core.MFAPolicy{},
	})
	return v.(*mfaState)
}

func mfaKey(realm, user string) string { return realm + "\x00" + user }

func (s *Store) realmExists(realm string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.needRealm(realm)
}

// PutTOTP implements core.MFAStore.
func (s *Store) PutTOTP(_ context.Context, c core.TOTPCredential) error {
	if err := s.realmExists(c.Realm); err != nil {
		return err
	}
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mfaKey(c.Realm, c.UserID)
	if old, ok := m.creds[k]; ok && old.Confirmed {
		return dup("totp credential")
	}
	c.Confirmed, c.LastUsedStep = false, 0
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	m.creds[k] = c
	return nil
}

// GetTOTP implements core.MFAStore.
func (s *Store) GetTOTP(_ context.Context, realm, userID string) (core.TOTPCredential, error) {
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[mfaKey(realm, userID)]
	if !ok {
		return core.TOTPCredential{}, nf("totp credential")
	}
	return c, nil
}

// ConfirmTOTP implements core.MFAStore.
func (s *Store) ConfirmTOTP(_ context.Context, realm, userID string, step int64) (bool, error) {
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mfaKey(realm, userID)
	c, ok := m.creds[k]
	if !ok || c.Confirmed {
		return false, nil
	}
	c.Confirmed, c.LastUsedStep = true, step
	m.creds[k] = c
	return true, nil
}

// UseTOTPStep implements core.MFAStore.
func (s *Store) UseTOTPStep(_ context.Context, realm, userID string, step int64) (bool, error) {
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mfaKey(realm, userID)
	c, ok := m.creds[k]
	if !ok || !c.Confirmed || step <= c.LastUsedStep {
		return false, nil
	}
	c.LastUsedStep = step
	m.creds[k] = c
	return true, nil
}

// DeleteUserMFA implements core.MFAStore.
func (s *Store) DeleteUserMFA(_ context.Context, realm, userID string) error {
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mfaKey(realm, userID)
	delete(m.creds, k)
	delete(m.recovery, k)
	return nil
}

// ReplaceRecoveryCodes implements core.MFAStore.
func (s *Store) ReplaceRecoveryCodes(_ context.Context, realm, userID string, hashes []string) error {
	if err := s.realmExists(realm); err != nil {
		return err
	}
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	set := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		set[h] = true
	}
	m.recovery[mfaKey(realm, userID)] = set
	return nil
}

// ConsumeRecoveryCode implements core.MFAStore.
func (s *Store) ConsumeRecoveryCode(_ context.Context, realm, userID, hash string) (bool, error) {
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.recovery[mfaKey(realm, userID)]
	if !set[hash] {
		return false, nil
	}
	delete(set, hash)
	return true, nil
}

// CountRecoveryCodes implements core.MFAStore.
func (s *Store) CountRecoveryCodes(_ context.Context, realm, userID string) (int, error) {
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recovery[mfaKey(realm, userID)]), nil
}

// GetMFAPolicy implements core.MFAStore.
func (s *Store) GetMFAPolicy(_ context.Context, realm string) (core.MFAPolicy, error) {
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.policy[realm], nil
}

// PutMFAPolicy implements core.MFAStore.
func (s *Store) PutMFAPolicy(_ context.Context, realm string, p core.MFAPolicy) error {
	if err := s.realmExists(realm); err != nil {
		return err
	}
	m := s.mfa()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy[realm] = p
	return nil
}
