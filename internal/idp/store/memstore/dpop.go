// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// DPoP state (core.DPoPStore) lives beside the Store, keyed by its pointer,
// so memstore.go stays untouched.
type dpopBinding struct {
	jkt     string
	expires time.Time
}

type dpopState struct {
	mu       sync.Mutex
	proofs   map[string]time.Time // realm|proofHash -> expiry
	bindings map[string]dpopBinding
}

var dpopStates sync.Map // *Store -> *dpopState

var _ core.DPoPStore = (*Store)(nil)

func (s *Store) dpop() *dpopState {
	v, _ := dpopStates.LoadOrStore(s, &dpopState{proofs: map[string]time.Time{}, bindings: map[string]dpopBinding{}})
	return v.(*dpopState)
}

func (s *Store) RememberDPoPProof(_ context.Context, realm, proofHash string, now, expires time.Time) error {
	d := s.dpop()
	d.mu.Lock()
	defer d.mu.Unlock()
	k := realm + "|" + proofHash
	if exp, ok := d.proofs[k]; ok && now.Before(exp) {
		return idp.ErrConflict
	}
	if len(d.proofs) > 4096 { // opportunistic cleanup keeps the map bounded
		for key, exp := range d.proofs {
			if !now.Before(exp) {
				delete(d.proofs, key)
			}
		}
	}
	d.proofs[k] = expires
	return nil
}

func (s *Store) BindRefreshToken(_ context.Context, tokenHash, jkt string, expires time.Time) error {
	d := s.dpop()
	d.mu.Lock()
	defer d.mu.Unlock()
	if b, ok := d.bindings[tokenHash]; ok && b.jkt != jkt {
		return idp.ErrConflict
	}
	d.bindings[tokenHash] = dpopBinding{jkt: jkt, expires: expires}
	return nil
}

func (s *Store) RefreshTokenBinding(_ context.Context, tokenHash string, now time.Time) (string, error) {
	d := s.dpop()
	d.mu.Lock()
	defer d.mu.Unlock()
	b, ok := d.bindings[tokenHash]
	if !ok || !now.Before(b.expires) {
		return "", idp.ErrNotFound
	}
	return b.jkt, nil
}

func (s *Store) PurgeExpiredDPoP(_ context.Context, now time.Time) (int, error) {
	d := s.dpop()
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for k, exp := range d.proofs {
		if !now.Before(exp) {
			delete(d.proofs, k)
			n++
		}
	}
	for k, b := range d.bindings {
		if !now.Before(b.expires) {
			delete(d.bindings, k)
			n++
		}
	}
	return n, nil
}
