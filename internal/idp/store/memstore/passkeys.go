// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// passkeyState holds the WebAuthn tables; it is guarded by Store.mu and its
// maps are created on first use.
type passkeyState struct {
	creds      map[string]core.Passkey // realm \x00 credential id
	handles    map[string]string       // realm \x00 user id -> handle
	byHandle   map[string]string       // realm \x00 handle -> user id
	challenges map[string]time.Time    // digest -> expires
	policy     map[string]bool         // realm -> require passkeys
}

var _ core.PasskeyStore = (*Store)(nil)

func (s *Store) pkInit() {
	if s.pk.creds == nil {
		s.pk = passkeyState{creds: map[string]core.Passkey{}, handles: map[string]string{},
			byHandle: map[string]string{}, challenges: map[string]time.Time{}, policy: map[string]bool{}}
	}
}

func clonePasskey(p core.Passkey) core.Passkey {
	p.PublicKey, p.Transports = cb(p.PublicKey), cs(p.Transports)
	return p
}

func (s *Store) UserHandle(_ context.Context, realm, userID, candidate string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	if u, ok := s.users[userID]; !ok || u.Realm != realm {
		return "", nf("user")
	}
	k := realm + "\x00" + userID
	if h, ok := s.pk.handles[k]; ok {
		return h, nil
	}
	if _, taken := s.pk.byHandle[realm+"\x00"+candidate]; taken || candidate == "" {
		return "", dup("passkey user handle")
	}
	s.pk.handles[k] = candidate
	s.pk.byHandle[realm+"\x00"+candidate] = userID
	return candidate, nil
}

func (s *Store) UserByHandle(_ context.Context, realm, handle string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	if id, ok := s.pk.byHandle[realm+"\x00"+handle]; ok {
		return id, nil
	}
	return "", nf("passkey user handle")
}

func (s *Store) AddPasskey(_ context.Context, p core.Passkey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	if u, ok := s.users[p.UserID]; !ok || u.Realm != p.Realm {
		return nf("user")
	}
	k := p.Realm + "\x00" + p.CredentialID
	if _, ok := s.pk.creds[k]; ok {
		return dup("passkey")
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	s.pk.creds[k] = clonePasskey(p)
	return nil
}

func (s *Store) GetPasskey(_ context.Context, realm, credentialID string) (core.Passkey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	p, ok := s.pk.creds[realm+"\x00"+credentialID]
	if !ok {
		return core.Passkey{}, nf("passkey")
	}
	return clonePasskey(p), nil
}

func (s *Store) ListPasskeys(_ context.Context, realm, userID string) ([]core.Passkey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	var out []core.Passkey
	for _, p := range s.pk.creds {
		if p.Realm == realm && p.UserID == userID {
			out = append(out, clonePasskey(p))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].CredentialID < out[j].CredentialID
	})
	return out, nil
}

func (s *Store) UpdatePasskeyUse(_ context.Context, realm, credentialID string, signCount uint32, backupState bool, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	k := realm + "\x00" + credentialID
	p, ok := s.pk.creds[k]
	if !ok {
		return nf("passkey")
	}
	p.SignCount, p.BackupState, p.LastUsedAt = signCount, backupState, at
	s.pk.creds[k] = p
	return nil
}

func (s *Store) RenamePasskey(_ context.Context, realm, userID, credentialID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	k := realm + "\x00" + credentialID
	p, ok := s.pk.creds[k]
	if !ok || p.UserID != userID {
		return nf("passkey")
	}
	p.Name = name
	s.pk.creds[k] = p
	return nil
}

func (s *Store) DeletePasskey(_ context.Context, realm, userID, credentialID string, keepLast bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	k := realm + "\x00" + credentialID
	p, ok := s.pk.creds[k]
	if !ok || p.UserID != userID {
		return nf("passkey")
	}
	if keepLast {
		n := 0
		for _, o := range s.pk.creds {
			if o.Realm == realm && o.UserID == userID {
				n++
			}
		}
		if n <= 1 {
			return dup("last passkey")
		}
	}
	delete(s.pk.creds, k)
	return nil
}

func (s *Store) ConsumeChallenge(_ context.Context, digest string, now, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	for d, exp := range s.pk.challenges {
		if !exp.After(now) {
			delete(s.pk.challenges, d)
		}
	}
	if _, used := s.pk.challenges[digest]; used {
		return dup("challenge")
	}
	s.pk.challenges[digest] = expires
	return nil
}

func (s *Store) RealmRequiresPasskeys(_ context.Context, realm string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	return s.pk.policy[realm], nil
}

func (s *Store) SetRealmRequiresPasskeys(_ context.Context, realm string, v bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	if err := s.needRealm(realm); err != nil {
		return err
	}
	if v {
		s.pk.policy[realm] = true
	} else {
		delete(s.pk.policy, realm)
	}
	return nil
}

// pkDrop removes passkey data of a deleted realm (userID == "") or user, the
// in-memory equivalent of the ON DELETE CASCADE of the Postgres schema. Called
// with s.mu held.
func (s *Store) pkDrop(realm, userID string) {
	for k, p := range s.pk.creds {
		if p.Realm == realm && (userID == "" || p.UserID == userID) {
			delete(s.pk.creds, k)
		}
	}
	for k, h := range s.pk.handles {
		r, u, _ := strings.Cut(k, "\x00")
		if r == realm && (userID == "" || u == userID) {
			delete(s.pk.handles, k)
			delete(s.pk.byHandle, realm+"\x00"+h)
		}
	}
	if userID == "" {
		delete(s.pk.policy, realm)
	}
}
