// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Session controls, passkey-only and front-channel logout tables
// (core.SessionPolicyStore, core.PasskeyOnlyStore, core.FrontchannelStore).
// They are kept beside the Store, keyed by it, and guarded by Store.mu so that
// they change atomically with sessions, passkeys and clients.
type sessCtlState struct {
	policy    map[string]core.SessionPolicy // realm
	remember  map[string]time.Duration      // session id -> remembered idle window
	pkOnly    map[string]bool               // realm
	pwless    map[string]time.Time          // realm \x00 credential id -> that credential's CreatedAt
	frontchan map[string]string             // client uuid -> uri
}

var sessCtlStates sync.Map // *Store -> *sessCtlState

var (
	_ core.SessionPolicyStore = (*Store)(nil)
	_ core.PasskeyOnlyStore   = (*Store)(nil)
	_ core.FrontchannelStore  = (*Store)(nil)
)

// sessCtl must be called with s.mu held.
func (s *Store) sessCtl() *sessCtlState {
	if v, ok := sessCtlStates.Load(s); ok {
		return v.(*sessCtlState)
	}
	v, _ := sessCtlStates.LoadOrStore(s, &sessCtlState{
		policy: map[string]core.SessionPolicy{}, remember: map[string]time.Duration{},
		pkOnly: map[string]bool{}, pwless: map[string]time.Time{}, frontchan: map[string]string{}})
	return v.(*sessCtlState)
}

// sessCtlDropRealm removes a deleted realm's options (the in-memory
// equivalent of ON DELETE CASCADE). Called with s.mu held.
func (s *Store) sessCtlDropRealm(realm string) {
	c := s.sessCtl()
	delete(c.policy, realm)
	delete(c.pkOnly, realm)
	for k := range c.pwless {
		if strings.HasPrefix(k, realm+"\x00") {
			delete(c.pwless, k)
		}
	}
}

// GetSessionPolicy implements core.SessionPolicyStore.
func (s *Store) GetSessionPolicy(_ context.Context, realm string) (core.SessionPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessCtl().policy[realm], nil
}

// PutSessionPolicy implements core.SessionPolicyStore.
func (s *Store) PutSessionPolicy(_ context.Context, realm string, p core.SessionPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(realm); err != nil {
		return err
	}
	s.sessCtl().policy[realm] = p
	return nil
}

// CreateLimitedSession implements core.SessionPolicyStore.
func (s *Store) CreateLimitedSession(_ context.Context, x core.Session, o core.NewSessionOptions) ([]core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(x.Realm); err != nil {
		return nil, err
	}
	var live []core.Session
	for _, other := range s.sess {
		if other.ID == x.ID || other.CookieHash == x.CookieHash {
			return nil, dup("session")
		}
		if other.Realm == x.Realm && other.UserID == x.UserID && other.ID != o.Replaces &&
			o.Now.Before(other.ExpiresAt) && o.Now.Before(other.IdleExpires) {
			live = append(live, other)
		}
	}
	var evicted []core.Session
	if over := len(live) + 1 - o.MaxLive; o.MaxLive > 0 && over > 0 {
		if o.DenyNew {
			return nil, core.ErrSessionLimit
		}
		slices.SortFunc(live, func(a, b core.Session) int {
			if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
				return c
			}
			return strings.Compare(a.ID, b.ID)
		})
		for _, old := range live[:min(over, len(live))] {
			evicted = append(evicted, cses(old))
			delete(s.sess, old.ID)
		}
	}
	if x.CreatedAt.IsZero() {
		x.CreatedAt = time.Now().UTC()
	}
	s.sess[x.ID] = cses(x)
	c := s.sessCtl()
	for id := range c.remember { // forget sessions that are gone
		if _, ok := s.sess[id]; !ok {
			delete(c.remember, id)
		}
	}
	if o.RememberIdle > 0 {
		c.remember[x.ID] = o.RememberIdle
	}
	return evicted, nil
}

// SessionRememberIdle implements core.SessionPolicyStore.
func (s *Store) SessionRememberIdle(_ context.Context, realm, id string) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.sess[id]; !ok || x.Realm != realm {
		return 0, nil
	}
	return s.sessCtl().remember[id], nil
}

// PasskeyOnly implements core.PasskeyOnlyStore.
func (s *Store) PasskeyOnly(_ context.Context, realm string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessCtl().pkOnly[realm], nil
}

// SetPasskeyOnly implements core.PasskeyOnlyStore.
func (s *Store) SetPasskeyOnly(_ context.Context, realm string, v bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(realm); err != nil {
		return err
	}
	s.sessCtl().pkOnly[realm] = v
	return nil
}

// MarkPasswordlessPasskey implements core.PasskeyOnlyStore.
func (s *Store) MarkPasswordlessPasskey(_ context.Context, realm, credentialID string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	k := realm + "\x00" + credentialID
	p, ok := s.pk.creds[k]
	if !ok {
		return nf("passkey")
	}
	s.sessCtl().pwless[k] = p.CreatedAt
	return nil
}

// PasswordlessPasskeys implements core.PasskeyOnlyStore.
func (s *Store) PasswordlessPasskeys(_ context.Context, realm, userID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkInit()
	c := s.sessCtl()
	var out []string
	for k, p := range s.pk.creds {
		if p.Realm != realm || p.UserID != userID {
			continue
		}
		// The mark belongs to one registration: same id, same creation time.
		if at, ok := c.pwless[k]; ok && at.Equal(p.CreatedAt) {
			out = append(out, p.CredentialID)
		}
	}
	slices.Sort(out)
	return out, nil
}

// FrontchannelLogoutURI implements core.FrontchannelStore.
func (s *Store) FrontchannelLogoutURI(_ context.Context, realm, clientUUID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cl, ok := s.clients[clientUUID]; !ok || cl.Realm != realm {
		return "", nil
	}
	return s.sessCtl().frontchan[clientUUID], nil
}

// SetFrontchannelLogoutURI implements core.FrontchannelStore.
func (s *Store) SetFrontchannelLogoutURI(_ context.Context, realm, clientUUID, uri string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cl, ok := s.clients[clientUUID]; !ok || cl.Realm != realm {
		return nf("client")
	}
	if uri == "" {
		delete(s.sessCtl().frontchan, clientUUID)
		return nil
	}
	s.sessCtl().frontchan[clientUUID] = uri
	return nil
}

func init() {
	type snap struct {
		Policy    map[string]core.SessionPolicy `json:"policy"`
		Remember  map[string]time.Duration      `json:"remember"`
		PKOnly    map[string]bool               `json:"passkeyOnly"`
		PWLess    map[string]time.Time          `json:"passwordless"`
		Frontchan map[string]string             `json:"frontchannel"`
	}
	RegisterPersist("sessioncontrols", func(s *Store) (any, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		c := s.sessCtl()
		return snap{copyMap(c.policy), copyMap(c.remember), copyMap(c.pkOnly), copyMap(c.pwless), copyMap(c.frontchan)}, nil
	}, func(s *Store, raw json.RawMessage) error {
		var v snap
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		c := s.sessCtl()
		c.policy, c.remember, c.pkOnly = orEmpty(v.Policy), orEmpty(v.Remember), orEmpty(v.PKOnly)
		c.pwless, c.frontchan = orEmpty(v.PWLess), orEmpty(v.Frontchan)
		return nil
	})
}
