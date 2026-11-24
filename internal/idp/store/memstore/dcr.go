// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.DCRStore = (*Store)(nil)

// dcrState lives in its own struct so New() needs no edit; it is created on
// first use under s.mu.
type dcrState struct {
	iats     map[string]core.InitialAccessToken // key: realm \x00 id
	regs     map[string]core.RegisteredClient   // key: realm \x00 client_id
	policies map[string]core.RegistrationPolicy // key: realm
}

func (s *Store) dcrLocked() *dcrState {
	if s.dcr == nil {
		s.dcr = &dcrState{
			iats: map[string]core.InitialAccessToken{}, regs: map[string]core.RegisteredClient{},
			policies: map[string]core.RegistrationPolicy{},
		}
	}
	return s.dcr
}

func dkey(realm, id string) string { return realm + "\x00" + id }

func (s *Store) PutInitialAccessToken(_ context.Context, t core.InitialAccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(t.Realm); err != nil {
		return err
	}
	d := s.dcrLocked()
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	for _, o := range d.iats {
		if o.TokenHash == t.TokenHash {
			return dup("initial access token")
		}
	}
	if _, ok := d.iats[dkey(t.Realm, t.ID)]; ok {
		return dup("initial access token")
	}
	d.iats[dkey(t.Realm, t.ID)] = t
	return nil
}

func (s *Store) ListInitialAccessTokens(_ context.Context, realm string) ([]core.InitialAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.InitialAccessToken{}
	for _, t := range s.dcrLocked().iats {
		if t.Realm == realm {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *Store) DeleteInitialAccessToken(_ context.Context, realm, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.dcrLocked()
	if _, ok := d.iats[dkey(realm, id)]; !ok {
		return nf("initial access token")
	}
	delete(d.iats, dkey(realm, id))
	return nil
}

func (s *Store) ConsumeInitialAccessToken(_ context.Context, realm, hash string, now time.Time) (core.InitialAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.dcrLocked()
	for k, t := range d.iats {
		if t.Realm == realm && t.TokenHash == hash {
			if t.Remaining <= 0 || !t.ExpiresAt.After(now) {
				return core.InitialAccessToken{}, nf("initial access token")
			}
			t.Remaining--
			d.iats[k] = t
			return t, nil
		}
	}
	return core.InitialAccessToken{}, nf("initial access token")
}

func (s *Store) RefundInitialAccessToken(_ context.Context, realm, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.dcrLocked()
	if t, ok := d.iats[dkey(realm, id)]; ok && t.Remaining < t.Count {
		t.Remaining++
		d.iats[dkey(realm, id)] = t
	}
	return nil
}

func ccopy(rc core.RegisteredClient) core.RegisteredClient {
	rc.GrantTypes, rc.Contacts = cs(rc.GrantTypes), cs(rc.Contacts)
	return rc
}

func (s *Store) PutRegisteredClient(_ context.Context, rc core.RegisteredClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(rc.Realm); err != nil {
		return err
	}
	d := s.dcrLocked()
	if _, ok := d.regs[dkey(rc.Realm, rc.ClientID)]; ok {
		return dup("registered client")
	}
	if rc.CreatedAt.IsZero() {
		rc.CreatedAt = time.Now().UTC()
	}
	if rc.UpdatedAt.IsZero() {
		rc.UpdatedAt = rc.CreatedAt
	}
	d.regs[dkey(rc.Realm, rc.ClientID)] = ccopy(rc)
	return nil
}

func (s *Store) GetRegisteredClient(_ context.Context, realm, clientID string) (core.RegisteredClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rc, ok := s.dcrLocked().regs[dkey(realm, clientID)]
	if !ok {
		return core.RegisteredClient{}, nf("registered client")
	}
	return ccopy(rc), nil
}

func (s *Store) UpdateRegisteredClient(_ context.Context, in core.RegisteredClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.dcrLocked()
	rc, ok := d.regs[dkey(in.Realm, in.ClientID)]
	if !ok {
		return nf("registered client")
	}
	rc.ApplicationType, rc.TokenAuthMethod, rc.Scope = in.ApplicationType, in.TokenAuthMethod, in.Scope
	rc.GrantTypes, rc.Contacts = cs(in.GrantTypes), cs(in.Contacts)
	rc.LogoURI, rc.ClientURI, rc.PolicyURI, rc.TosURI = in.LogoURI, in.ClientURI, in.PolicyURI, in.TosURI
	rc.UpdatedAt = in.UpdatedAt
	d.regs[dkey(in.Realm, in.ClientID)] = rc
	return nil
}

func (s *Store) DeleteRegisteredClient(_ context.Context, realm, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.dcrLocked()
	if _, ok := d.regs[dkey(realm, clientID)]; !ok {
		return nf("registered client")
	}
	delete(d.regs, dkey(realm, clientID))
	return nil
}

func (s *Store) ListRegisteredClients(_ context.Context, realm string) ([]core.RegisteredClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.RegisteredClient{}
	for _, rc := range s.dcrLocked().regs {
		if rc.Realm == realm {
			out = append(out, ccopy(rc))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

func (s *Store) GetRegistrationPolicy(_ context.Context, realm string) (core.RegistrationPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.dcrLocked().policies[realm]
	if !ok {
		return core.RegistrationPolicy{}, nf("registration policy")
	}
	p.AllowedGrantTypes = cs(p.AllowedGrantTypes)
	return p, nil
}

func (s *Store) PutRegistrationPolicy(_ context.Context, p core.RegistrationPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(p.Realm); err != nil {
		return err
	}
	p.AllowedGrantTypes = cs(p.AllowedGrantTypes)
	s.dcrLocked().policies[p.Realm] = p
	return nil
}
