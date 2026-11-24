// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// fedData is the federation state of one Store. It lives beside the Store (in
// fedStates) so this feature adds no field to the shared struct.
type fedData struct {
	mu        sync.Mutex
	providers map[string]core.FedProvider // realm\x00alias
	links     map[string]core.FedLink     // realm\x00alias\x00subject
	states    map[string]core.FedLoginState
}

var fedStates sync.Map // *Store -> *fedData

var _ core.FedStore = (*Store)(nil)

func (s *Store) fed() *fedData {
	if d, ok := fedStates.Load(s); ok {
		return d.(*fedData)
	}
	d, _ := fedStates.LoadOrStore(s, &fedData{
		providers: map[string]core.FedProvider{}, links: map[string]core.FedLink{}, states: map[string]core.FedLoginState{},
	})
	return d.(*fedData)
}

func pk(realm, alias string) string      { return realm + "\x00" + alias }
func lk(realm, alias, sub string) string { return realm + "\x00" + alias + "\x00" + sub }
func cloneProv(p core.FedProvider) core.FedProvider {
	p.Config = maps.Clone(p.Config)
	return p
}

func cloneLink(l core.FedLink) core.FedLink {
	l.MappedRoles = cs(l.MappedRoles)
	return l
}

func (s *Store) CreateFedProvider(_ context.Context, p core.FedProvider) error {
	s.mu.Lock()
	if err := s.needRealm(p.Realm); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.providers[pk(p.Realm, p.Alias)]; ok {
		return dup("identity provider " + p.Alias)
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	d.providers[pk(p.Realm, p.Alias)] = cloneProv(p)
	return nil
}

func (s *Store) UpdateFedProvider(_ context.Context, p core.FedProvider) error {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	old, ok := d.providers[pk(p.Realm, p.Alias)]
	if !ok {
		return nf("identity provider " + p.Alias)
	}
	p.CreatedAt = old.CreatedAt
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now().UTC()
	}
	d.providers[pk(p.Realm, p.Alias)] = cloneProv(p)
	return nil
}

func (s *Store) GetFedProvider(_ context.Context, realm, alias string) (core.FedProvider, error) {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.providers[pk(realm, alias)]
	if !ok {
		return core.FedProvider{}, nf("identity provider " + alias)
	}
	return cloneProv(p), nil
}

func (s *Store) ListFedProviders(_ context.Context, realm string) ([]core.FedProvider, error) {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []core.FedProvider{}
	for _, p := range d.providers {
		if p.Realm == realm {
			out = append(out, cloneProv(p))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out, nil
}

func (s *Store) DeleteFedProvider(_ context.Context, realm, alias string) error {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.providers[pk(realm, alias)]; !ok {
		return nf("identity provider " + alias)
	}
	delete(d.providers, pk(realm, alias))
	for k, l := range d.links {
		if l.Realm == realm && l.Alias == alias {
			delete(d.links, k)
		}
	}
	for k, st := range d.states {
		if st.Realm == realm && st.Alias == alias {
			delete(d.states, k)
		}
	}
	return nil
}

func (s *Store) GetFedLink(_ context.Context, realm, alias, subject string) (core.FedLink, error) {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	l, ok := d.links[lk(realm, alias, subject)]
	if !ok {
		return core.FedLink{}, nf("federated identity")
	}
	return cloneLink(l), nil
}

func (s *Store) CreateFedLink(_ context.Context, l core.FedLink) error {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.providers[pk(l.Realm, l.Alias)]; !ok {
		return nf("identity provider " + l.Alias)
	}
	if _, ok := d.links[lk(l.Realm, l.Alias, l.Subject)]; ok {
		return dup("federated identity")
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	if l.LastLoginAt.IsZero() {
		l.LastLoginAt = l.CreatedAt
	}
	d.links[lk(l.Realm, l.Alias, l.Subject)] = cloneLink(l)
	return nil
}

func (s *Store) UpdateFedLink(_ context.Context, l core.FedLink) error {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	old, ok := d.links[lk(l.Realm, l.Alias, l.Subject)]
	if !ok {
		return nf("federated identity")
	}
	old.MappedRoles, old.LastLoginAt = cs(l.MappedRoles), l.LastLoginAt
	d.links[lk(l.Realm, l.Alias, l.Subject)] = old
	return nil
}

func (s *Store) ListFedLinksByUser(_ context.Context, realm, userID string) ([]core.FedLink, error) {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []core.FedLink{}
	for _, l := range d.links {
		if l.Realm == realm && l.UserID == userID {
			out = append(out, cloneLink(l))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out, nil
}

func (s *Store) DeleteFedLink(_ context.Context, realm, alias, userID string) error {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	found := false
	for k, l := range d.links {
		if l.Realm == realm && l.Alias == alias && l.UserID == userID {
			delete(d.links, k)
			found = true
		}
	}
	if !found {
		return nf("federated identity")
	}
	return nil
}

func (s *Store) DeleteFedLinksForUser(_ context.Context, realm, userID string) (int, error) {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for k, l := range d.links {
		if l.Realm == realm && l.UserID == userID {
			delete(d.links, k)
			n++
		}
	}
	return n, nil
}

func (s *Store) PutFedState(_ context.Context, st core.FedLoginState) error {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for k, v := range d.states {
		if !v.ExpiresAt.After(now) {
			delete(d.states, k)
		}
	}
	if _, ok := d.states[st.StateHash]; ok {
		return dup("login state")
	}
	d.states[st.StateHash] = st
	return nil
}

func (s *Store) ConsumeFedState(_ context.Context, stateHash string) (core.FedLoginState, error) {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.states[stateHash]
	if !ok {
		return core.FedLoginState{}, nf("login state")
	}
	delete(d.states, stateHash)
	return st, nil
}

// fedDropRealm and fedDropUser mirror the ON DELETE CASCADE of the pg schema.
// Called from DeleteRealm / DeleteUser with s.mu held; they only take fed.mu.
func (s *Store) fedDropRealm(realm string) {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, p := range d.providers {
		if p.Realm == realm {
			delete(d.providers, k)
		}
	}
	for k, l := range d.links {
		if l.Realm == realm {
			delete(d.links, k)
		}
	}
	for k, st := range d.states {
		if st.Realm == realm {
			delete(d.states, k)
		}
	}
}

func (s *Store) fedDropUser(realm, userID string) {
	d := s.fed()
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, l := range d.links {
		if l.Realm == realm && l.UserID == userID {
			delete(d.links, k)
		}
	}
}
