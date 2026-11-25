// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Realm branding and email templates (core.BrandingStore). Kept beside the
// Store, keyed by it, so the shared Store struct gains no field.
type brandingState struct {
	mu        sync.Mutex
	branding  map[string]core.Branding      // realm
	templates map[string]core.EmailTemplate // realm \x00 kind \x00 locale
}

var brandingStates sync.Map // *Store -> *brandingState

var _ core.BrandingStore = (*Store)(nil)

func (s *Store) brandingData() *brandingState {
	if v, ok := brandingStates.Load(s); ok {
		return v.(*brandingState)
	}
	v, _ := brandingStates.LoadOrStore(s, &brandingState{
		branding: map[string]core.Branding{}, templates: map[string]core.EmailTemplate{}})
	return v.(*brandingState)
}

// brandingDropRealm is the cascade of DeleteRealm (called with s.mu held; the
// feature lock is never held while taking s.mu).
func (s *Store) brandingDropRealm(realm string) {
	m := s.brandingData()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.branding, realm)
	for k, t := range m.templates {
		if t.Realm == realm {
			delete(m.templates, k)
		}
	}
}

func tmplKey(realm, kind, locale string) string { return realm + "\x00" + kind + "\x00" + locale }

// GetBranding implements core.BrandingStore.
func (s *Store) GetBranding(_ context.Context, realm string) (core.Branding, error) {
	m := s.brandingData()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.branding[realm], nil
}

// PutBranding implements core.BrandingStore.
func (s *Store) PutBranding(_ context.Context, b core.Branding) error {
	if err := s.realmExists(b.Realm); err != nil {
		return err
	}
	m := s.brandingData()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.branding[b.Realm] = b
	return nil
}

// DeleteBranding implements core.BrandingStore.
func (s *Store) DeleteBranding(_ context.Context, realm string) error {
	m := s.brandingData()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.branding, realm)
	return nil
}

// GetEmailTemplate implements core.BrandingStore.
func (s *Store) GetEmailTemplate(_ context.Context, realm, kind, locale string) (core.EmailTemplate, error) {
	m := s.brandingData()
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.templates[tmplKey(realm, kind, locale)]
	if !ok {
		return core.EmailTemplate{}, nf("email template")
	}
	return t, nil
}

// ListEmailTemplates implements core.BrandingStore.
func (s *Store) ListEmailTemplates(_ context.Context, realm string) ([]core.EmailTemplate, error) {
	m := s.brandingData()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []core.EmailTemplate{}
	for _, t := range m.templates {
		if t.Realm == realm {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b core.EmailTemplate) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Locale, b.Locale)
	})
	return out, nil
}

// PutEmailTemplate implements core.BrandingStore.
func (s *Store) PutEmailTemplate(_ context.Context, t core.EmailTemplate) error {
	if err := s.realmExists(t.Realm); err != nil {
		return err
	}
	m := s.brandingData()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.templates[tmplKey(t.Realm, t.Kind, t.Locale)] = t
	return nil
}

// DeleteEmailTemplate implements core.BrandingStore.
func (s *Store) DeleteEmailTemplate(_ context.Context, realm, kind, locale string) error {
	m := s.brandingData()
	m.mu.Lock()
	defer m.mu.Unlock()
	k := tmplKey(realm, kind, locale)
	if _, ok := m.templates[k]; !ok {
		return nf("email template")
	}
	delete(m.templates, k)
	return nil
}

type brandingSnapshot struct {
	Branding  map[string]core.Branding      `json:"branding,omitempty"`
	Templates map[string]core.EmailTemplate `json:"templates,omitempty"`
}

func init() {
	RegisterPersist("branding", func(s *Store) (any, error) {
		m := s.brandingData()
		m.mu.Lock()
		defer m.mu.Unlock()
		if len(m.branding) == 0 && len(m.templates) == 0 {
			return nil, nil
		}
		return brandingSnapshot{Branding: copyMap(m.branding), Templates: copyMap(m.templates)}, nil
	}, func(s *Store, raw json.RawMessage) error {
		var sn brandingSnapshot
		if err := json.Unmarshal(raw, &sn); err != nil {
			return err
		}
		m := s.brandingData()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.branding, m.templates = orEmpty(sn.Branding), orEmpty(sn.Templates)
		return nil
	})
}
