// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keycloak

import (
	"context"
	"fmt"
	"github.com/zyvorai/haven/internal/idp"
	"sync"
)

type Manager struct {
	mu     sync.RWMutex
	client *AdminClient
}

func NewManagerFromEnv() (*Manager, error) {
	c, err := NewFromEnv()
	if err != nil {
		return nil, err
	}
	return &Manager{client: c}, nil
}

// Manager is the Keycloak implementation of idp.Backend.
var _ idp.Backend = (*Manager)(nil)

// Client returns the current provider, or a true nil interface when unset.
func (m *Manager) Client() idp.Provider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil {
		return nil
	}
	return m.client
}

func (m *Manager) Config() (url, user string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.client == nil {
		return "", ""
	}
	return m.client.BaseURL(), m.client.User()
}

func (m *Manager) Reconfigure(ctx context.Context, baseURL, user, password string) error {
	if baseURL == "" {
		return fmt.Errorf("keycloak URL is required")
	}
	if user == "" {
		user = "admin"
	}
	if password == "" {
		return fmt.Errorf("admin password is required")
	}
	c := New(baseURL, user, password)
	if _, err := c.token(ctx); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	m.mu.Lock()
	m.client = c
	m.mu.Unlock()
	return nil
}

func New(baseURL, user, password string) *AdminClient {
	return &AdminClient{
		baseURL:  baseURL,
		user:     user,
		password: password,
		http:     defaultHTTPClient(),
	}
}

func (c *AdminClient) User() string { return c.user }

// AdminClient is the Keycloak implementation of idp.Provider.
var _ idp.Provider = (*AdminClient)(nil)
