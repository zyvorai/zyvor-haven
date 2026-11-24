// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// FedProvider is an upstream OIDC identity provider configured for a realm
// ("Sign in with ..."). ClientSecretSealed is the upstream client secret
// encrypted with secretbox (context "idp|realm|alias"); it is never returned
// by the Admin API and never logged.
type FedProvider struct {
	Realm        string
	Alias        string // [a-z0-9-]{1,32}, unique per realm
	DisplayName  string
	ProviderType string // "oidc" | "google" | "microsoft"
	Enabled      bool
	TrustEmail   bool
	// Config holds the non-secret settings (issuer, discoveryUrl, clientId,
	// scopes, tenant, hostedDomain, usernameClaim, linkExistingByEmail,
	// autoCreateUsers, roleMappings, roleSyncMode).
	Config             map[string]string
	ClientSecretSealed string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// FedLink binds an upstream subject to a local user. MappedRoles are the
// roles federation itself added to the user (so a "sync" role mode removes
// only those, never roles an administrator assigned).
type FedLink struct {
	Realm       string
	Alias       string
	Subject     string // the upstream `sub`
	UserID      string
	MappedRoles []string
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// FedLoginState is one in-flight upstream login. Only the sha256 hex of the
// `state` parameter and of the browser-binding cookie are stored. It is
// single use (ConsumeFedState deletes it).
type FedLoginState struct {
	StateHash   string
	Realm       string
	Alias       string
	BrowserHash string // sha256 hex of the cookie that must come back with the callback
	Nonce       string
	AuthQuery   string // the original /auth query string, replayed after login
	ExpiresAt   time.Time
}

// FedStore is the persistence contract of identity brokering. Stores that do
// not implement it simply do not offer federation (the feature answers 501 /
// shows no buttons). Errors use idp.ErrNotFound and idp.ErrConflict.
type FedStore interface {
	CreateFedProvider(ctx context.Context, p FedProvider) error // ErrConflict on duplicate alias
	UpdateFedProvider(ctx context.Context, p FedProvider) error // ErrNotFound; keeps CreatedAt
	GetFedProvider(ctx context.Context, realm, alias string) (FedProvider, error)
	ListFedProviders(ctx context.Context, realm string) ([]FedProvider, error) // by alias
	// DeleteFedProvider removes the provider and all its links (not users).
	DeleteFedProvider(ctx context.Context, realm, alias string) error

	GetFedLink(ctx context.Context, realm, alias, subject string) (FedLink, error)
	// CreateFedLink fails with ErrConflict when (realm, alias, subject) exists.
	CreateFedLink(ctx context.Context, l FedLink) error
	// UpdateFedLink replaces MappedRoles and LastLoginAt.
	UpdateFedLink(ctx context.Context, l FedLink) error
	ListFedLinksByUser(ctx context.Context, realm, userID string) ([]FedLink, error)
	// DeleteFedLink unlinks one provider from a user; ErrNotFound if none.
	DeleteFedLink(ctx context.Context, realm, alias, userID string) error
	DeleteFedLinksForUser(ctx context.Context, realm, userID string) (int, error)

	PutFedState(ctx context.Context, s FedLoginState) error
	// ConsumeFedState returns and deletes the state atomically; a second
	// call, or an unknown hash, returns ErrNotFound. Expiry is the caller's check.
	ConsumeFedState(ctx context.Context, stateHash string) (FedLoginState, error)
}
