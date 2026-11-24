// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// OAuth 2.0 Dynamic Client Registration (RFC 7591) and Client Registration
// Management (RFC 7592). This is a feature store: reach it with
// StoreAs[DCRStore]; a store without it simply has DCR switched off.

// DCRDefaultMaxClients is the per-realm cap on clients created through DCR
// when no RegistrationPolicy row exists.
const DCRDefaultMaxClients = 100

// DCRCreatedVia marks clients created through the registration endpoint.
const DCRCreatedVia = "dcr"

// DCRGrantTypes are the grant types DCR may hand out, in canonical order.
var DCRGrantTypes = []string{"authorization_code", "refresh_token", "client_credentials"}

// InitialAccessToken is an admin-issued capability to register clients. Only
// the sha256 hex of the token is stored. Each registration uses one of
// Remaining.
type InitialAccessToken struct {
	ID        string // public handle (Admin API), not a credential
	Realm     string
	TokenHash string
	Note      string
	Count     int // registrations granted at creation
	Remaining int
	CreatedAt time.Time
	ExpiresAt time.Time
}

// RegisteredClient is the DCR side-record of a client created through the
// registration endpoint. Its existence is what makes a client manageable with
// a registration access token: admin-created clients have none.
type RegisteredClient struct {
	Realm          string
	ClientID       string // OAuth client_id (hc_...)
	ClientUUID     string // core.Client.ID; guards against a reused client_id
	RegTokenHash   string // sha256 hex of the registration access token
	CreatedVia     string // DCRCreatedVia
	InitialTokenID string // InitialAccessToken.ID it was registered with

	ApplicationType string // "web" | "native"
	TokenAuthMethod string // none | client_secret_basic | client_secret_post
	Scope           string
	GrantTypes      []string
	Contacts        []string
	LogoURI         string
	ClientURI       string
	PolicyURI       string
	TosURI          string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// RegistrationPolicy is the per-realm DCR policy.
type RegistrationPolicy struct {
	Realm             string
	MaxClients        int
	AllowedGrantTypes []string
}

// DCRStore persists dynamic client registration state.
type DCRStore interface {
	// PutInitialAccessToken stores t (ErrConflict on a duplicate ID or hash).
	PutInitialAccessToken(ctx context.Context, t InitialAccessToken) error
	ListInitialAccessTokens(ctx context.Context, realm string) ([]InitialAccessToken, error)
	// DeleteInitialAccessToken revokes by ID (ErrNotFound if absent).
	DeleteInitialAccessToken(ctx context.Context, realm, id string) error
	// ConsumeInitialAccessToken atomically uses one registration of the token
	// with this hash if it exists, has not expired at now and has some left,
	// and returns it (Remaining already decremented). Otherwise ErrNotFound:
	// unknown, expired, exhausted and revoked are indistinguishable.
	ConsumeInitialAccessToken(ctx context.Context, realm, tokenHash string, now time.Time) (InitialAccessToken, error)
	// RefundInitialAccessToken gives one registration back (never above
	// Count). A missing token is not an error.
	RefundInitialAccessToken(ctx context.Context, realm, id string) error

	// PutRegisteredClient stores rc (ErrConflict if the client_id has one).
	PutRegisteredClient(ctx context.Context, rc RegisteredClient) error
	GetRegisteredClient(ctx context.Context, realm, clientID string) (RegisteredClient, error)
	// UpdateRegisteredClient replaces the metadata fields (ApplicationType,
	// TokenAuthMethod, Scope, GrantTypes, Contacts, the URIs) and UpdatedAt;
	// identity, token hash, marker and CreatedAt are kept.
	UpdateRegisteredClient(ctx context.Context, rc RegisteredClient) error
	DeleteRegisteredClient(ctx context.Context, realm, clientID string) error
	ListRegisteredClients(ctx context.Context, realm string) ([]RegisteredClient, error)

	// GetRegistrationPolicy returns ErrNotFound when none was set.
	GetRegistrationPolicy(ctx context.Context, realm string) (RegistrationPolicy, error)
	PutRegistrationPolicy(ctx context.Context, p RegistrationPolicy) error
}
