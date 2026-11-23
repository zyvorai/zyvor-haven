// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package idp defines the identity backend that Haven manages. Haven's API,
// Guard, Time Machine and Access Review depend on Provider, never on a
// concrete server. Write methods keep the (status, body, error) shape for now;
// Phase 1b replaces the raw HTTP status with typed errors.
package idp

import (
	"context"
	"encoding/json"
)

// Provider is the full admin surface Haven needs from an identity backend.
type Provider interface {
	// Health and realms.
	Status(ctx context.Context) (*Status, error)
	ListRealms(ctx context.Context) ([]Realm, error)
	GetRealm(ctx context.Context, realm string) (*Realm, error)
	CreateRealm(ctx context.Context, realm Realm) (int, []byte, error)
	UpdateRealm(ctx context.Context, realm string, body Realm) (int, []byte, error)
	DeleteRealm(ctx context.Context, realm string) (int, []byte, error)
	RealmExists(ctx context.Context, name string) (bool, error)
	BootstrapRealm(ctx context.Context, name string) error

	// Clients and secrets.
	ListClients(ctx context.Context, realm string) ([]Client, error)
	GetClient(ctx context.Context, realm, id string) (*Client, error)
	CreateClient(ctx context.Context, realm string, cl Client) (int, []byte, error)
	UpdateClient(ctx context.Context, realm, id string, cl Client) (int, []byte, error)
	DeleteClient(ctx context.Context, realm, id string) (int, []byte, error)
	EnsureHavenConsoleClient(ctx context.Context, realm string, consoleBases ...string) error
	GetClientSecret(ctx context.Context, realm, id string) (*ClientSecret, error)
	RegenerateClientSecret(ctx context.Context, realm, id string) (*ClientSecret, error)
	GetRotatedClientSecret(ctx context.Context, realm, id string) (*ClientSecret, int, error)
	InvalidateRotatedClientSecret(ctx context.Context, realm, id string) (int, []byte, error)
	ListClientScopes(ctx context.Context, realm string) ([]ClientScope, error)

	// Users.
	ListUsers(ctx context.Context, realm, search string) ([]User, error)
	ListAllUsers(ctx context.Context, realm string) ([]User, error)
	CreateUser(ctx context.Context, realm string, u User) (int, []byte, error)
	UpdateUser(ctx context.Context, realm, id string, u User) (int, []byte, error)
	DeleteUser(ctx context.Context, realm, id string) (int, []byte, error)
	ResetPassword(ctx context.Context, realm, id string, pw PasswordReset) (int, []byte, error)
	EnsureUserPassword(ctx context.Context, realm, username, password string) error

	// Roles and groups.
	ListRoles(ctx context.Context, realm string) ([]Role, error)
	CreateRole(ctx context.Context, realm string, role Role) (int, []byte, error)
	GetUserRoleMappings(ctx context.Context, realm, userID string) (*RoleMappings, error)
	AddRealmRoleMappings(ctx context.Context, realm, userID string, roles []Role) (int, []byte, error)
	ListGroups(ctx context.Context, realm string) ([]Group, error)
	CreateGroup(ctx context.Context, realm string, group Group) (int, []byte, error)
	ListUserGroups(ctx context.Context, realm, userID string) ([]Group, error)
	JoinGroup(ctx context.Context, realm, userID, groupID string) (int, []byte, error)

	// Federation.
	ListIdentityProviders(ctx context.Context, realm string) ([]IdentityProvider, error)
	CreateIdentityProvider(ctx context.Context, realm string, idp IdentityProvider) (int, []byte, error)
	DeleteIdentityProvider(ctx context.Context, realm, alias string) (int, []byte, error)

	// Events, keys and native backup/restore.
	ListAdminEvents(ctx context.Context, realm string) ([]AdminEvent, error)
	ListKeys(ctx context.Context, realm string) ([]Key, error)
	PartialExport(ctx context.Context, realm string) (json.RawMessage, error)
	PartialImport(ctx context.Context, realm string, payload json.RawMessage) (int, []byte, error)
}
