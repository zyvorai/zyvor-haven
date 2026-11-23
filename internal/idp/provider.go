// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package idp defines the identity backend that Haven manages. Haven's API,
// Guard, Time Machine and Access Review depend on Provider, never on a
// concrete server. Write methods return an error; a backend rejection is an *StatusError
// that matches ErrNotFound or ErrConflict via errors.Is.
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
	CreateRealm(ctx context.Context, realm Realm) error
	UpdateRealm(ctx context.Context, realm string, body Realm) error
	DeleteRealm(ctx context.Context, realm string) error
	RealmExists(ctx context.Context, name string) (bool, error)
	BootstrapRealm(ctx context.Context, name string) error

	// Clients and secrets.
	ListClients(ctx context.Context, realm string) ([]Client, error)
	GetClient(ctx context.Context, realm, id string) (*Client, error)
	CreateClient(ctx context.Context, realm string, cl Client) error
	UpdateClient(ctx context.Context, realm, id string, cl Client) error
	DeleteClient(ctx context.Context, realm, id string) error
	EnsureHavenConsoleClient(ctx context.Context, realm string, consoleBases ...string) error
	GetClientSecret(ctx context.Context, realm, id string) (*ClientSecret, error)
	RegenerateClientSecret(ctx context.Context, realm, id string) (*ClientSecret, error)
	GetRotatedClientSecret(ctx context.Context, realm, id string) (*ClientSecret, error)
	InvalidateRotatedClientSecret(ctx context.Context, realm, id string) error
	ListClientScopes(ctx context.Context, realm string) ([]ClientScope, error)

	// Users.
	ListUsers(ctx context.Context, realm, search string) ([]User, error)
	ListAllUsers(ctx context.Context, realm string) ([]User, error)
	CreateUser(ctx context.Context, realm string, u User) error
	UpdateUser(ctx context.Context, realm, id string, u User) error
	DeleteUser(ctx context.Context, realm, id string) error
	ResetPassword(ctx context.Context, realm, id string, pw PasswordReset) error
	EnsureUserPassword(ctx context.Context, realm, username, password string) error

	// Roles and groups.
	ListRoles(ctx context.Context, realm string) ([]Role, error)
	CreateRole(ctx context.Context, realm string, role Role) error
	GetUserRoleMappings(ctx context.Context, realm, userID string) (*RoleMappings, error)
	AddRealmRoleMappings(ctx context.Context, realm, userID string, roles []Role) error
	ListGroups(ctx context.Context, realm string) ([]Group, error)
	CreateGroup(ctx context.Context, realm string, group Group) error
	ListUserGroups(ctx context.Context, realm, userID string) ([]Group, error)
	JoinGroup(ctx context.Context, realm, userID, groupID string) error

	// Federation.
	ListIdentityProviders(ctx context.Context, realm string) ([]IdentityProvider, error)
	CreateIdentityProvider(ctx context.Context, realm string, ip IdentityProvider) error
	DeleteIdentityProvider(ctx context.Context, realm, alias string) error

	// Events, keys and native backup/restore.
	ListAdminEvents(ctx context.Context, realm string) ([]AdminEvent, error)
	ListKeys(ctx context.Context, realm string) ([]Key, error)
	PartialExport(ctx context.Context, realm string) (json.RawMessage, error)
	PartialImport(ctx context.Context, realm string, payload json.RawMessage) error
}
