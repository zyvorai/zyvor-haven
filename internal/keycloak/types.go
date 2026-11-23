// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keycloak

import "github.com/zyvorai/haven/internal/idp"

// The wire types live in internal/idp so the API, Guard and Time Machine do
// not depend on a specific identity backend. These aliases keep the Keycloak
// adapter source-compatible.
type (
	Realm            = idp.Realm
	RealmHardening   = idp.RealmHardening
	Client           = idp.Client
	ClientSecret     = idp.ClientSecret
	User             = idp.User
	Role             = idp.Role
	RoleMappings     = idp.RoleMappings
	Group            = idp.Group
	IdentityProvider = idp.IdentityProvider
	ClientScope      = idp.ClientScope
	AdminEvent       = idp.AdminEvent
	Key              = idp.Key
	ServerInfo       = idp.ServerInfo
	Status           = idp.Status
	PasswordReset    = idp.PasswordReset
	APIError         = idp.APIError
)
