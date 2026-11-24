// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package configcode is "config as code" for realms: a declarative YAML file
// describes a realm, `Diff` compares it with the live state read through an
// idp.Provider, `Gate` runs Haven Guard on the result, and `Apply` makes it so.
// Because it works on idp.Provider it applies to any provider implementation.
//
// Semantics (contract for every implementation):
//   - A nil/absent setting means "unmanaged": it is never changed on an existing
//     realm, and gets a secure default when the realm is created.
//   - roles, groups and clients are managed sets. Entries in the file are
//     created or updated; live entries missing from the file are left alone
//     unless Options.Prune is set, in which case live clients (only) are
//     deleted; roles and groups are never pruned in v1.
//   - Built-in clients (posture.IsBuiltInClient) and the admin client are never
//     pruned. Users are data, not configuration, and are out of scope in v1.
//   - Secrets never appear in a Spec, a Plan or rendered output. A confidential
//     client's generated secret is returned once in ApplyResult.NewSecrets.
package configcode

import "github.com/zyvorai/haven/internal/posture"

const (
	APIVersion = "haven.zyvor.dev/v1"
	KindRealm  = "Realm"
)

// Spec is one realm file.
type Spec struct {
	APIVersion  string   `json:"apiVersion"`
	Kind        string   `json:"kind"`
	Realm       string   `json:"realm"`
	DisplayName string   `json:"displayName,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	Settings    Settings `json:"settings,omitempty"`
	Roles       []Role   `json:"roles,omitempty"`
	Groups      []Group  `json:"groups,omitempty"`
	Clients     []Client `json:"clients,omitempty"`
}

// Settings are the realm-level security settings. nil = unmanaged.
type Settings struct {
	SelfRegistration          *bool   `json:"selfRegistration,omitempty"`
	EmailVerificationRequired *bool   `json:"emailVerificationRequired,omitempty"`
	BruteForceProtection      *bool   `json:"bruteForceProtection,omitempty"`
	TransportSecurity         *string `json:"transportSecurity,omitempty"` // none | external | all
	PasswordPolicy            *string `json:"passwordPolicy,omitempty"`    // e.g. "length(12) and digits(1)"
	AccessTokenSeconds        *int    `json:"accessTokenSeconds,omitempty"`
	SessionIdleSeconds        *int    `json:"sessionIdleSeconds,omitempty"`
	AuthEvents                *bool   `json:"authEvents,omitempty"`
	AdminEvents               *bool   `json:"adminEvents,omitempty"`
	RefreshTokenRotation      *bool   `json:"refreshTokenRotation,omitempty"`
}

type Role struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Group struct {
	Name string `json:"name"`
}

// Client is an application. Public clients default to PKCE required.
type Client struct {
	ClientID       string   `json:"clientId"`
	Name           string   `json:"name,omitempty"`
	Enabled        *bool    `json:"enabled,omitempty"` // default true
	Public         bool     `json:"public,omitempty"`
	ServiceAccount bool     `json:"serviceAccount,omitempty"`
	AuthCodeFlow   *bool    `json:"authCodeFlow,omitempty"` // default: true unless ServiceAccount
	RequirePKCE    *bool    `json:"requirePKCE,omitempty"`  // default: true for public clients
	RedirectURIs   []string `json:"redirectUris,omitempty"`
	Origins        []string `json:"origins,omitempty"`
	// BackchannelLogoutURL receives OIDC Back-Channel Logout tokens (https; http for loopback). Empty = not notified.
	BackchannelLogoutURL string `json:"backchannelLogoutUrl,omitempty"`
	// DeviceFlowEnabled lets the client use the OAuth 2.0 Device Authorization Grant (RFC 8628). Default false.
	DeviceFlowEnabled bool `json:"deviceFlowEnabled,omitempty"`
}

// Action is what a Change does.
type Action string

const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// Kind of a Change.
const (
	KindOfRealm  = "realm"
	KindOfRole   = "role"
	KindOfGroup  = "group"
	KindOfClient = "client"
)

// FieldChange is one differing field, rendered as strings for display.
// Old is "" for creates and New is "" for deletes. Never contains secrets.
type FieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old,omitempty"`
	New   string `json:"new,omitempty"`
}

// Change is one step of a Plan.
type Change struct {
	Action Action        `json:"action"`
	Kind   string        `json:"kind"`
	Name   string        `json:"name"`
	Fields []FieldChange `json:"fields,omitempty"`
}

// Plan is the ordered list of changes that turns live into desired.
// Order: realm, roles, groups, clients (creates/updates), then deletes in
// reverse dependency order (clients only in v1). Empty = no drift.
type Plan struct {
	Realm        string   `json:"realm"`
	RealmMissing bool     `json:"realmMissing,omitempty"` // realm does not exist yet
	Changes      []Change `json:"changes"`
}

// Options for Diff and Apply.
type Options struct {
	// Prune deletes live clients that the file does not list. Roles and groups
	// are never pruned in v1 (idp.Provider cannot delete them).
	Prune bool
}

// ApplyResult reports what Apply did.
type ApplyResult struct {
	Applied []Change `json:"applied"`
	// NewSecrets maps clientId to the generated secret of each newly created
	// confidential client. Revealed once; the caller must store it safely.
	NewSecrets map[string]string `json:"-"`
}

// GateResult is Guard's verdict on what applying a Spec would do.
type GateResult struct {
	Before  posture.Report
	After   posture.Report
	New     []posture.Finding // present After, absent Before
	Fixed   []posture.Finding // present Before, absent After
	Blocked []posture.Finding // subset of New at or above the threshold
}
