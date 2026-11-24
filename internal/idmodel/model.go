// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package idmodel is the backend-neutral view of an identity realm that Haven
// Guard, Time Machine and Access Review operate on. Backends map their own
// representation into it (see FromRealm and friends for the idp wire types).
package idmodel

// Realm is the core of a tenant. Hardening is nil when the source reported
// none of the optional settings; individual nil fields mean "not reported",
// which is never a finding.
type Realm struct {
	ID                        string
	Name                      string
	DisplayName               string
	Enabled                   bool
	SelfRegistration          bool
	EmailVerificationRequired bool
	BruteForceProtection      bool
	Hardening                 *Hardening
}

// Hardening holds optional security settings.
type Hardening struct {
	TransportSecurity     *string // "none", "external" or "all"
	PasswordPolicy        *string
	AccessTokenTTLSeconds *int
	SessionIdleTTLSeconds *int
	SessionMaxTTLSeconds  *int // SSO session absolute lifetime (Guard HAVEN022)
	OfflineIdleTTLSeconds *int // offline session idle timeout (Guard HAVEN023)
	AuthEventsLogged      *bool
	AdminEventsLogged     *bool
	RefreshTokenRotation  *bool
}

// Client is an application registered in a realm.
type Client struct {
	ID           string
	ClientID     string
	Name         string
	Enabled      bool
	Public       bool
	BearerOnly   bool
	Protocol     string // "openid-connect", "saml", ...
	RedirectURIs []string
	Origins      []string

	AuthCodeFlow   bool
	ImplicitFlow   bool
	PasswordFlow   bool
	ServiceAccount bool

	// PKCEMethod is the normalized code-challenge method ("" when unset).
	PKCEMethod string
	// BackchannelLogoutURL is the OIDC Back-Channel Logout endpoint ("" = none).
	// Keycloak keeps it in the attribute BackchannelLogoutAttr.
	BackchannelLogoutURL string
	// Attrs keeps the provider attributes verbatim. Guard fingerprints hash the
	// PKCE-related keys so existing baselines stay valid.
	Attrs map[string]string
}

// User is an account in a realm.
type User struct {
	ID               string
	Username         string
	Email            string
	Enabled          bool
	EmailVerified    bool
	PendingActions   []string
	IsServiceAccount bool
}

// Role is a realm role.
type Role struct {
	ID          string
	Name        string
	Description string
}

// Group is a realm group addressed by path.
type Group struct {
	ID   string
	Name string
	Path string
}

// FederationProvider is an upstream identity provider.
type FederationProvider struct {
	Alias       string
	DisplayName string
	Kind        string // "oidc", "saml", "google", "github", ...
	Enabled     bool
	TrustEmail  bool
	StoreToken  bool
	Config      map[string]string
}

// UserAccess is a user's role and group bindings by name.
type UserAccess struct {
	Username   string
	RealmRoles []string
	Groups     []string
}

// BackchannelLogoutAttr and FrontchannelLogoutAttr are the Keycloak client
// attribute names for the logout URLs. Only the back-channel one is supported.
const (
	BackchannelLogoutAttr  = "backchannel.logout.url"
	FrontchannelLogoutAttr = "frontchannel.logout.url"
)
