// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keycloak

import "encoding/json"

type Realm struct {
	ID                  string `json:"id,omitempty"`
	Realm               string `json:"realm"`
	DisplayName         string `json:"displayName,omitempty"`
	Enabled             bool   `json:"enabled"`
	RegistrationAllowed bool   `json:"registrationAllowed,omitempty"`
	VerifyEmail         bool   `json:"verifyEmail,omitempty"`
	BruteForceProtected bool   `json:"bruteForceProtected,omitempty"`

	// RealmHardening carries optional settings read by Haven Guard. A nil
	// pointer means the source did not report the value, which is never
	// treated as a finding.
	*RealmHardening
}

// RealmHardening holds the realm settings Haven Guard evaluates beyond the
// core fields. Fields are pointers so "absent" and "false" stay distinct.
type RealmHardening struct {
	SSLRequired               *string `json:"sslRequired,omitempty"`
	PasswordPolicy            *string `json:"passwordPolicy,omitempty"`
	AccessTokenLifespan       *int    `json:"accessTokenLifespan,omitempty"`
	SSOSessionIdleTimeout     *int    `json:"ssoSessionIdleTimeout,omitempty"`
	SSOSessionMaxLifespan     *int    `json:"ssoSessionMaxLifespan,omitempty"`
	OfflineSessionIdleTimeout *int    `json:"offlineSessionIdleTimeout,omitempty"`
	EventsEnabled             *bool   `json:"eventsEnabled,omitempty"`
	AdminEventsEnabled        *bool   `json:"adminEventsEnabled,omitempty"`
	RevokeRefreshToken        *bool   `json:"revokeRefreshToken,omitempty"`
}

type Client struct {
	ID                        string            `json:"id,omitempty"`
	ClientID                  string            `json:"clientId"`
	Name                      string            `json:"name,omitempty"`
	Description               string            `json:"description,omitempty"`
	Enabled                   bool              `json:"enabled"`
	PublicClient              bool              `json:"publicClient"`
	BearerOnly                bool              `json:"bearerOnly,omitempty"`
	Protocol                  string            `json:"protocol,omitempty"`
	RedirectURIs              []string          `json:"redirectUris,omitempty"`
	WebOrigins                []string          `json:"webOrigins,omitempty"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled,omitempty"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled,omitempty"`
	Attributes                map[string]string `json:"attributes,omitempty"`
	Secret                    string            `json:"secret,omitempty"`
}

type ClientSecret struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type User struct {
	ID              string   `json:"id,omitempty"`
	Username        string   `json:"username"`
	Email           string   `json:"email,omitempty"`
	FirstName       string   `json:"firstName,omitempty"`
	LastName        string   `json:"lastName,omitempty"`
	Enabled         bool     `json:"enabled"`
	EmailVerified   bool     `json:"emailVerified"`
	RequiredActions []string `json:"requiredActions,omitempty"`
}

type Role struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type RoleMappings struct {
	RealmMappings []Role `json:"realmMappings,omitempty"`
}

type Group struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

type IdentityProvider struct {
	Alias                     string            `json:"alias"`
	DisplayName               string            `json:"displayName,omitempty"`
	ProviderID                string            `json:"providerId"`
	Enabled                   bool              `json:"enabled"`
	TrustEmail                bool              `json:"trustEmail,omitempty"`
	StoreToken                bool              `json:"storeToken,omitempty"`
	FirstBrokerLoginFlowAlias string            `json:"firstBrokerLoginFlowAlias,omitempty"`
	Config                    map[string]string `json:"config,omitempty"`
}

type ClientScope struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

type AdminEvent struct {
	Time           int64  `json:"time"`
	RealmID        string `json:"realmId,omitempty"`
	OperationType  string `json:"operationType,omitempty"`
	ResourceType   string `json:"resourceType,omitempty"`
	ResourcePath   string `json:"resourcePath,omitempty"`
	Representation string `json:"representation,omitempty"`
	Error          string `json:"error,omitempty"`
}

type Key struct {
	ProviderID       string `json:"providerId,omitempty"`
	ProviderPriority int    `json:"providerPriority,omitempty"`
	Status           string `json:"status,omitempty"`
	Type             string `json:"type,omitempty"`
	Kid              string `json:"kid,omitempty"`
}

type ServerInfo struct {
	SystemInfo struct {
		Version string `json:"version"`
		Uptime  string `json:"uptime,omitempty"`
	} `json:"systemInfo,omitempty"`
	MemoryInfo struct {
		Total int64 `json:"total,omitempty"`
		Free  int64 `json:"free,omitempty"`
	} `json:"memoryInfo,omitempty"`
}

type Status struct {
	Connected   bool   `json:"connected"`
	Version     string `json:"version,omitempty"`
	RealmCount  int    `json:"realmCount"`
	KeycloakURL string `json:"keycloakUrl"`
}

type PasswordReset struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

type APIError struct {
	Error    string          `json:"error"`
	Keycloak json.RawMessage `json:"keycloak,omitempty"`
	Status   int             `json:"status,omitempty"`
}
