// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package upstream is the OIDC client side of identity brokering: it validates
// the configuration of an upstream provider (Google, Microsoft Entra ID, any
// generic OpenID Connect provider), fetches and caches its discovery document
// and keys, exchanges authorization codes and fully validates ID tokens.
//
// Every outbound request goes through internal/idp/safehttp (dial-time IP
// policy, no redirects, timeouts, size limits). Only the authorization code
// flow with PKCE (S256) and a nonce is implemented.
package upstream

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/zyvorai/haven/internal/idp/safehttp"
)

// Provider types.
const (
	TypeOIDC      = "oidc"
	TypeGoogle    = "google"
	TypeMicrosoft = "microsoft"
)

// Fixed endpoints of the presets.
const (
	GoogleIssuer       = "https://accounts.google.com"
	microsoftBase      = "https://login.microsoftonline.com/"
	microsoftTenantTpl = "{tenantid}" // placeholder in the multi-tenant issuer
)

// Config keys (the wire `config` map of idp.IdentityProvider). clientSecret is
// handled by the caller, never stored in this map.
const (
	KeyIssuer       = "issuer"
	KeyDiscovery    = "discoveryUrl"
	KeyClientID     = "clientId"
	KeyClientSecret = "clientSecret"
	KeyScopes       = "scopes"
	KeyTenant       = "tenant"
	KeyHostedDomain = "hostedDomain"
	KeyUsername     = "usernameClaim"
	KeyLinkByEmail  = "linkExistingByEmail"
	KeyAutoCreate   = "autoCreateUsers"
	KeyRoleMappings = "roleMappings"
	KeyRoleSync     = "roleSyncMode"
)

// RoleSync modes.
const (
	// SyncImport only ever adds roles granted by the mappings.
	SyncImport = "import"
	// SyncForce additionally removes roles federation added earlier that the
	// mappings no longer grant. Roles an administrator assigned are never removed.
	SyncForce = "sync"
)

// RoleRule grants Roles when the ID token claim Claim equals (or, for an array
// claim, contains) Value.
type RoleRule struct {
	Claim string   `json:"claim"`
	Value string   `json:"value"`
	Roles []string `json:"roles"`
}

// Spec is a validated provider configuration.
type Spec struct {
	Type          string
	Issuer        string // exact expected issuer; contains {tenantid} for multi-tenant Microsoft
	DiscoveryURL  string
	ClientID      string
	Scopes        []string
	Tenant        string
	HostedDomain  string
	UsernameClaim string
	LinkByEmail   bool
	AutoCreate    bool
	Rules         []RoleRule
	RoleSync      string
}

// MultiTenant reports whether the ID token issuer must be matched against the
// token's tid claim (Microsoft "common", "organizations", "consumers").
func (s Spec) MultiTenant() bool { return strings.Contains(s.Issuer, microsoftTenantTpl) }

var (
	guidRE      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	aliasRE     = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	scopeRE     = regexp.MustCompile(`^[A-Za-z0-9:._/-]{1,100}$`)
	claimRE     = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
	domainRE    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	roleNameRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	knownConfig = map[string]bool{KeyIssuer: true, KeyDiscovery: true, KeyClientID: true, KeyClientSecret: true,
		KeyScopes: true, KeyTenant: true, KeyHostedDomain: true, KeyUsername: true, KeyLinkByEmail: true,
		KeyAutoCreate: true, KeyRoleMappings: true, KeyRoleSync: true}
)

// ValidAlias reports whether s is an acceptable provider alias.
func ValidAlias(s string) bool { return aliasRE.MatchString(s) }

const (
	maxURL      = 512
	maxRules    = 64
	maxRulesLen = 16 << 10
	wellKnown   = "/.well-known/openid-configuration"
)

// ParseConfig validates cfg for a provider of type typ and returns the
// resolved Spec plus the canonical config (every key explicit, without
// clientSecret). It never contacts the network. allowPrivate permits http
// issuers on loopback (dev and tests). The returned error text is meant for
// the administrator and never contains secrets.
func ParseConfig(typ string, cfg map[string]string, allowPrivate bool) (Spec, map[string]string, error) {
	switch typ {
	case TypeOIDC, TypeGoogle, TypeMicrosoft:
	default:
		return Spec{}, nil, errors.New(`providerId must be "oidc", "google" or "microsoft" (GitHub and SAML are not supported)`)
	}
	for k := range cfg {
		if !knownConfig[k] {
			return Spec{}, nil, fmt.Errorf("unknown config key %q", k)
		}
	}
	s := Spec{Type: typ}
	out := map[string]string{}

	s.ClientID = strings.TrimSpace(cfg[KeyClientID])
	if s.ClientID == "" || len(s.ClientID) > 512 || hasCtl(s.ClientID) {
		return s, nil, errors.New("config.clientId is required (1-512 characters)")
	}
	out[KeyClientID] = s.ClientID

	scopes := strings.Fields(cfg[KeyScopes])
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	if len(scopes) > 20 {
		return s, nil, errors.New("config.scopes has too many entries")
	}
	hasOpenID := false
	for _, sc := range scopes {
		if !scopeRE.MatchString(sc) {
			return s, nil, errors.New("config.scopes contains an invalid scope")
		}
		hasOpenID = hasOpenID || sc == "openid"
	}
	if !hasOpenID {
		return s, nil, errors.New(`config.scopes must include "openid"`)
	}
	s.Scopes = scopes
	out[KeyScopes] = strings.Join(scopes, " ")

	s.UsernameClaim = strings.TrimSpace(cfg[KeyUsername])
	if s.UsernameClaim == "" {
		s.UsernameClaim = "preferred_username"
	}
	if !claimRE.MatchString(s.UsernameClaim) {
		return s, nil, errors.New("config.usernameClaim is invalid")
	}
	out[KeyUsername] = s.UsernameClaim

	var err error
	if s.LinkByEmail, err = parseBool(cfg, KeyLinkByEmail); err != nil {
		return s, nil, err
	}
	if s.AutoCreate, err = parseBool(cfg, KeyAutoCreate); err != nil {
		return s, nil, err
	}
	out[KeyLinkByEmail], out[KeyAutoCreate] = boolStr(s.LinkByEmail), boolStr(s.AutoCreate)

	s.RoleSync = cfg[KeyRoleSync]
	switch s.RoleSync {
	case "":
		s.RoleSync = SyncImport
	case SyncImport, SyncForce:
	default:
		return s, nil, errors.New(`config.roleSyncMode must be "import" or "sync"`)
	}
	out[KeyRoleSync] = s.RoleSync

	if raw := strings.TrimSpace(cfg[KeyRoleMappings]); raw != "" {
		if s.Rules, err = ParseRules(raw); err != nil {
			return s, nil, err
		}
		b, _ := json.Marshal(s.Rules)
		out[KeyRoleMappings] = string(b)
	}

	switch typ {
	case TypeGoogle:
		if err := presetIssuer(cfg, GoogleIssuer); err != nil {
			return s, nil, err
		}
		if cfg[KeyDiscovery] != "" || cfg[KeyTenant] != "" {
			return s, nil, errors.New("config.discoveryUrl and config.tenant do not apply to google")
		}
		s.Issuer = GoogleIssuer
		s.HostedDomain = strings.ToLower(strings.TrimSpace(cfg[KeyHostedDomain]))
		if s.HostedDomain != "" {
			if !domainRE.MatchString(s.HostedDomain) {
				return s, nil, errors.New("config.hostedDomain must be a domain name")
			}
			out[KeyHostedDomain] = s.HostedDomain
		}
	case TypeMicrosoft:
		if cfg[KeyDiscovery] != "" || cfg[KeyHostedDomain] != "" {
			return s, nil, errors.New("config.discoveryUrl and config.hostedDomain do not apply to microsoft")
		}
		s.Tenant = strings.ToLower(strings.TrimSpace(cfg[KeyTenant]))
		if s.Tenant == "" {
			s.Tenant = "common"
		}
		switch {
		case s.Tenant == "common" || s.Tenant == "organizations" || s.Tenant == "consumers":
			s.Issuer = microsoftBase + microsoftTenantTpl + "/v2.0"
			if s.LinkByEmail {
				return s, nil, errors.New("config.linkExistingByEmail is refused for a multi-tenant Microsoft provider: any Entra tenant could assert any email. Set config.tenant to your tenant id")
			}
		case guidRE.MatchString(s.Tenant):
			s.Issuer = microsoftBase + s.Tenant + "/v2.0"
		default:
			return s, nil, errors.New(`config.tenant must be a tenant id (GUID), "common", "organizations" or "consumers"`)
		}
		s.DiscoveryURL = microsoftBase + s.Tenant + "/v2.0" + wellKnown
		if v := strings.TrimSpace(cfg[KeyIssuer]); v != "" && v != s.Issuer && v != microsoftBase+s.Tenant+"/v2.0" {
			return s, nil, errors.New("config.issuer is fixed for this provider type; leave it out")
		}
		out[KeyTenant] = s.Tenant
	case TypeOIDC:
		if cfg[KeyTenant] != "" || cfg[KeyHostedDomain] != "" {
			return s, nil, errors.New("config.tenant and config.hostedDomain apply to microsoft and google only")
		}
		iss := strings.TrimSpace(cfg[KeyIssuer])
		disco := strings.TrimSpace(cfg[KeyDiscovery])
		if iss == "" && disco == "" {
			return s, nil, errors.New("config.issuer (or config.discoveryUrl) is required")
		}
		if disco != "" {
			if _, err := safehttp.ValidateURL(disco, allowPrivate, "config.discoveryUrl", maxURL); err != nil {
				return s, nil, err
			}
			if iss == "" {
				if !strings.HasSuffix(disco, wellKnown) {
					return s, nil, errors.New("config.issuer is required when config.discoveryUrl does not end in " + wellKnown)
				}
				iss = strings.TrimSuffix(disco, wellKnown)
			}
			s.DiscoveryURL = disco
			out[KeyDiscovery] = disco
		}
		u, err := safehttp.ValidateURL(iss, allowPrivate, "config.issuer", maxURL)
		if err != nil {
			return s, nil, err
		}
		if u.RawQuery != "" || u.ForceQuery {
			return s, nil, errors.New("config.issuer must not contain a query")
		}
		s.Issuer = iss
		out[KeyIssuer] = iss
		if s.DiscoveryURL == "" {
			s.DiscoveryURL = strings.TrimRight(iss, "/") + wellKnown
		}
	}
	return s, out, nil
}

// presetIssuer accepts an issuer in cfg only when it equals the fixed value.
func presetIssuer(cfg map[string]string, want string) error {
	if v := strings.TrimSpace(cfg[KeyIssuer]); v != "" && v != want {
		return errors.New("config.issuer is fixed for this provider type; leave it out")
	}
	return nil
}

func parseBool(cfg map[string]string, k string) (bool, error) {
	switch cfg[k] {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, fmt.Errorf(`config.%s must be "true" or "false"`, k)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func hasCtl(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// ParseRules parses and validates the compact roleMappings JSON:
// [{"claim":"groups","value":"eng","roles":["developer"]}, ...].
func ParseRules(raw string) ([]RoleRule, error) {
	if len(raw) > maxRulesLen {
		return nil, errors.New("config.roleMappings is too large")
	}
	var rules []RoleRule
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rules); err != nil || dec.More() {
		return nil, errors.New(`config.roleMappings must be a JSON array of {"claim","value","roles":[...]}`)
	}
	if len(rules) > maxRules {
		return nil, errors.New("config.roleMappings has too many rules")
	}
	for _, r := range rules {
		if !claimRE.MatchString(r.Claim) || r.Value == "" || len(r.Value) > 256 || hasCtl(r.Value) {
			return nil, errors.New("config.roleMappings: invalid claim or value")
		}
		if len(r.Roles) == 0 || len(r.Roles) > 32 {
			return nil, errors.New("config.roleMappings: each rule needs 1-32 roles")
		}
		for _, n := range r.Roles {
			if !roleNameRE.MatchString(n) {
				return nil, errors.New("config.roleMappings: invalid role name")
			}
		}
	}
	return rules, nil
}

// MapRoles returns the (de-duplicated, sorted) roles the rules grant for the
// given ID token claims.
func MapRoles(rules []RoleRule, claims map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rules {
		if !claimMatches(lookup(claims, r.Claim), r.Value) {
			continue
		}
		for _, n := range r.Roles {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	slices.Sort(out)
	return out
}

// lookup finds a claim by exact top-level name first, then by dotted path
// through nested objects.
func lookup(claims map[string]any, name string) any {
	if v, ok := claims[name]; ok {
		return v
	}
	if !strings.Contains(name, ".") {
		return nil
	}
	var cur any = claims
	for _, part := range strings.Split(name, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

func claimMatches(v any, want string) bool {
	switch x := v.(type) {
	case string:
		return x == want
	case bool:
		return fmt.Sprint(x) == want
	case json.Number:
		return x.String() == want
	case float64:
		return fmt.Sprint(x) == want
	case []any:
		for _, e := range x {
			if claimMatches(e, want) {
				return true
			}
		}
	}
	return false
}
