// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idmodel

import (
	"strings"

	"github.com/zyvorai/haven/internal/idp"
)

// pkceKeys are the client attribute names that carry the PKCE method.
var pkceKeys = []string{"pkce.code.challenge.method", "pkceCodeChallengeMethod"}

// PKCEAttrKeys returns the attribute keys that carry the PKCE method, in
// priority order.
func PKCEAttrKeys() []string { return append([]string(nil), pkceKeys...) }

// FromRealm maps the idp wire realm into the neutral model.
func FromRealm(r idp.Realm) Realm {
	out := Realm{
		ID:                        r.ID,
		Name:                      r.Realm,
		DisplayName:               r.DisplayName,
		Enabled:                   r.Enabled,
		SelfRegistration:          r.RegistrationAllowed,
		EmailVerificationRequired: r.VerifyEmail,
		BruteForceProtection:      r.BruteForceProtected,
	}
	if h := r.RealmHardening; h != nil {
		out.Hardening = &Hardening{
			TransportSecurity:     h.SSLRequired,
			PasswordPolicy:        h.PasswordPolicy,
			AccessTokenTTLSeconds: h.AccessTokenLifespan,
			SessionIdleTTLSeconds: h.SSOSessionIdleTimeout,
			AuthEventsLogged:      h.EventsEnabled,
			AdminEventsLogged:     h.AdminEventsEnabled,
			RefreshTokenRotation:  h.RevokeRefreshToken,
		}
	}
	return out
}

// FromClient maps the idp wire client into the neutral model.
func FromClient(c idp.Client) Client {
	out := Client{
		ID: c.ID, ClientID: c.ClientID, Name: c.Name,
		Enabled: c.Enabled, Public: c.PublicClient, BearerOnly: c.BearerOnly,
		Protocol:     c.Protocol,
		RedirectURIs: c.RedirectURIs, Origins: c.WebOrigins,
		AuthCodeFlow: c.StandardFlowEnabled, ImplicitFlow: c.ImplicitFlowEnabled,
		PasswordFlow: c.DirectAccessGrantsEnabled, ServiceAccount: c.ServiceAccountsEnabled,
		Attrs: c.Attributes,
	}
	for _, k := range pkceKeys {
		if v := strings.TrimSpace(c.Attributes[k]); v != "" {
			out.PKCEMethod = v
			break
		}
	}
	return out
}

// FromClients maps a slice.
func FromClients(in []idp.Client) []Client {
	out := make([]Client, len(in))
	for i, c := range in {
		out[i] = FromClient(c)
	}
	return out
}

// FromRealms maps a slice.
func FromRealms(in []idp.Realm) []Realm {
	out := make([]Realm, len(in))
	for i, r := range in {
		out[i] = FromRealm(r)
	}
	return out
}

// FromUser maps the idp wire user.
func FromUser(u idp.User) User {
	return User{
		ID: u.ID, Username: u.Username, Email: u.Email,
		Enabled: u.Enabled, EmailVerified: u.EmailVerified,
		PendingActions:   u.RequiredActions,
		IsServiceAccount: strings.HasPrefix(u.Username, "service-account-"),
	}
}

// FromRole maps the idp wire role.
func FromRole(r idp.Role) Role { return Role{ID: r.ID, Name: r.Name, Description: r.Description} }

// FromGroup maps the idp wire group.
func FromGroup(g idp.Group) Group { return Group{ID: g.ID, Name: g.Name, Path: g.Path} }

// FromIdentityProvider maps the idp wire identity provider.
func FromIdentityProvider(p idp.IdentityProvider) FederationProvider {
	return FederationProvider{
		Alias: p.Alias, DisplayName: p.DisplayName, Kind: p.ProviderID,
		Enabled: p.Enabled, TrustEmail: p.TrustEmail, StoreToken: p.StoreToken,
		Config: p.Config,
	}
}
