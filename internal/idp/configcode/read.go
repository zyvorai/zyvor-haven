// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"context"
	"fmt"

	"github.com/zyvorai/haven/internal/idmodel"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/posture"
)

const (
	adminClientID = "haven-admin"
	pkceAttr      = "pkce.code.challenge.method"
)

func isUnmanagedClient(id string) bool { return id == adminClientID || posture.IsBuiltInClient(id) }

// Read returns the live realm as a normalized Spec (hardening fields
// populated, built-in and admin clients omitted, everything sorted). The error
// wraps idp.ErrNotFound when the realm does not exist.
func Read(ctx context.Context, p idp.Provider, realm string) (*Spec, error) {
	r, err := p.GetRealm(ctx, realm)
	if err != nil {
		return nil, fmt.Errorf("read realm %q: %w", realm, err)
	}
	if r == nil {
		return nil, fmt.Errorf("read realm %q: %w", realm, idp.ErrNotFound)
	}
	s := &Spec{APIVersion: APIVersion, Kind: KindRealm, Realm: r.Realm, DisplayName: r.DisplayName}
	if s.Realm == "" {
		s.Realm = realm
	}
	enabled := r.Enabled
	s.Enabled = &enabled
	reg, ver, bf := r.RegistrationAllowed, r.VerifyEmail, r.BruteForceProtected
	s.Settings = Settings{SelfRegistration: &reg, EmailVerificationRequired: &ver, BruteForceProtection: &bf}
	if h := r.RealmHardening; h != nil {
		s.Settings.TransportSecurity = h.SSLRequired
		s.Settings.PasswordPolicy = h.PasswordPolicy
		s.Settings.AccessTokenSeconds = h.AccessTokenLifespan
		s.Settings.SessionIdleSeconds = h.SSOSessionIdleTimeout
		s.Settings.AuthEvents = h.EventsEnabled
		s.Settings.AdminEvents = h.AdminEventsEnabled
		s.Settings.RefreshTokenRotation = h.RevokeRefreshToken
	}
	roles, err := p.ListRoles(ctx, realm)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	for _, ro := range roles {
		s.Roles = append(s.Roles, Role{Name: ro.Name, Description: ro.Description})
	}
	groups, err := p.ListGroups(ctx, realm)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	for _, g := range groups {
		s.Groups = append(s.Groups, Group{Name: g.Name})
	}
	clients, err := p.ListClients(ctx, realm)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	for _, c := range clients {
		if isUnmanagedClient(c.ClientID) {
			continue
		}
		s.Clients = append(s.Clients, fromIDPClient(c))
	}
	return normalized(s), nil
}

func fromIDPClient(c idp.Client) Client {
	en, flow, pkce := c.Enabled, c.StandardFlowEnabled, c.Attributes[pkceAttr] == "S256"
	return Client{
		ClientID: c.ClientID, Name: c.Name, Enabled: &en, Public: c.PublicClient,
		ServiceAccount: c.ServiceAccountsEnabled, AuthCodeFlow: &flow, RequirePKCE: &pkce,
		RedirectURIs: c.RedirectURIs, Origins: c.WebOrigins,
		BackchannelLogoutURL: idmodel.FromClient(c).BackchannelLogoutURL,
	}
}
