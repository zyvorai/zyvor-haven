// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

const pkceAttr = "pkce.code.challenge.method"

var (
	clientIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)
	roleNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	actionRE   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

func ptr[T any](v T) *T { return &v }

// ---- realm ----

func realmToWire(r core.Realm) idp.Realm {
	return idp.Realm{
		ID: r.ID, Realm: r.Name, DisplayName: r.DisplayName, Enabled: r.Enabled,
		RegistrationAllowed: r.SelfRegistration, VerifyEmail: r.EmailVerificationRequired,
		BruteForceProtected: r.BruteForceProtection,
		RealmHardening: &idp.RealmHardening{
			SSLRequired:           ptr(r.TransportSecurity),
			PasswordPolicy:        ptr(r.PasswordPolicy),
			AccessTokenLifespan:   ptr(int(r.AccessTokenTTL / time.Second)),
			SSOSessionIdleTimeout: ptr(int(r.SessionIdleTTL / time.Second)),
			EventsEnabled:         ptr(r.AuthEventsLogged),
			AdminEventsEnabled:    ptr(r.AdminEventsLogged),
			RevokeRefreshToken:    ptr(r.RefreshTokenRotation),
		},
	}
}

// applyRealm copies the wire fields onto base (a secure-default realm on
// create, the stored realm on update). present tells whether the body named
// bruteForceProtected, since false and absent look alike on the wire.
func applyRealm(base core.Realm, w idp.Realm, present map[string]bool) (core.Realm, error) {
	if !validText(w.DisplayName, 255) {
		return base, bad("invalid displayName")
	}
	base.DisplayName = w.DisplayName
	base.Enabled = w.Enabled
	base.SelfRegistration = w.RegistrationAllowed
	base.EmailVerificationRequired = w.VerifyEmail
	if present["bruteForceProtected"] {
		base.BruteForceProtection = w.BruteForceProtected
	}
	h := w.RealmHardening
	if h == nil {
		return base, nil
	}
	if h.SSLRequired != nil {
		switch *h.SSLRequired {
		case "none", "external", "all":
			base.TransportSecurity = *h.SSLRequired
		default:
			return base, bad("sslRequired must be none, external or all")
		}
	}
	if h.PasswordPolicy != nil {
		if !validText(*h.PasswordPolicy, 512) {
			return base, bad("invalid passwordPolicy")
		}
		base.PasswordPolicy = *h.PasswordPolicy
	}
	if h.AccessTokenLifespan != nil {
		if *h.AccessTokenLifespan < 1 || *h.AccessTokenLifespan > 86400 {
			return base, bad("accessTokenLifespan must be 1..86400 seconds")
		}
		base.AccessTokenTTL = time.Duration(*h.AccessTokenLifespan) * time.Second
	}
	if h.SSOSessionIdleTimeout != nil {
		if *h.SSOSessionIdleTimeout < 1 || *h.SSOSessionIdleTimeout > 30*86400 {
			return base, bad("ssoSessionIdleTimeout must be 1..2592000 seconds")
		}
		base.SessionIdleTTL = time.Duration(*h.SSOSessionIdleTimeout) * time.Second
	}
	if h.EventsEnabled != nil {
		base.AuthEventsLogged = *h.EventsEnabled
	}
	if h.AdminEventsEnabled != nil {
		base.AdminEventsLogged = *h.AdminEventsEnabled
	}
	if h.RevokeRefreshToken != nil {
		base.RefreshTokenRotation = *h.RevokeRefreshToken
	}
	return base, nil
}

func secureRealmDefaults(name string) core.Realm {
	return core.Realm{
		Name: name, BruteForceProtection: true, TransportSecurity: "external",
		PasswordPolicy: "length(12)", AccessTokenTTL: 300 * time.Second,
		RefreshTokenTTL: 30 * 24 * time.Hour, SessionIdleTTL: 1800 * time.Second,
		AuthEventsLogged: true, AdminEventsLogged: true, RefreshTokenRotation: true,
	}
}

// ---- client ----

func clientToWire(c core.Client) idp.Client {
	w := idp.Client{
		ID: c.ID, ClientID: c.ClientID, Name: c.Name, Enabled: c.Enabled,
		PublicClient: c.Public, Protocol: "openid-connect",
		RedirectURIs: c.RedirectURIs, WebOrigins: c.Origins,
		StandardFlowEnabled: c.AuthCodeFlow, DirectAccessGrantsEnabled: c.PasswordFlow,
		ServiceAccountsEnabled: c.ServiceAccount,
	}
	if c.RequirePKCE {
		w.Attributes = map[string]string{pkceAttr: "S256"}
	}
	return w
}

// clientFromWire validates w and maps it to a core client. The caller sets
// ID, Realm, SecretHash and CreatedAt.
func clientFromWire(w idp.Client) (core.Client, error) {
	if !clientIDRE.MatchString(w.ClientID) {
		return core.Client{}, bad("invalid clientId")
	}
	if !validText(w.Name, 255) || !validText(w.Description, 1024) {
		return core.Client{}, bad("invalid name or description")
	}
	if w.Protocol != "" && w.Protocol != "openid-connect" {
		return core.Client{}, bad("only the openid-connect protocol is supported")
	}
	if w.DirectAccessGrantsEnabled {
		return core.Client{}, bad("directAccessGrantsEnabled is not implemented")
	}
	if w.ImplicitFlowEnabled {
		return core.Client{}, bad("implicitFlowEnabled is not implemented")
	}
	if w.BearerOnly {
		return core.Client{}, bad("bearerOnly is not implemented")
	}
	if w.Secret != "" {
		return core.Client{}, bad("secret cannot be set; it is generated")
	}
	if w.PublicClient && w.ServiceAccountsEnabled {
		return core.Client{}, bad("a public client cannot be a service account")
	}
	pk := w.Attributes[pkceAttr]
	if pk != "" && pk != "S256" {
		return core.Client{}, bad(pkceAttr + " must be S256")
	}
	if len(w.RedirectURIs) > 50 || len(w.WebOrigins) > 50 {
		return core.Client{}, bad("too many redirect URIs or origins")
	}
	for _, u := range w.RedirectURIs {
		if !validRedirect(u) {
			return core.Client{}, bad("invalid redirect URI")
		}
	}
	for _, o := range w.WebOrigins {
		if !validOrigin(o) {
			return core.Client{}, bad("invalid web origin")
		}
	}
	return core.Client{
		ClientID: w.ClientID, Name: w.Name, Enabled: w.Enabled, Public: w.PublicClient,
		RedirectURIs: w.RedirectURIs, Origins: w.WebOrigins,
		AuthCodeFlow: w.StandardFlowEnabled, ServiceAccount: w.ServiceAccountsEnabled,
		RequirePKCE: w.PublicClient || pk == "S256",
	}, nil
}

func validRedirect(raw string) bool {
	if raw == "" || len(raw) > 2048 || !validText(raw, 2048) || strings.Contains(raw, "*") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Fragment != "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "javascript", "data", "vbscript", "file", "blob":
		return false
	case "http", "https":
		return u.Host != ""
	}
	return true
}

func validOrigin(raw string) bool {
	if len(raw) > 512 || !validText(raw, 512) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	return (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// ---- user ----

func userToWire(u core.User) idp.User {
	return idp.User{
		ID: u.ID, Username: u.Username, Email: u.Email, FirstName: u.FirstName, LastName: u.LastName,
		Enabled: u.Enabled, EmailVerified: u.EmailVerified, RequiredActions: u.PendingActions,
	}
}

// applyUser validates w and copies its profile fields onto base.
func applyUser(base core.User, w idp.User) (core.User, error) {
	if w.Username == "" || !validText(w.Username, 255) || strings.TrimSpace(w.Username) != w.Username {
		return base, bad("invalid username")
	}
	if !validText(w.Email, 320) || !validText(w.FirstName, 255) || !validText(w.LastName, 255) {
		return base, bad("invalid email or name")
	}
	if len(w.RequiredActions) > 16 {
		return base, bad("too many requiredActions")
	}
	for _, a := range w.RequiredActions {
		if !actionRE.MatchString(a) {
			return base, bad("invalid requiredActions entry")
		}
	}
	base.Username, base.Email, base.FirstName, base.LastName = w.Username, w.Email, w.FirstName, w.LastName
	base.Enabled, base.EmailVerified = w.Enabled, w.EmailVerified
	base.PendingActions = append([]string(nil), w.RequiredActions...)
	return base, nil
}

func roleToWire(r core.Role) idp.Role {
	return idp.Role{ID: r.ID, Name: r.Name, Description: r.Description}
}

func groupToWire(g core.Group) idp.Group { return idp.Group{ID: g.ID, Name: g.Name, Path: g.Path} }
