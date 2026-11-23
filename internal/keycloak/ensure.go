// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// BootstrapRealm is the realm used for Haven console OIDC (default platform).
func BootstrapRealm() string {
	if v := strings.TrimSpace(os.Getenv("HAVEN_BOOTSTRAP_REALM")); v != "" {
		return v
	}
	return "platform"
}

func ConsoleClientID() string {
	if v := strings.TrimSpace(os.Getenv("HAVEN_OIDC_CLIENT_ID")); v != "" {
		return v
	}
	return "haven-console"
}

// ConsoleRedirectURIs builds Keycloak 26–safe redirect URIs for console public bases.
// Path wildcards (http://host:port/*) are allowed; host wildcards (http://*/*) are not.
func ConsoleRedirectURIs(consoleBases ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	defaults := []string{
		"http://localhost:30742",
		"http://localhost:8080",
		"http://127.0.0.1:30742",
		"http://127.0.0.1:8080",
	}
	bases := append([]string{}, consoleBases...)
	bases = append(bases, defaults...)
	for _, b := range bases {
		b = strings.TrimRight(strings.TrimSpace(b), "/")
		if b == "" {
			continue
		}
		add(b + "/*")
		add(b + "/api/v1/auth/oidc/callback")
	}
	return out
}

func mergeStringList(existing []any, extras []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		// Drop Keycloak 26–invalid host wildcards that break OIDC.
		if strings.Contains(s, "://*") {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, v := range existing {
		if s, ok := v.(string); ok {
			add(s)
		}
	}
	for _, s := range extras {
		add(s)
	}
	return out
}

func (c *AdminClient) FindClientByClientID(ctx context.Context, realm, clientID string) (*Client, error) {
	var clients []Client
	path := "/admin/realms/" + url.PathEscape(realm) + "/clients?clientId=" + url.QueryEscape(clientID)
	_, _, err := c.do(ctx, http.MethodGet, path, nil, &clients)
	if err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, nil
	}
	return &clients[0], nil
}

func (c *AdminClient) getClientRepresentation(ctx context.Context, realm, id string) (map[string]any, error) {
	var raw map[string]any
	code, body, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/clients/"+url.PathEscape(id), nil, &raw)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("get client HTTP %d: %s", code, string(body))
	}
	return raw, nil
}

// EnsureHavenConsoleClient creates or updates the public PKCE haven-console client
// so OIDC redirect_uri matches the live console origin (Keycloak 26+).
func (c *AdminClient) EnsureHavenConsoleClient(ctx context.Context, realm string, consoleBases ...string) error {
	if realm == "" {
		realm = BootstrapRealm()
	}
	clientID := ConsoleClientID()
	wantURIs := ConsoleRedirectURIs(consoleBases...)

	existing, err := c.FindClientByClientID(ctx, realm, clientID)
	if err != nil {
		return err
	}
	if existing == nil || existing.ID == "" {
		cl := Client{
			ClientID:                  clientID,
			Name:                      "Haven Console",
			Enabled:                   true,
			PublicClient:              true,
			Protocol:                  "openid-connect",
			StandardFlowEnabled:       true,
			DirectAccessGrantsEnabled: false,
			RedirectURIs:              wantURIs,
			WebOrigins:                []string{"+"},
		}
		if err := c.CreateClient(ctx, realm, cl); err != nil {
			return wrapStatus("create "+clientID, err)
		}
		return nil
	}

	rep, err := c.getClientRepresentation(ctx, realm, existing.ID)
	if err != nil {
		return err
	}
	var prev []any
	if v, ok := rep["redirectUris"].([]any); ok {
		prev = v
	}
	rep["redirectUris"] = mergeStringList(prev, wantURIs)
	rep["webOrigins"] = []string{"+"}
	rep["publicClient"] = true
	rep["standardFlowEnabled"] = true
	rep["directAccessGrantsEnabled"] = false
	rep["enabled"] = true
	attrs, _ := rep["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["pkce.code.challenge.method"] = "S256"
	rep["attributes"] = attrs

	code, raw, err := c.do(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(realm)+"/clients/"+url.PathEscape(existing.ID), rep, nil)
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("update %s: %s", clientID, string(raw))
	}
	return nil
}

// EnsureUserPassword creates a realm user (if missing) and sets a non-temporary password.
func (c *AdminClient) EnsureUserPassword(ctx context.Context, realm, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return fmt.Errorf("username and password required")
	}
	users, err := c.ListUsers(ctx, realm, username)
	if err != nil {
		return err
	}
	var id string
	for _, u := range users {
		if u.Username == username {
			id = u.ID
			break
		}
	}
	if id == "" {
		if err := c.CreateUser(ctx, realm, User{
			Username:      username,
			Enabled:       true,
			EmailVerified: true,
		}); err != nil {
			return wrapStatus("create user", err)
		}
		users, err = c.ListUsers(ctx, realm, username)
		if err != nil {
			return err
		}
		for _, u := range users {
			if u.Username == username {
				id = u.ID
				break
			}
		}
		if id == "" {
			return fmt.Errorf("user %q created but not found", username)
		}
	}
	return wrapStatus("reset password", c.ResetPassword(ctx, realm, id, PasswordReset{
		Type:      "password",
		Value:     password,
		Temporary: false,
	}))
}
