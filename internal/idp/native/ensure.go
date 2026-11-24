// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import (
	"context"
	"errors"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
)

// mergeURIs keeps existing redirect URIs, appends wanted ones, drops host
// wildcards and duplicates (same rules as the Keycloak implementation).
func mergeURIs(existing, wanted []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range append(append([]string{}, existing...), wanted...) {
		s = strings.TrimSpace(s)
		if s == "" || strings.Contains(s, "://*") {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// EnsureHavenConsoleClient creates or updates the public PKCE console client,
// merging redirect URIs into any existing set.
func (c *Client) EnsureHavenConsoleClient(ctx context.Context, realm string, consoleBases ...string) error {
	if realm == "" {
		realm = idp.BootstrapRealm()
	}
	clientID := idp.ConsoleClientID()
	want := idp.ConsoleRedirectURIs(consoleBases...)

	found, err := c.FindClientByClientID(ctx, realm, clientID)
	if err != nil {
		return err
	}
	existing := found
	if existing == nil || existing.ID == "" {
		return c.CreateClient(ctx, realm, idp.Client{
			ClientID:            clientID,
			Name:                "Haven Console",
			Enabled:             true,
			PublicClient:        true,
			Protocol:            "openid-connect",
			StandardFlowEnabled: true,
			RedirectURIs:        mergeURIs(nil, want),
			WebOrigins:          []string{"+"},
			Attributes:          map[string]string{"pkce.code.challenge.method": "S256"},
		})
	}
	cl, err := c.GetClient(ctx, realm, existing.ID)
	if err != nil {
		return err
	}
	cl.RedirectURIs = mergeURIs(cl.RedirectURIs, want)
	cl.WebOrigins = []string{"+"}
	cl.PublicClient = true
	cl.StandardFlowEnabled = true
	cl.DirectAccessGrantsEnabled = false
	cl.Enabled = true
	cl.Secret = ""
	attrs := make(map[string]string, len(cl.Attributes)+1)
	for k, v := range cl.Attributes {
		attrs[k] = v
	}
	attrs["pkce.code.challenge.method"] = "S256"
	cl.Attributes = attrs
	return c.UpdateClient(ctx, realm, existing.ID, *cl)
}

// BootstrapRealm creates the realm if missing (a concurrent 409 is ignored)
// and ensures the console client. A new realm also gets the "kubernetes"
// client, as the Keycloak implementation does.
func (c *Client) BootstrapRealm(ctx context.Context, name string) error {
	exists, err := c.RealmExists(ctx, name)
	if err != nil {
		return err
	}
	if !exists {
		err := c.CreateRealm(ctx, idp.Realm{Realm: name, DisplayName: "Private Cloud", Enabled: true})
		if err != nil && !errors.Is(err, idp.ErrConflict) {
			return err
		}
	}
	if err := c.EnsureHavenConsoleClient(ctx, name); err != nil {
		return err
	}
	if exists {
		return nil
	}
	err = c.CreateClient(ctx, name, idp.Client{
		ClientID:            "kubernetes",
		Name:                "Kubernetes API",
		Enabled:             true,
		Protocol:            "openid-connect",
		StandardFlowEnabled: true,
	})
	if err != nil && !errors.Is(err, idp.ErrConflict) {
		return err
	}
	return nil
}
