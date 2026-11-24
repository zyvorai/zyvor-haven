// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"net/http"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Feature registry. A feature lives in its own files and adds itself from an
// init() with registerFeature (routes) and registerDiscovery (metadata), so
// features never edit New() or discovery() and do not collide in merges.
var (
	featureRoutes  []func(p *Provider, mux *http.ServeMux)
	discoveryHooks []func(p *Provider, realm string, doc map[string]any)
)

// grantHooks adds token-endpoint grant types. The hook runs after client
// authentication; it returns the token response or an OAuth error (oerr).
var grantHooks = map[string]func(p *Provider, r *http.Request, rl core.Realm, cl core.Client, confidential bool) (map[string]any, *tokenErr){}

// registerGrant adds a grant_type (its full URN or name) to the token endpoint.
// Registering the same grant twice is a programming error.
func registerGrant(grantType string, h func(p *Provider, r *http.Request, rl core.Realm, cl core.Client, confidential bool) (map[string]any, *tokenErr)) {
	if _, dup := grantHooks[grantType]; dup {
		panic("oidc: grant registered twice: " + grantType)
	}
	grantHooks[grantType] = h
}

// registerFeature adds routes to the provider's mux. Patterns follow the
// existing "METHOD /realms/{realm}/..." convention.
func registerFeature(f func(p *Provider, mux *http.ServeMux)) {
	featureRoutes = append(featureRoutes, f)
}

// registerDiscovery lets a feature add fields to the discovery document.
func registerDiscovery(f func(p *Provider, realm string, doc map[string]any)) {
	discoveryHooks = append(discoveryHooks, f)
}
