// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
)

// The registries are what every feature plugs into, so prove each hook fires.
func TestFeatureRegistries(t *testing.T) {
	savedRoutes, savedDisc := featureRoutes, discoveryHooks
	defer func() { featureRoutes, discoveryHooks = savedRoutes, savedDisc; delete(grantHooks, "urn:test:grant") }()

	registerFeature(func(p *Provider, mux *http.ServeMux) {
		mux.HandleFunc("GET /realms/{realm}/x-feature", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hi")) })
	})
	registerDiscovery(func(_ *Provider, realm string, doc map[string]any) { doc["x_feature_realm"] = realm })
	registerGrant("urn:test:grant", func(_ *Provider, _ *http.Request, _ core.Realm, _ core.Client, _ bool) (map[string]any, *tokenErr) {
		return map[string]any{"access_token": "granted", "token_type": "Bearer"}, nil
	})

	e := newEnv(t, nil)
	if w := e.do(httptest.NewRequest("GET", "/realms/r/x-feature", nil)); w.Code != 200 || w.Body.String() != "hi" {
		t.Errorf("feature route: %d %q", w.Code, w.Body)
	}
	if w := e.do(httptest.NewRequest("GET", "/realms/r/.well-known/openid-configuration", nil)); !strings.Contains(w.Body.String(), `"x_feature_realm":"r"`) {
		t.Errorf("discovery hook not applied: %s", w.Body)
	}
	status, body, _ := e.tokenReq(url.Values{"grant_type": {"urn:test:grant"}, "client_id": {"app"}}, "", "")
	if status != 200 || body["access_token"] != "granted" {
		t.Errorf("grant hook: %d %v", status, body)
	}
	status, body, _ = e.tokenReq(url.Values{"grant_type": {"urn:test:unknown"}, "client_id": {"app"}}, "", "")
	if status != 400 || body["error"] != "unsupported_grant_type" {
		t.Errorf("unknown grant: %d %v", status, body)
	}
	defer func() {
		if recover() == nil {
			t.Error("registering a grant twice must panic")
		}
	}()
	registerGrant("urn:test:grant", nil)
}
