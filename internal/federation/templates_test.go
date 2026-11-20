// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package federation

import "testing"

func TestBuildEntra(t *testing.T) {
	p, err := BuildIdentityProvider(ConnectionRequest{
		Realm: "platform", Template: "entra", Alias: "corp",
		Values: map[string]string{"tenantId": "tenant", "clientId": "id", "clientSecret": "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.ProviderID != "oidc" || p.Config["issuer"] != "https://login.microsoftonline.com/tenant/v2.0" {
		t.Fatalf("unexpected provider: %#v", p)
	}
	if p.Config["tenantId"] != "" {
		t.Fatal("tenantId should not be sent to Keycloak config")
	}
}

func TestBuildSAMLHardensSignature(t *testing.T) {
	p, err := BuildIdentityProvider(ConnectionRequest{
		Realm: "platform", Template: "saml", Alias: "legacy",
		Values: map[string]string{"singleSignOnServiceUrl": "https://idp.example/sso", "entityId": "urn:test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Config["validateSignature"] != "true" || p.Config["wantAuthnRequestsSigned"] != "true" {
		t.Fatalf("SAML hardening missing: %#v", p.Config)
	}
}

func TestValidation(t *testing.T) {
	_, err := BuildIdentityProvider(ConnectionRequest{Realm: "platform", Template: "google", Alias: "google", Values: map[string]string{"clientId": "id"}})
	if err == nil {
		t.Fatal("expected missing secret error")
	}
}
