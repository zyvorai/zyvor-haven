// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package federation

import (
	"encoding/json"
	"os"
	"testing"
)

var goldenCases = map[string]ConnectionRequest{
	"entra":        {Realm: "r", Template: "entra", Alias: "corp", Values: map[string]string{"tenantId": " tenant ", "clientId": "id", "clientSecret": "secret"}},
	"google":       {Realm: "r", Template: "google", Alias: "g", Values: map[string]string{"clientId": "id", "clientSecret": "secret"}},
	"google_scope": {Realm: "r", Template: "google", Alias: "g", DisplayName: "My G", Values: map[string]string{"clientId": "id", "clientSecret": "secret", "defaultScope": "openid"}},
	"github":       {Realm: "r", Template: "github", Alias: "gh", Values: map[string]string{"clientId": "id", "clientSecret": "secret"}},
	"oidc":         {Realm: "r", Template: "oidc", Alias: "o", Values: map[string]string{"issuer": "https://i", "authorizationUrl": "https://a", "tokenUrl": "https://t", "jwksUrl": "https://j", "userInfoUrl": "https://u", "clientId": "id", "clientSecret": "secret", "extra": "x", "blank": " "}},
	"saml":         {Realm: "r", Template: "saml", Alias: "s", Values: map[string]string{"singleSignOnServiceUrl": "https://sso", "singleLogoutServiceUrl": "https://slo", "entityId": "urn:t", "signingCertificate": "CERT"}},
}

func TestGolden(t *testing.T) {
	out := map[string]any{}
	for name, req := range goldenCases {
		p, err := BuildIdentityProvider(req)
		if err != nil {
			t.Fatal(name, err)
		}
		out[name] = p
	}
	got, _ := json.MarshalIndent(out, "", "  ")
	got = append(got, '\n')
	const path = "testdata/golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("golden mismatch:\n%s\nwant:\n%s", got, want)
	}
}
