// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kcimport

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIdentityProviderConversion(t *testing.T) {
	res := conv(t, `{"realm":"r","identityProviders":[
	 {"alias":"Okta_Corp","displayName":"Okta","providerId":"oidc","enabled":true,"trustEmail":true,
	  "config":{"issuer":"https://corp.okta.com","clientId":"cid","clientSecret":"**********","defaultScope":"openid email"}},
	 {"alias":"google","providerId":"google","enabled":true,"config":{"clientId":"g","clientSecret":"SECRET-google","hostedDomain":"corp.example"}},
	 {"alias":"ms","providerId":"microsoft","config":{"clientId":"m","clientSecret":"SECRET-ms"}},
	 {"alias":"gh","providerId":"github","config":{"clientId":"x"}},
	 {"alias":"saml1","providerId":"saml","config":{}},
	 {"alias":"noissuer","providerId":"oidc","config":{"clientId":"x","authorizationUrl":"https://a.example/auth"}},
	 {"alias":"badissuer","providerId":"oidc","config":{"clientId":"x","issuer":"http://insecure.example"}}
	]}`)
	if len(res.IdentityProviders) != 3 {
		t.Fatalf("converted %d providers, want 3: %+v", len(res.IdentityProviders), res.IdentityProviders)
	}
	by := map[string]int{}
	for i, p := range res.IdentityProviders {
		by[p.Alias] = i
		if p.Enabled {
			t.Errorf("%s: converted providers must be disabled until the secret is set", p.Alias)
		}
		if _, ok := p.Config["clientSecret"]; ok {
			t.Errorf("%s: client secret carried over", p.Alias)
		}
	}
	o := res.IdentityProviders[by["okta-corp"]]
	if o.ProviderID != "oidc" || o.Config["issuer"] != "https://corp.okta.com" || o.Config["clientId"] != "cid" || o.Config["scopes"] != "openid email" || !o.TrustEmail || o.DisplayName != "Okta" {
		t.Fatalf("okta: %+v", o)
	}
	if g := res.IdentityProviders[by["google"]]; g.ProviderID != "google" || g.Config["hostedDomain"] != "corp.example" {
		t.Fatalf("google: %+v", g)
	}
	if res.Report.NotMigrated["identity_providers"] != 4 {
		t.Fatalf("not migrated: %v", res.Report.NotMigrated)
	}
	for _, code := range []string{"identity_provider.secret_required", "identity_provider.dropped", "identity_provider.alias_changed", "identity_provider.trust_email"} {
		if res.Report.WarningCounts[code] == 0 {
			t.Errorf("no %s warning: %v", code, res.Report.WarningCounts)
		}
	}
	// No secret anywhere in the result or the report.
	all, _ := json.Marshal(res)
	rep, _ := json.Marshal(res.Report)
	for _, s := range []string{string(all), string(rep)} {
		if strings.Contains(s, "SECRET-") || strings.Contains(s, "**********") {
			t.Fatalf("a client secret leaked into the conversion: %.200s", s)
		}
	}
}
