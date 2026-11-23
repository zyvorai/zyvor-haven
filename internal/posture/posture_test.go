// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package posture

import (
	"testing"

	"github.com/zyvorai/haven/internal/idmodel"
	"github.com/zyvorai/haven/internal/keycloak"
)

func TestEvaluateDetectsOIDCRisks(t *testing.T) {
	realms := []keycloak.Realm{{
		Realm:               "prod",
		Enabled:             true,
		RegistrationAllowed: true,
		VerifyEmail:         false,
		BruteForceProtected: false,
	}}
	clients := map[string][]keycloak.Client{
		"prod": {{
			ClientID:                  "web",
			Enabled:                   true,
			PublicClient:              true,
			Protocol:                  "openid-connect",
			RedirectURIs:              []string{"http://app.example.com/callback", "https://app.example.com/*"},
			WebOrigins:                []string{"*"},
			StandardFlowEnabled:       true,
			DirectAccessGrantsEnabled: true,
			ImplicitFlowEnabled:       true,
			ServiceAccountsEnabled:    true,
			Attributes:                map[string]string{},
		}},
	}

	r := evalKC(realms, clients, Options{})
	if r.Score >= 70 {
		t.Fatalf("expected poor score, got %d", r.Score)
	}
	want := map[string]bool{
		"HAVEN001": false, "HAVEN002": false, "HAVEN003": false,
		"HAVEN004": false, "HAVEN005": false, "HAVEN006": false,
		"HAVEN007": false, "HAVEN011": false, "HAVEN012": false,
	}
	for _, f := range r.Findings {
		if _, ok := want[f.RuleID]; ok {
			want[f.RuleID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("expected finding %s", id)
		}
	}
}

func TestSafePublicClientScoresClean(t *testing.T) {
	realms := []keycloak.Realm{{Realm: "prod", Enabled: true, VerifyEmail: true, BruteForceProtected: true}}
	clients := map[string][]keycloak.Client{
		"prod": {{
			ClientID:            "web",
			Enabled:             true,
			PublicClient:        true,
			Protocol:            "openid-connect",
			RedirectURIs:        []string{"https://app.example.com/callback"},
			WebOrigins:          []string{"https://app.example.com"},
			StandardFlowEnabled: true,
			Attributes:          map[string]string{"pkce.code.challenge.method": "S256"},
		}},
	}
	r := evalKC(realms, clients, Options{})
	if r.Score != 100 || len(r.Findings) != 0 {
		t.Fatalf("expected clean posture, score=%d findings=%v", r.Score, r.Findings)
	}
}

func TestLoopbackHTTPRedirectAllowed(t *testing.T) {
	c := keycloak.Client{
		ClientID:            "native",
		Enabled:             true,
		PublicClient:        true,
		Protocol:            "openid-connect",
		StandardFlowEnabled: true,
		RedirectURIs:        []string{"http://127.0.0.1:18080/callback", "http://localhost:5173/callback"},
		Attributes:          map[string]string{"pkce.code.challenge.method": "S256"},
	}
	findings := evaluateClient("dev", idmodel.FromClient(c))
	for _, f := range findings {
		if f.RuleID == "HAVEN002" {
			t.Fatalf("loopback redirect should not be flagged: %+v", f)
		}
	}
}

func TestFingerprintStableAcrossOrdering(t *testing.T) {
	r := keycloak.Realm{Realm: "prod", Enabled: true, BruteForceProtected: true}
	one := keycloak.Client{ClientID: "a", Enabled: true, RedirectURIs: []string{"https://x/b", "https://x/a"}}
	two := keycloak.Client{ClientID: "b", Enabled: true}
	a := evalKC([]keycloak.Realm{r}, map[string][]keycloak.Client{"prod": {one, two}}, Options{})
	one.RedirectURIs = []string{"https://x/a", "https://x/b"}
	b := evalKC([]keycloak.Realm{r}, map[string][]keycloak.Client{"prod": {two, one}}, Options{})
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("fingerprint must be order-independent: %s != %s", a.Fingerprint, b.Fingerprint)
	}
}

func TestBaselineDrift(t *testing.T) {
	realms := []keycloak.Realm{{Realm: "prod", Enabled: true, BruteForceProtected: true}}
	base := evalKC(realms, map[string][]keycloak.Client{"prod": nil}, Options{})
	changed := evalKC(realms, map[string][]keycloak.Client{"prod": {{ClientID: "new-client", Enabled: true}}}, Options{Baseline: base.Fingerprint})
	if !changed.Drifted {
		t.Fatal("expected drift after client inventory changed")
	}
}

func TestSARIFMapsSeverities(t *testing.T) {
	r := Report{Findings: []Finding{{RuleID: "HAVEN001", Severity: SeverityCritical, Realm: "prod", ClientID: "web", Title: "Wildcard redirect URI", Evidence: "*"}}}
	s := ToSARIF(r, "identity/realm.json")
	if len(s.Runs) != 1 || len(s.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF shape: %+v", s)
	}
	if got := s.Runs[0].Results[0].Level; got != "error" {
		t.Fatalf("expected error level, got %q", got)
	}
	locations := s.Runs[0].Results[0].Locations
	if len(locations) != 1 || locations[0].PhysicalLocation.ArtifactLocation.URI != "identity/realm.json" {
		t.Fatalf("expected repository-relative SARIF location, got %+v", locations)
	}
}
