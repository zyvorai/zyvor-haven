// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package posture

import (
	"encoding/json"
	"testing"

	"github.com/zyvorai/haven/internal/keycloak"
)

func sp(s string) *string { return &s }
func ip(i int) *int       { return &i }
func bp(b bool) *bool     { return &b }

func ruleIDs(r Report) map[string]bool {
	out := map[string]bool{}
	for _, f := range r.Findings {
		out[f.RuleID] = true
	}
	return out
}

func TestPolicyMinLength(t *testing.T) {
	cases := map[string]int{
		"length(12)":                         12,
		"length(8) and digits(1)":            8,
		"digits(1) and length( 15 )":         15,
		"length(abc)":                        0,
		"length(-4)":                         0,
		"length(99999999999999999999999999)": 0,
		"length(12":                          0,
		"notlength(12)":                      0,
		"":                                   0,
	}
	for in, want := range cases {
		if got := policyMinLength(in); got != want {
			t.Errorf("policyMinLength(%q)=%d want %d", in, got, want)
		}
	}
}

func TestHardeningRules(t *testing.T) {
	public := []keycloak.Client{{ClientID: "spa", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
		RedirectURIs: []string{"https://a.example/cb"}, Attributes: map[string]string{"pkce.code.challenge.method": "S256"}}}
	cases := []struct {
		name    string
		h       *keycloak.RealmHardening
		clients []keycloak.Client
		want    []string
		absent  []string
	}{
		{"nil hardening is silent", nil, public, nil, []string{"HAVEN014", "HAVEN015", "HAVEN019", "HAVEN021"}},
		{"ssl none", &keycloak.RealmHardening{SSLRequired: sp("none")}, nil, []string{"HAVEN014"}, nil},
		{"ssl external ok", &keycloak.RealmHardening{SSLRequired: sp("EXTERNAL")}, nil, nil, []string{"HAVEN014"}},
		{"empty policy", &keycloak.RealmHardening{PasswordPolicy: sp("  ")}, nil, []string{"HAVEN015"}, []string{"HAVEN016"}},
		{"short policy", &keycloak.RealmHardening{PasswordPolicy: sp("length(8) and digits(1)")}, nil, []string{"HAVEN016"}, []string{"HAVEN015"}},
		{"policy without length", &keycloak.RealmHardening{PasswordPolicy: sp("digits(1)")}, nil, []string{"HAVEN016"}, nil},
		{"strong policy", &keycloak.RealmHardening{PasswordPolicy: sp("length(14)")}, nil, nil, []string{"HAVEN015", "HAVEN016"}},
		{"long token", &keycloak.RealmHardening{AccessTokenLifespan: ip(7200)}, nil, []string{"HAVEN017"}, nil},
		{"boundary token", &keycloak.RealmHardening{AccessTokenLifespan: ip(3600)}, nil, nil, []string{"HAVEN017"}},
		{"long idle", &keycloak.RealmHardening{SSOSessionIdleTimeout: ip(86401)}, nil, []string{"HAVEN018"}, nil},
		{"events off", &keycloak.RealmHardening{EventsEnabled: bp(false), AdminEventsEnabled: bp(false)}, nil, []string{"HAVEN019", "HAVEN020"}, nil},
		{"events on", &keycloak.RealmHardening{EventsEnabled: bp(true), AdminEventsEnabled: bp(true)}, nil, nil, []string{"HAVEN019", "HAVEN020"}},
		{"no rotation with public client", &keycloak.RealmHardening{RevokeRefreshToken: bp(false)}, public, []string{"HAVEN021"}, nil},
		{"no rotation without public client", &keycloak.RealmHardening{RevokeRefreshToken: bp(false)}, nil, nil, []string{"HAVEN021"}},
		{"negative numbers are not findings", &keycloak.RealmHardening{AccessTokenLifespan: ip(-5), SSOSessionIdleTimeout: ip(-1)}, nil, nil, []string{"HAVEN017", "HAVEN018"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			realm := keycloak.Realm{Realm: "r", Enabled: true, VerifyEmail: true, BruteForceProtected: true, RealmHardening: tc.h}
			got := ruleIDs(evalKC([]keycloak.Realm{realm}, map[string][]keycloak.Client{"r": tc.clients}, Options{}))
			for _, id := range tc.want {
				if !got[id] {
					t.Errorf("missing %s", id)
				}
			}
			for _, id := range tc.absent {
				if got[id] {
					t.Errorf("unexpected %s", id)
				}
			}
		})
	}
}

func TestHardeningIgnoredForDisabledRealm(t *testing.T) {
	realm := keycloak.Realm{Realm: "r", Enabled: false, RealmHardening: &keycloak.RealmHardening{SSLRequired: sp("none")}}
	if ids := ruleIDs(evalKC([]keycloak.Realm{realm}, nil, Options{})); ids["HAVEN014"] {
		t.Fatal("disabled realm should not be evaluated for hardening")
	}
}

func TestHardeningDoesNotChangeFingerprint(t *testing.T) {
	base := keycloak.Realm{Realm: "r", Enabled: true, VerifyEmail: true, BruteForceProtected: true}
	hard := base
	hard.RealmHardening = &keycloak.RealmHardening{SSLRequired: sp("none"), EventsEnabled: bp(false)}
	a := evalKC([]keycloak.Realm{base}, nil, Options{})
	b := evalKC([]keycloak.Realm{hard}, nil, Options{})
	if a.Fingerprint != b.Fingerprint {
		t.Fatal("hardening settings must not alter the baseline fingerprint")
	}
}

func TestHardeningDecodesFromRealmJSON(t *testing.T) {
	var r keycloak.Realm
	raw := `{"realm":"x","enabled":true,"sslRequired":"none","accessTokenLifespan":99999,"passwordPolicy":"","eventsEnabled":false,"unknown":{"a":1}}`
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(evalKC([]keycloak.Realm{r}, nil, Options{}))
	for _, id := range []string{"HAVEN014", "HAVEN015", "HAVEN017", "HAVEN019"} {
		if !ids[id] {
			t.Errorf("missing %s", id)
		}
	}
}
