// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package posture

import (
	"github.com/zyvorai/haven/internal/idp"
	"testing"

	"github.com/zyvorai/haven/internal/idmodel"
)

// TestGoldenFingerprints pins fingerprints so refactors cannot silently
// invalidate stored baselines.
func TestGoldenFingerprints(t *testing.T) {
	realms := []idp.Realm{
		{Realm: "prod", Enabled: true, RegistrationAllowed: true, VerifyEmail: false, BruteForceProtected: true,
			RealmHardening: &idp.RealmHardening{SSLRequired: sp("none"), PasswordPolicy: sp("length(8)"),
				AccessTokenLifespan: ip(7200), SSOSessionIdleTimeout: ip(90000), EventsEnabled: bp(false),
				AdminEventsEnabled: bp(false), RevokeRefreshToken: bp(false)}},
		{Realm: "dev", Enabled: true},
		{Realm: "master", Enabled: true, BruteForceProtected: false},
	}
	clients := map[string][]idp.Client{
		"prod": {
			{ClientID: "account", Enabled: true, PublicClient: true},
			{ClientID: "spa", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
				RedirectURIs: []string{"https://b/cb", "https://a/cb"}, WebOrigins: []string{"https://b", "*"}},
			{ClientID: "legacy", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
				DirectAccessGrantsEnabled: true, ServiceAccountsEnabled: true, ImplicitFlowEnabled: true,
				RedirectURIs: []string{"http://example.com/*"},
				Attributes:   map[string]string{"pkceCodeChallengeMethod": " s256 ", "other": "x"}},
			{ClientID: "api", Enabled: false, BearerOnly: true, StandardFlowEnabled: true,
				Attributes: map[string]string{"pkce.code.challenge.method": "plain"}},
		},
		"dev": {
			{ClientID: "svc", Enabled: true, DirectAccessGrantsEnabled: true, Protocol: "openid-connect"},
			{ClientID: "saml", Enabled: true, Protocol: "saml"},
		},
	}
	r := evalWire(realms, clients, Options{})
	got := map[string]string{"report": r.Fingerprint}
	for _, rr := range r.Realms {
		got[rr.Realm] = rr.Fingerprint
	}
	want := map[string]string{
		"dev":    "sha256:5fc55cdc99a735a3d5894b9659ffceb60536f9ef515d91edd7c84a46e0e4ca28",
		"master": "sha256:230b8b88cc8cbecb7eba9b49500c6cd15598f987c6930ae13886584dd2dd51c3",
		"prod":   "sha256:bc425212b6cbfad73d41557592f1463ffcc62b0c9ddf09bf473265c93d21cff3",
		"report": "sha256:bcacf88bbe7761848a966989f45ba4b7820c0301c8b47e02a6134f436278c68e",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %s want %s", k, got[k], v)
		}
	}
	if len(want) == 0 {
		t.Fatalf("pin these: %#v", got)
	}
}

// evalWire maps wire types into idmodel and evaluates them.
func evalWire(realms []idp.Realm, clients map[string][]idp.Client, opts Options) Report {
	mc := map[string][]idmodel.Client{}
	for k, v := range clients {
		mc[k] = idmodel.FromClients(v)
	}
	return Evaluate(idmodel.FromRealms(realms), mc, opts)
}
