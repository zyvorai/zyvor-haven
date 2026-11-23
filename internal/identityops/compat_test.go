// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package identityops

import (
	"encoding/json"
	"reflect"
	"testing"
)

// legacySnapshotJSON is a literal on-disk snapshot. Its shape must keep
// loading: saved Time Machine history and `haven-audit access-review` read it.
const legacySnapshotJSON = `{
  "schemaVersion": 1,
  "id": "acme-20260101T000000.000000000Z-abc123def456",
  "realm": "acme",
  "createdAt": "2026-01-01T00:00:00Z",
  "reason": "nightly",
  "fingerprint": "abc123def456",
  "realmConfig": {"realm": "acme", "displayName": "Acme", "enabled": true, "registrationAllowed": true, "verifyEmail": true, "bruteForceProtected": true},
  "clients": [{"clientId": "grafana", "name": "Grafana", "enabled": true, "publicClient": true, "protocol": "openid-connect", "redirectUris": ["https://g/*"], "webOrigins": ["+"], "standardFlowEnabled": true, "attributes": {"pkce.code.challenge.method": "S256"}}],
  "users": [{"username": "alice", "email": "a@x.io", "enabled": true, "emailVerified": true, "requiredActions": ["UPDATE_PASSWORD"]}, {"username": "service-account-ci", "enabled": true}],
  "roles": [{"name": "admin", "description": "Admins"}],
  "groups": [{"name": "ops", "path": "/ops"}],
  "identityProviders": [{"alias": "entra", "displayName": "Entra", "providerId": "oidc", "enabled": true, "trustEmail": true, "config": {"issuer": "https://i"}}],
  "userAccess": [{"username": "alice", "realmRoles": ["admin"], "groups": ["/ops"]}],
  "partialExport": {"policy": "SKIP", "x": [1, 2]}
}`

func TestLegacySnapshotRoundTrip(t *testing.T) {
	var s RealmSnapshot
	if err := json.Unmarshal([]byte(legacySnapshotJSON), &s); err != nil {
		t.Fatal(err)
	}
	if s.Realm != "acme" || len(s.Clients) != 1 || len(s.Users) != 2 || len(s.Roles) != 1 ||
		len(s.Groups) != 1 || len(s.IdentityProviders) != 1 || len(s.UserAccess) != 1 || len(s.PartialExport) == 0 {
		t.Fatalf("snapshot did not load fully: %+v", s)
	}
	if s.Users[0].RequiredActions[0] != "UPDATE_PASSWORD" || s.IdentityProviders[0].ProviderID != "oidc" ||
		s.Clients[0].Attributes["pkce.code.challenge.method"] != "S256" || !s.RealmConfig.RegistrationAllowed {
		t.Fatalf("field mapping lost: %+v", s)
	}
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]any
	_ = json.Unmarshal([]byte(legacySnapshotJSON), &want)
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	// Re-encoding may add zero-valued non-omitempty keys, but every key in the
	// original must survive with an equal value.
	assertSubset(t, "", want, got)
	var again RealmSnapshot
	if err := json.Unmarshal(out, &again); err != nil {
		t.Fatal(err)
	}
	out2, _ := json.Marshal(again)
	if string(out) != string(out2) {
		t.Fatalf("encoding not stable across round trip:\n%s\n%s", out, out2)
	}
}

func assertSubset(t *testing.T, path string, want, got any) {
	t.Helper()
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("%s: not an object", path)
		}
		for k, v := range w {
			gv, ok := g[k]
			if !ok {
				t.Fatalf("%s.%s missing after round trip", path, k)
			}
			assertSubset(t, path+"."+k, v, gv)
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			t.Fatalf("%s: array mismatch", path)
		}
		for i := range w {
			assertSubset(t, path, w[i], g[i])
		}
	default:
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: %v != %v", path, want, got)
		}
	}
}
