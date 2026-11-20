// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package identityops

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/keycloak"
)

func sampleSnapshot() RealmSnapshot {
	return RealmSnapshot{
		Realm:             "platform",
		RealmConfig:       keycloak.Realm{Realm: "platform", Enabled: true},
		Clients:           []keycloak.Client{{ClientID: "grafana", Enabled: true}, {ClientID: "kubernetes", Enabled: true}},
		Users:             []keycloak.User{{Username: "alice", Enabled: true}},
		Roles:             []keycloak.Role{{Name: "admin"}, {Name: "viewer"}},
		Groups:            []keycloak.Group{{Name: "engineering", Path: "/engineering"}},
		IdentityProviders: []keycloak.IdentityProvider{{Alias: "entra", ProviderID: "oidc", Enabled: true}},
	}
}

func TestFingerprintStableAcrossOrderAndIDs(t *testing.T) {
	a := sampleSnapshot()
	a.Clients[0].ID = "server-generated"
	b := sampleSnapshot()
	b.Clients[0], b.Clients[1] = b.Clients[1], b.Clients[0]

	fa, err := Fingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := Fingerprint(b)
	if err != nil {
		t.Fatal(err)
	}
	if fa != fb {
		t.Fatalf("expected stable fingerprints: %s != %s", fa, fb)
	}
}

func TestStoreSnapshotRoundTrip(t *testing.T) {
	s := NewStore(t.TempDir())
	snap := sampleSnapshot()
	snap.Reason = "before release"
	got, err := s.SaveSnapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.Fingerprint == "" {
		t.Fatal("id/fingerprint not generated")
	}

	loaded, err := s.GetSnapshot(got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Realm != "platform" || len(loaded.Clients) != 2 {
		t.Fatalf("bad snapshot: %#v", loaded)
	}

	list, err := s.ListSnapshots("platform")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != got.ID {
		t.Fatalf("unexpected list: %#v", list)
	}
}

func TestRotationRecord(t *testing.T) {
	s := NewStore(t.TempDir())
	now := time.Now().UTC().Truncate(time.Second)
	err := s.RecordRotation(RotationRecord{Realm: "platform", ClientID: "grafana", ClientUUID: "abc", LastRotatedAt: now, OverlapAvailable: true})
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := s.Rotation("platform", "abc")
	if !ok || !rec.OverlapAvailable || !rec.LastRotatedAt.Equal(now) {
		t.Fatalf("bad record: %#v", rec)
	}
	if err := s.ClearOverlap("platform", "abc"); err != nil {
		t.Fatal(err)
	}
	rec, _ = s.Rotation("platform", "abc")
	if rec.OverlapAvailable {
		t.Fatal("expected overlap cleared")
	}
}

func TestDiff(t *testing.T) {
	before := sampleSnapshot()
	before.ID = "snap-1"
	after := sampleSnapshot()
	after.Clients = append(after.Clients, keycloak.Client{ClientID: "argocd", Enabled: true})
	after.Users = nil
	before.UserAccess = []UserAccess{{Username: "alice", RealmRoles: []string{"admin"}}}
	after.UserAccess = []UserAccess{{Username: "alice", RealmRoles: []string{"viewer"}}}

	d, err := Diff(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Drifted {
		t.Fatal("expected drift")
	}
	if len(d.Clients.Added) != 1 || d.Clients.Added[0] != "argocd" {
		t.Fatalf("bad client diff: %#v", d.Clients)
	}
	if len(d.Users.Removed) != 1 || d.Users.Removed[0] != "alice" {
		t.Fatalf("bad user diff: %#v", d.Users)
	}
	if len(d.Access.Added) != 1 || len(d.Access.Removed) != 1 {
		t.Fatalf("bad access diff: %#v", d.Access)
	}
}

func TestSanitizePartialExportRemovesSecrets(t *testing.T) {
	raw := SanitizePartialExport([]byte(`{"realm":"platform","clients":[{"clientId":"grafana","secret":"do-not-store","attributes":{"client.secret.creation.time":"123"}}],"users":[{"username":"a","credentials":[{"value":"x"}]}]}`))
	text := string(raw)
	if strings.Contains(strings.ToLower(text), "secret") || strings.Contains(strings.ToLower(text), "credential") || strings.Contains(text, "do-not-store") {
		t.Fatalf("sensitive fields survived sanitization: %s", text)
	}
	if !strings.Contains(text, `"policy":"SKIP"`) {
		t.Fatalf("partial import policy missing: %s", text)
	}
}
