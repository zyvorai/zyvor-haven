// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

func fill(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.CreateRealm(ctx, core.Realm{Name: "demo", Enabled: true}))
	must(s.CreateUser(ctx, core.User{ID: "u1", Realm: "demo", Username: "alice", Email: "a@example.org", Enabled: true, PasswordHash: "$argon2id$secret-hash", Roles: []string{"admin"}}))
	must(s.CreateClient(ctx, core.Client{Realm: "demo", ClientID: "app", Enabled: true, RedirectURIs: []string{"http://localhost/cb"}, SecretHash: "sha"}))
	must(s.CreateRole(ctx, core.Role{Realm: "demo", Name: "admin"}))
	must(s.CreateGroup(ctx, core.Group{Realm: "demo", Name: "g", Path: "/g"}))
	must(s.PutSigningKey(ctx, core.SigningKey{KID: "k1", Realm: "demo", Alg: "ES256", PrivatePEM: []byte("PRIVATE"), PublicJWK: []byte("{}"), Active: true}))
	must(s.PutRefreshToken(ctx, core.RefreshToken{TokenHash: "rt", FamilyID: "f", Realm: "demo", ClientID: "app", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)}))
	must(s.PutRefreshToken(ctx, core.RefreshToken{TokenHash: "old", FamilyID: "f2", Realm: "demo", ClientID: "app", UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour)}))
	must(s.PutSession(ctx, core.Session{ID: "s1", CookieHash: "ch", Realm: "demo", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour), IdleExpires: time.Now().Add(time.Hour)}))
	must(s.AppendEvent(ctx, core.Event{Realm: "demo", Type: "LOGIN", UserID: "u1", Time: time.Now()}))
	must(s.PutAuthCode(ctx, core.AuthCode{CodeHash: "code", Realm: "demo", ClientID: "app", ExpiresAt: time.Now().Add(time.Minute)}))
	must(s.PutTOTP(ctx, core.TOTPCredential{Realm: "demo", UserID: "u1", SealedSeed: "sealed"}))
}

func TestSnapshotRoundTrip(t *testing.T) {
	a := New()
	fill(t, a)
	b1, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Restore(b1); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u, err := c.GetUserByUsername(ctx, "demo", "ALICE")
	if err != nil || u.PasswordHash != "$argon2id$secret-hash" || len(u.Roles) != 1 {
		t.Fatalf("user: %+v %v", u, err)
	}
	if ks, _ := c.ListSigningKeys(ctx, "demo"); len(ks) != 1 || string(ks[0].PrivatePEM) != "PRIVATE" {
		t.Fatalf("keys: %+v", ks)
	}
	if _, err := c.GetSessionByCookie(ctx, "demo", "ch"); err != nil {
		t.Errorf("session lost: %v", err)
	}
	if _, err := c.GetRefreshToken(ctx, "rt"); err != nil {
		t.Errorf("refresh lost: %v", err)
	}
	if _, err := c.GetRefreshToken(ctx, "old"); err == nil {
		t.Error("expired refresh token survived the restore")
	}
	if _, err := c.ConsumeAuthCode(ctx, "code"); err == nil {
		t.Error("authorization codes must not be persisted")
	}
	if cred, err := c.GetTOTP(ctx, "demo", "u1"); err != nil || cred.SealedSeed != "sealed" {
		t.Errorf("totp: %+v %v", cred, err)
	}
	if evs, _ := c.ListEvents(ctx, "demo", 10); len(evs) != 1 {
		t.Errorf("events: %d", len(evs))
	}
	// Writes keep working after a restore and snapshot again identically.
	if err := c.CreateUser(ctx, core.User{Realm: "demo", Username: "bob", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateUser(ctx, core.User{Realm: "demo", Username: "alice", Enabled: true}); err == nil {
		t.Error("username uniqueness lost after restore")
	}
}

func TestSnapshotIsDeterministic(t *testing.T) {
	a := New()
	fill(t, a)
	x, _ := a.Snapshot()
	y, _ := a.Snapshot()
	if !bytes.Equal(x, y) {
		t.Fatal("two snapshots of an unchanged store differ (the saver would rewrite the file every tick)")
	}
}

// Guards the claim "everything durable is in the snapshot": adding a field to
// Store must be a conscious decision (persist it or mark it ephemeral).
func TestEveryStoreFieldIsAccountedFor(t *testing.T) {
	persisted := map[string]bool{"realms": true, "users": true, "clients": true, "roles": true, "groups": true,
		"keys": true, "refresh": true, "actions": true, "sess": true, "events": true,
		"dcr": true, "pk": true} // dcr, pk: via hooks
	ephemeral := map[string]bool{"mu": true, "codes": true, "rates": true, "dev": true}
	rt := reflect.TypeOf(Store{})
	for i := 0; i < rt.NumField(); i++ {
		n := rt.Field(i).Name
		if !persisted[n] && !ephemeral[n] {
			t.Errorf("Store.%s is neither persisted nor declared ephemeral in persist.go", n)
		}
	}
}

func TestPersisterWritesPrivateFilesAtomically(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st, p, err := OpenPersistent(dir)
	if err != nil {
		t.Fatal(err)
	}
	fill(t, st)
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, StateFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", di.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("leftover files after save: %v", ents)
	}
	// Unchanged store: no rewrite.
	before, _ := os.Stat(filepath.Join(dir, StateFile))
	time.Sleep(10 * time.Millisecond)
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(filepath.Join(dir, StateFile))
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("unchanged store was rewritten")
	}
	// Second process generation sees the data.
	st2, _, err := OpenPersistent(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.GetUserByUsername(context.Background(), "demo", "alice"); err != nil {
		t.Fatalf("data did not survive: %v", err)
	}
}

func TestSaveTightensLooseExistingFileMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, StateFile)
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestOpenPersistentRefusesOpenDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenPersistent(dir); !errors.Is(err, ErrDirNotPrivate) {
		t.Fatalf("want ErrDirNotPrivate, got %v", err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o755 {
		t.Error("we changed the permissions of a directory we did not create")
	}
}

func TestOpenPersistentNeverOverwritesCorruptSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, StateFile)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := OpenPersistent(dir)
	if err == nil || !strings.Contains(err.Error(), "move it aside") {
		t.Fatalf("want a clear error, got %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "{not json" {
		t.Error("corrupt snapshot was modified")
	}
	// A snapshot from a different format version is also refused.
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenPersistent(dir); err == nil {
		t.Error("unsupported version accepted")
	}
}

func TestRunSavesOnShutdown(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	st, p, err := OpenPersistent(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx, time.Hour, nil); close(done) }()
	fill(t, st)
	cancel()
	<-done
	if _, err := os.Stat(filepath.Join(dir, StateFile)); err != nil {
		t.Fatalf("no final save: %v", err)
	}
}
