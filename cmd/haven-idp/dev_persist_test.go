// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

func TestPreparePersistCreatesPrivateKeyAndReusesIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	abs, k1, err := preparePersist(dir)
	if err != nil || k1 == "" {
		t.Fatalf("%v %q", err, k1)
	}
	fi, err := os.Stat(filepath.Join(abs, secretKeyFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	if di, _ := os.Stat(abs); di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", di.Mode().Perm())
	}
	_, k2, err := preparePersist(dir)
	if err != nil || k2 != k1 {
		t.Fatalf("key not stable across restarts: %v", err)
	}
}

func TestPreparePersistRefusesLooseModesAndBadKey(t *testing.T) {
	open := t.TempDir()
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := preparePersist(open); err == nil {
		t.Error("world-readable directory accepted")
	}
	dir := filepath.Join(t.TempDir(), "s")
	if _, _, err := preparePersist(dir); err != nil {
		t.Fatal(err)
	}
	kp := filepath.Join(dir, secretKeyFile)
	if err := os.Chmod(kp, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := preparePersist(dir); err == nil {
		t.Error("group/world-readable key file accepted")
	}
	if err := os.Chmod(kp, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := preparePersist(dir); err == nil {
		t.Error("garbage key accepted")
	}
}

func TestSyncDevPassword(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	h := password.New(password.TestParams)
	_ = st.CreateRealm(ctx, core.Realm{Name: "demo", Enabled: true})
	old, _ := h.Hash("old-password")
	_ = st.CreateUser(ctx, core.User{Realm: "demo", Username: "demo", Enabled: true, PasswordHash: old})
	_ = st.CreateUser(ctx, core.User{Realm: "demo", Username: "other", Enabled: true, PasswordHash: old})
	if err := syncDevPassword(ctx, st, h, "demo", "demo", "new-password"); err != nil {
		t.Fatal(err)
	}
	u, _ := st.GetUserByUsername(ctx, "demo", "demo")
	if ok, _ := h.Verify("new-password", u.PasswordHash); !ok {
		t.Error("test user password not synced")
	}
	o, _ := st.GetUserByUsername(ctx, "demo", "other")
	if o.PasswordHash != old {
		t.Error("another user's password was touched")
	}
	if err := syncDevPassword(ctx, st, h, "demo", "ghost", "x"); err != nil {
		t.Errorf("missing user should be a no-op: %v", err)
	}
}
