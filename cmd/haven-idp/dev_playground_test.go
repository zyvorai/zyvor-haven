// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDevAdminSecretReadsCurrentCreds(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if _, err := devAdminSecret(); err == nil {
		t.Fatal("missing creds file must be an error")
	}
	path, err := devCredsPath()
	if err != nil {
		t.Fatal(err)
	}
	c, err := loadDevCreds(path, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := devAdminSecret()
	if err != nil || got != c.AdminSecret || got == "" {
		t.Fatalf("got %q, %v; want %q", got, err, c.AdminSecret)
	}
	// --reset-creds rewrites the file; the next call must see the new secret.
	c2, err := loadDevCreds(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := devAdminSecret(); got != c2.AdminSecret || got == c.AdminSecret {
		t.Fatalf("stale secret after reset: %q", got)
	}
	if err := os.WriteFile(path, []byte(`{"password":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := devAdminSecret(); err == nil {
		t.Fatal("a file without an admin secret must be an error")
	}
}
