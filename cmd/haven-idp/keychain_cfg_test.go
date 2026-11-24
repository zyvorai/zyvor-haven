// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/keychain"
)

type fakeKC struct {
	off   bool
	items map[string]string // service -> secret
	err   error
	asked []string
}

func (k *fakeKC) Available() bool { return !k.off }
func (k *fakeKC) Get(_ context.Context, svc, acct string) (string, error) {
	k.asked = append(k.asked, svc+"/"+acct)
	if k.err != nil {
		return "", k.err
	}
	if v, ok := k.items[svc]; ok && acct == "haven-idp" {
		return v, nil
	}
	return "", keychain.ErrNotFound
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestKeychainSecretKeyWinsAndFallsBack(t *testing.T) {
	kc := &fakeKC{items: map[string]string{"haven-idp.secret-key": " FROM-KEYCHAIN \n"}}
	var warn bytes.Buffer
	cfg := Config{SecretKey: "FROM-ENV"}
	if err := applyKeychain(context.Background(), &cfg, env(map[string]string{envSecretKeyKeychain: "1"}), kc, &warn); err != nil {
		t.Fatal(err)
	}
	if cfg.SecretKey != "FROM-KEYCHAIN" || warn.Len() != 0 {
		t.Errorf("key = %q, warn = %q", cfg.SecretKey, warn.String())
	}

	// Not configured: the Keychain is never consulted.
	kc.asked = nil
	cfg = Config{SecretKey: "FROM-ENV"}
	_ = applyKeychain(context.Background(), &cfg, env(nil), kc, &warn)
	if cfg.SecretKey != "FROM-ENV" || len(kc.asked) != 0 {
		t.Errorf("unconfigured use of the Keychain: %q %v", cfg.SecretKey, kc.asked)
	}

	for name, k := range map[string]*fakeKC{
		"missing":     {items: map[string]string{}},
		"unavailable": {off: true},
		"error":       {err: errors.New("keychain: security exited with status 36")},
		"empty":       {items: map[string]string{"custom-item": "  "}},
	} {
		warn.Reset()
		cfg = Config{SecretKey: "FROM-ENV"}
		if err := applyKeychain(context.Background(), &cfg, env(map[string]string{envSecretKeyKeychain: "custom-item"}), k, &warn); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.SecretKey != "FROM-ENV" {
			t.Errorf("%s: did not fall back, key = %q", name, cfg.SecretKey)
		}
		if !strings.Contains(warn.String(), "warning") {
			t.Errorf("%s: silent fallback", name)
		}
	}
}

func TestKeychainNeverPrintsSecrets(t *testing.T) {
	kc := &fakeKC{items: map[string]string{"haven-idp.secret-key": "SEKRIT-KEY", "haven-idp.db-password": "SEKRIT-PW"}}
	var warn bytes.Buffer
	cfg := Config{DSN: "postgres://haven@db/haven"}
	e := env(map[string]string{envSecretKeyKeychain: "true", envDBPasswordKeychain: "1"})
	if err := applyKeychain(context.Background(), &cfg, e, kc, &warn); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(warn.String(), "SEKRIT") {
		t.Errorf("secret in output: %s", warn.String())
	}
	if cfg.SecretKey != "SEKRIT-KEY" || cfg.DSN != "postgres://haven:SEKRIT-PW@db/haven" {
		t.Errorf("cfg = %q / %q", cfg.SecretKey, cfg.DSN)
	}
	// Errors about a broken DSN must not echo it (it may contain a password).
	cfg = Config{DSN: "postgres://u:hunter2@[bad/db"}
	err := applyKeychain(context.Background(), &cfg, env(map[string]string{envDBPasswordKeychain: "1"}), kc, &warn)
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v", err)
	}
	cfg = Config{}
	if err := applyKeychain(context.Background(), &cfg, env(map[string]string{envDBPasswordKeychain: "1"}), kc, &warn); err == nil {
		t.Error("db password without a DSN must be an error")
	}
}

func TestDSNWithPassword(t *testing.T) {
	cases := []struct{ in, pw, want string }{
		{"postgres://haven@db:5432/haven?sslmode=require", "p@ss/w:rd", "postgres://haven:p%40ss%2Fw%3Ard@db:5432/haven?sslmode=require"},
		{"postgresql://db/haven", "pw", "postgresql://:pw@db/haven"},
		{"postgres://haven:explicit@db/haven", "pw", "postgres://haven:explicit@db/haven"}, // explicit wins
		{"host=db user=haven dbname=haven", `it's a\b`, `host=db user=haven dbname=haven password='it\'s a\\b'`},
		{"host=db password=explicit", "pw", "host=db password=explicit"},
	}
	for _, c := range cases {
		got, err := dsnWithPassword(c.in, c.pw)
		if err != nil || got != c.want {
			t.Errorf("dsnWithPassword(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := dsnWithPassword("mysql://x@y/z", "pw"); err == nil {
		t.Error("non-postgres URL accepted")
	}
}
