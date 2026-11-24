// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keychain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// memRunner is an in-memory fake of the security tool, keyed by account.
func memRunner(m map[string]string) Runner {
	return func(_ context.Context, stdin string, args ...string) ([]byte, int, error) {
		switch {
		case len(args) == 1 && args[0] == "-i":
			// add-generic-password -U -s "svc" -a "acct" -w VALUE
			f := strings.Fields(strings.TrimSpace(stdin))
			m[strings.Trim(f[5], `"`)] = f[7]
			return nil, 0, nil
		case args[0] == "find-generic-password":
			if v, ok := m[args[4]]; ok {
				return []byte(v + "\n"), 0, nil
			}
			return nil, 44, nil
		case args[0] == "delete-generic-password":
			if _, ok := m[args[4]]; !ok {
				return nil, 44, nil
			}
			delete(m, args[4])
			return nil, 0, nil
		}
		return nil, 1, nil
	}
}

func TestBlobChunking(t *testing.T) {
	ctx := context.Background()
	m := map[string]string{}
	c := NewWithRunner(memRunner(m))
	big := strings.Repeat("Zz09+/", 1500) // 9000 chars -> 3 chunks
	if err := c.SetBlob(ctx, "svc", "p", big); err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 || !strings.HasPrefix(m["p"], "hb1.3.") {
		t.Fatalf("items = %d, head %.8q", len(m), m["p"])
	}
	for k, v := range m {
		if len(v) > 3100 {
			t.Errorf("chunk %s is %d bytes: too big for one security -i line", k, len(v))
		}
	}
	if got, err := c.GetBlob(ctx, "svc", "p"); err != nil || got != big {
		t.Fatalf("round trip: %v", err)
	}
	if err := c.SetBlob(ctx, "svc", "p", "small"); err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Errorf("stale chunks left after shrink: %d items", len(m))
	}
	if err := c.SetBlob(ctx, "svc", "p", big); err != nil {
		t.Fatal(err)
	}
	delete(m, "p#2")
	if _, err := c.GetBlob(ctx, "svc", "p"); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("missing chunk must fail: %v", err)
	}
	if err := c.DeleteBlob(ctx, "svc", "p"); err != nil || len(m) != 0 {
		t.Errorf("DeleteBlob left %d items (%v)", len(m), err)
	}
	if err := c.DeleteBlob(ctx, "svc", "p"); err != nil {
		t.Errorf("deleting a missing blob: %v", err)
	}
	m["raw"] = "not-a-blob"
	if _, err := c.GetBlob(ctx, "svc", "raw"); err == nil {
		t.Error("a plain item must not parse as a blob")
	}
	for _, h := range []string{"hb1.0.x", "hb1.99.x", "hb1.03.x", "hb1.x.y", "hb1.3"} {
		m["bad"] = h
		if _, err := c.GetBlob(ctx, "svc", "bad"); err == nil {
			t.Errorf("header %q accepted", h)
		}
	}
}

// TestRealBlob uses the real Keychain (HAVEN_TEST_KEYCHAIN=1, macOS only).
func TestRealBlob(t *testing.T) {
	if os.Getenv("HAVEN_TEST_KEYCHAIN") != "1" || !New().Available() {
		t.Skip("set HAVEN_TEST_KEYCHAIN=1 on macOS to run")
	}
	ctx := context.Background()
	svc := fmt.Sprintf("haven-test-blob-%d", os.Getpid())
	c := New()
	t.Cleanup(func() { _ = c.DeleteBlob(ctx, svc, "blob") })
	huge := strings.Repeat("AbCd0123+/", 1000) + "="
	if err := c.SetBlob(ctx, svc, "blob", huge); err != nil {
		t.Fatal(err)
	}
	if got, err := c.GetBlob(ctx, svc, "blob"); err != nil || got != huge {
		t.Fatalf("blob round trip: len %d err %v", len(got), err)
	}
	if err := c.SetBlob(ctx, svc, "blob", "tiny"); err != nil {
		t.Fatal(err)
	}
	if got, err := c.GetBlob(ctx, svc, "blob"); err != nil || got != "tiny" {
		t.Fatalf("shrunk blob: %q %v", got, err)
	}
	if _, err := c.Get(ctx, svc, "blob#1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("stale chunk left behind: %v", err)
	}
	if err := c.SetBlob(ctx, svc, "blob", huge); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteBlob(ctx, svc, "blob"); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"blob", "blob#1", "blob#3"} {
		if _, err := c.Get(ctx, svc, a); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s survived DeleteBlob: %v", a, err)
		}
	}
}
