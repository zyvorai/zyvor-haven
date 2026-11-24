// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keychain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

type call struct {
	stdin string
	args  []string
}

func fake(exit int, out string, calls *[]call) Runner {
	return func(_ context.Context, stdin string, args ...string) ([]byte, int, error) {
		*calls = append(*calls, call{stdin, args})
		return []byte(out), exit, nil
	}
}

func TestGetTrimsAndArgs(t *testing.T) {
	var calls []call
	c := NewWithRunner(fake(0, "s3cr3t+/=\n", &calls))
	got, err := c.Get(context.Background(), "svc", "acct")
	if err != nil || got != "s3cr3t+/=" {
		t.Fatalf("got %q, %v", got, err)
	}
	if want := "find-generic-password -s svc -a acct -w"; strings.Join(calls[0].args, " ") != want {
		t.Errorf("args = %v", calls[0].args)
	}
}

func TestGetNotFoundAndFailure(t *testing.T) {
	var calls []call
	if _, err := NewWithRunner(fake(44, "", &calls)).Get(context.Background(), "s", "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("exit 44: %v", err)
	}
	_, err := NewWithRunner(fake(36, "TOPSECRET", &calls)).Get(context.Background(), "s", "a")
	if err == nil || errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "TOPSECRET") {
		t.Errorf("exit 36 must be a plain error without tool output: %v", err)
	}
}

func TestSetUsesStdinNotArgv(t *testing.T) {
	var calls []call
	c := NewWithRunner(fake(0, "", &calls))
	if err := c.Set(context.Background(), `my "svc"`, "acct", "AbC123+/="); err != nil {
		t.Fatal(err)
	}
	got := calls[0]
	if strings.Join(got.args, " ") != "-i" {
		t.Errorf("argv must be just -i (a secret in argv is visible in ps): %v", got.args)
	}
	if want := `add-generic-password -U -s "my \"svc\"" -a "acct" -w AbC123+/=` + "\n"; got.stdin != want {
		t.Errorf("stdin = %q, want %q", got.stdin, want)
	}
}

func TestSetRejectsInjection(t *testing.T) {
	c := NewWithRunner(fake(0, "", new([]call)))
	for _, secret := range []string{"", "a b", "x\nadd-generic-password -s evil", `a"b`, "a;b", "a$b", strings.Repeat("a", 65<<10)} {
		if err := c.Set(context.Background(), "s", "a", secret); err == nil {
			t.Errorf("secret %.20q accepted", secret)
		}
	}
	for _, n := range []string{"", "a\nb", "a\x00b", strings.Repeat("x", 300)} {
		if err := c.Set(context.Background(), n, "a", "abc"); err == nil {
			t.Errorf("service %.20q accepted", n)
		}
		if _, err := c.Get(context.Background(), "s", n); err == nil {
			t.Errorf("account %.20q accepted", n)
		}
	}
}

func TestDelete(t *testing.T) {
	var calls []call
	for _, exit := range []int{0, 44} {
		if err := NewWithRunner(fake(exit, "", &calls)).Delete(context.Background(), "s", "a"); err != nil {
			t.Errorf("exit %d: %v", exit, err)
		}
	}
	if err := NewWithRunner(fake(2, "", &calls)).Delete(context.Background(), "s", "a"); err == nil {
		t.Error("exit 2 must fail")
	}
}

func TestUnavailable(t *testing.T) {
	c := &Client{}
	if c.Available() {
		t.Fatal("zero client available")
	}
	if _, err := c.Get(context.Background(), "s", "a"); !errors.Is(err, ErrUnavailable) {
		t.Error(err)
	}
	if err := c.Set(context.Background(), "s", "a", "x"); !errors.Is(err, ErrUnavailable) {
		t.Error(err)
	}
	var nilc *Client
	if nilc.Available() {
		t.Error("nil client available")
	}
	if runtime.GOOS != "darwin" && New().Available() {
		t.Error("available off macOS")
	}
}

// TestRealKeychain round-trips through the real `security` tool. It touches
// the login keychain, so it only runs when HAVEN_TEST_KEYCHAIN=1 on a Mac.
func TestRealKeychain(t *testing.T) {
	if os.Getenv("HAVEN_TEST_KEYCHAIN") != "1" || !New().Available() {
		t.Skip("set HAVEN_TEST_KEYCHAIN=1 on macOS to run")
	}
	ctx := context.Background()
	svc := fmt.Sprintf("haven-test-%d", os.Getpid())
	c := New()
	t.Cleanup(func() { _ = c.Delete(ctx, svc, "acct") })
	if _, err := c.Get(ctx, svc, "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fresh item: %v", err)
	}
	big := strings.Repeat("AbCd0123+/", 300) + "="
	for _, v := range []string{"first-value", big} {
		if err := c.Set(ctx, svc, "acct", v); err != nil {
			t.Fatal(err)
		}
		got, err := c.Get(ctx, svc, "acct")
		if err != nil || got != v {
			t.Fatalf("round trip failed (len %d vs %d): %v", len(got), len(v), err)
		}
	}
	if err := c.Delete(ctx, svc, "acct"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, svc, "acct"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
