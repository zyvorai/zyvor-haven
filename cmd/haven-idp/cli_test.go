// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/password"
)

func TestParseEnvFile(t *testing.T) {
	kv, err := parseEnvFile(strings.NewReader("# c\n\nA=1\nexport B = two \nC=\"q v\"\nD='x'\nE=a=b\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "1", "B": "two", "C": "q v", "D": "x", "E": "a=b"}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("%s = %q, want %q", k, kv[k], v)
		}
	}
	for _, bad := range []string{"NOEQUALS\n", "=v\n", "A B=1\n"} {
		if _, err := parseEnvFile(strings.NewReader(bad)); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestLoadEnvFileDoesNotOverrideRealEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.env")
	if err := os.WriteFile(p, []byte("HAVEN_T_SET=file\nHAVEN_T_NEW=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HAVEN_T_SET", "real")
	_ = os.Unsetenv("HAVEN_T_NEW")
	t.Cleanup(func() { _ = os.Unsetenv("HAVEN_T_NEW") })
	if err := loadEnvFile(p); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("HAVEN_T_SET") != "real" || os.Getenv("HAVEN_T_NEW") != "file" {
		t.Fatalf("env wins, file fills gaps: SET=%q NEW=%q", os.Getenv("HAVEN_T_SET"), os.Getenv("HAVEN_T_NEW"))
	}
}

func TestInitWritesPrivateFileAndRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := cmdInit([]string{"--dir", dir, "--base-url", "https://id.example.com/"}, &out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "haven-idp.env")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("want a 0600 file, got %v %v", st, err)
	}
	body, _ := os.ReadFile(path)
	kv, err := parseEnvFile(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("init output must be loadable by serve: %v", err)
	}
	if kv["HAVEN_IDP_BASE_URL"] != "https://id.example.com" {
		t.Errorf("trailing slash not trimmed: %q", kv["HAVEN_IDP_BASE_URL"])
	}
	if err := password.CheckPolicy("length(12)", kv["HAVEN_IDP_BOOTSTRAP_PASSWORD"]); err != nil {
		t.Errorf("generated admin password must satisfy the default realm policy: %v", err)
	}
	if len(kv["HAVEN_IDP_ADMIN_CLIENT_SECRET"]) < 43 || len(kv["HAVEN_IDP_CSRF_KEY"]) < 43 || len(kv["HAVEN_IDP_SECRET_KEY"]) < 43 {
		t.Error("secrets must be at least 256 bits")
	}
	if kv["HAVEN_IDP_DSN"] == "" || kv["HAVEN_IDP_DEV"] != "" {
		t.Error("default init must require a database, not the in-memory store")
	}
	// Secrets never reach the terminal.
	for _, k := range []string{"HAVEN_IDP_BOOTSTRAP_PASSWORD", "HAVEN_IDP_ADMIN_CLIENT_SECRET", "HAVEN_IDP_CSRF_KEY", "HAVEN_IDP_SECRET_KEY"} {
		if strings.Contains(out.String(), kv[k]) {
			t.Errorf("%s was printed to the terminal", k)
		}
	}
	// A second run must not silently replace working secrets...
	if err := cmdInit([]string{"--dir", dir}, io.Discard); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("want an overwrite refusal, got %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(body, after) {
		t.Fatal("the existing file was modified")
	}
	// ...unless asked, and the result stays private.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdInit([]string{"--dir", dir, "--force"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("--force must leave mode 0600, got %o", st.Mode().Perm())
	}
}

func TestInitValidatesInput(t *testing.T) {
	for _, args := range [][]string{
		{"--base-url", "ftp://x"}, {"--realm", "Bad Realm"}, {"--realm", "-x"}, {"--user", "a b"}, {"--user", ""},
	} {
		if err := cmdInit(append([]string{"--dir", t.TempDir()}, args...), io.Discard); err == nil {
			t.Errorf("%v must be rejected", args)
		}
	}
}

func TestInitPrintAndMemory(t *testing.T) {
	var out bytes.Buffer
	if err := cmdInit([]string{"--print", "--memory"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "HAVEN_IDP_DEV=1") || strings.Contains(out.String(), "HAVEN_IDP_DSN=") {
		t.Errorf("--memory must select the in-memory store:\n%s", out.String())
	}
}

func TestDevCredsAreStableAndResettable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "dev.json")
	a, err := loadDevCreds(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("creds file must be 0600, got %o", st.Mode().Perm())
	}
	b, _ := loadDevCreds(p, false)
	if a != b {
		t.Fatal("credentials must survive restarts")
	}
	if c, _ := loadDevCreds(p, true); c == a {
		t.Fatal("--reset-creds must generate new credentials")
	}
	// A truncated file is replaced, never trusted.
	if err := os.WriteFile(p, []byte(`{"password":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if d, err := loadDevCreds(p, false); err != nil || d.AdminSecret == "" || d.CSRFKey == "" {
		t.Fatalf("incomplete file must be regenerated: %+v %v", d, err)
	}
}

// End to end through the real server code path used by `dev`: bind an ephemeral
// port, bootstrap, then complete a login and token exchange over HTTP.
func TestServeDevConfigEndToEnd(t *testing.T) {
	ready := make(chan string, 1)
	cfg := Config{
		Listen: "127.0.0.1:0", BaseURL: "http://placeholder", Memory: true, CSRFKey: "k",
		BootstrapRealm: "demo", BootstrapUser: "demo", BootstrapPassword: "a-long-enough-pw-1",
		AdminClientSecret: "admin-secret-admin-secret-admin-secret", ConsoleClientID: devPlaygroundClient,
		PasswordParams: password.TestParams,
		OnReady:        func(addr string) { ready <- addr },
	}
	// BaseURL must equal the bound address for redirect/issuer checks, so bind first.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Pick a free port, then serve on it with a matching BaseURL.
	ln := listenFree(t)
	addr := ln
	cfg.Listen, cfg.BaseURL = addr, "http://"+addr
	cfg.ConsoleRedirects = []string{cfg.BaseURL + "/dev/"}
	done := make(chan error, 1)
	go func() { done <- serve(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("serve exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve never became ready")
	}

	issuer := cfg.BaseURL + "/realms/demo"
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("discovery: %v %v", resp, err)
	}
	var disc struct {
		Issuer string `json:"issuer"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	_ = resp.Body.Close()
	if disc.Issuer != issuer {
		t.Fatalf("issuer %q, want %q", disc.Issuer, issuer)
	}
	if r, _ := http.Get(cfg.BaseURL + "/readyz"); r == nil || r.StatusCode != 200 {
		t.Fatal("readyz must be 200")
	}
	if r, _ := http.Get(cfg.BaseURL + "/admin/v1/status"); r == nil || r.StatusCode != 401 {
		t.Fatalf("admin API must demand a token, got %v", r)
	}

	// Port already taken: a clear error, not a hang.
	cfg2 := cfg
	cfg2.OnReady = nil
	if err := serve(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg2); err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("want a friendly listen error, got %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown must not error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

// listenFree returns a loopback address that was free a moment ago.
func listenFree(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestInitListenFollowsBaseURLPort(t *testing.T) {
	for base, want := range map[string]string{
		"http://localhost:9000":       ":9000",
		"https://id.example.com":      ":8081",
		"https://id.example.com:8443": ":8443",
	} {
		var out bytes.Buffer
		if err := cmdInit([]string{"--print", "--base-url", base}, &out); err != nil {
			t.Fatal(err)
		}
		kv, _ := parseEnvFile(&out)
		if kv["HAVEN_IDP_LISTEN"] != want {
			t.Errorf("%s: listen %q, want %q", base, kv["HAVEN_IDP_LISTEN"], want)
		}
	}
}
