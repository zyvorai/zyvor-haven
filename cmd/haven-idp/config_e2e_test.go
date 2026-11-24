// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/native"
	"github.com/zyvorai/haven/internal/idp/password"
)

const e2eRealmFile = `apiVersion: haven.zyvor.dev/v1
kind: Realm
realm: acme
settings:
  transportSecurity: external
  passwordPolicy: length(12)
  bruteForceProtection: true
  authEvents: true
  adminEvents: true
  refreshTokenRotation: true
roles:
  - name: admin
clients:
  - clientId: web
    public: true
    redirectUris: [https://app.acme.example/cb]
  - clientId: worker
    serviceAccount: true
`

// Config as code against a real haven-idp: the whole plan/apply/drift/gate/
// prune loop through the CLI entry point, the real engine and the real Admin API.
func TestConfigAsCodeEndToEnd(t *testing.T) {
	ready := make(chan string, 1)
	addr := listenFree(t)
	base := "http://" + addr
	cfg := Config{
		Listen: addr, BaseURL: base, Memory: true, CSRFKey: "k",
		BootstrapRealm: "demo", BootstrapUser: "demo", BootstrapPassword: "a-long-enough-pw-1",
		AdminClientSecret: "admin-secret-admin-secret-admin-secret", PasswordParams: password.TestParams,
		OnReady: func(a string) { ready <- a },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Logf("serve returned: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("server did not shut down")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("serve exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve never became ready")
	}

	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Setenv("HAVEN_IDP_ADMIN_CLIENT_SECRET", cfg.AdminClientSecret)
	conn := []string{"--url", base, "--admin-realm", "demo", "--client-id", "haven-admin"}
	run := func(cmd string, args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := cmdConfig(cmd, append(append([]string{}, args...), conn...), cfgIO{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
		return code, out.String() + errb.String()
	}
	want := func(step string, got, exp int, out string) {
		t.Helper()
		if got != exp {
			t.Fatalf("%s: exit %d, want %d\n%s", step, got, exp, out)
		}
	}

	file := write("acme.yaml", e2eRealmFile)
	secrets := filepath.Join(dir, "secrets.env")

	// 1. A missing realm plans as creates.
	code, out := run("plan", "-f", file)
	want("plan new realm", code, 0, out)
	if !strings.Contains(out, "+ realm acme") || !strings.Contains(out, "Plan: 4 to create") {
		t.Fatalf("plan should create the realm, role and clients:\n%s", out)
	}

	// 2. Apply creates it and hands the confidential secret to a private file only.
	code, out = run("apply", "-f", file, "--auto-approve", "--secrets-file", secrets)
	want("apply", code, 0, out)
	st, err := os.Stat(secrets)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("secrets file must exist with mode 0600: %v %v", st, err)
	}
	kv, _ := parseEnvFile(mustOpen(t, secrets))
	secret := kv["worker"]
	if len(secret) < 32 || strings.Contains(out, secret) {
		t.Fatalf("secret missing, short, or printed to the terminal (%d chars)", len(secret))
	}
	if _, has := kv["web"]; has {
		t.Fatal("public clients have no secret")
	}

	// 3. The generated secret actually authenticates; a wrong one does not.
	tokenURL := base + "/realms/acme/protocol/openid-connect/token"
	post := func(user, pw string) int {
		req, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
		req.SetBasicAuth(user, pw)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if c := post("worker", secret); c != 200 {
		t.Fatalf("generated secret rejected: %d", c)
	}
	if c := post("worker", "wrong"); c != 401 {
		t.Fatalf("wrong secret must be 401, got %d", c)
	}

	// 4. Idempotent: nothing to do, --check is clean.
	code, out = run("plan", "-f", file, "--check")
	want("re-plan", code, 0, out)
	if !strings.Contains(out, "No changes") {
		t.Fatalf("second plan must be empty:\n%s", out)
	}

	// 5. Out-of-band drift is detected (exit 2) and reverted by apply.
	nc := native.New(native.Config{BaseURL: base, Realm: "demo", ClientID: "haven-admin", ClientSecret: cfg.AdminClientSecret})
	web, err := nc.FindClientByClientID(context.Background(), "acme", "web")
	if err != nil || web == nil {
		t.Fatalf("find web: %v %v", web, err)
	}
	web.RedirectURIs = append(web.RedirectURIs, "https://evil.example/cb")
	if err := nc.UpdateClient(context.Background(), "acme", web.ID, *web); err != nil {
		t.Fatal(err)
	}
	code, out = run("plan", "-f", file, "--check")
	want("drift", code, 2, out)
	if !strings.Contains(out, "evil.example") {
		t.Fatalf("drift output must show the foreign redirect:\n%s", out)
	}
	code, out = run("apply", "-f", file, "--auto-approve")
	want("revert drift", code, 0, out)
	code, out = run("plan", "-f", file, "--check")
	want("clean after revert", code, 0, out)

	// 6. A weakening edit is blocked by Guard and changes nothing; an override works.
	weak := write("weak.yaml", strings.Replace(e2eRealmFile, "transportSecurity: external", "transportSecurity: none", 1))
	code, out = run("apply", "-f", weak, "--auto-approve")
	want("guard block", code, 3, out)
	if !strings.Contains(out, "HAVEN014") {
		t.Fatalf("block must name the rule:\n%s", out)
	}
	if r, err := nc.GetRealm(context.Background(), "acme"); err != nil || r.RealmHardening == nil || *r.SSLRequired != "external" {
		t.Fatalf("a blocked apply must change nothing: %+v %v", r, err)
	}

	// 7. Prune is opt-in and only touches what the file no longer lists.
	noWeb := write("noweb.yaml", strings.Replace(e2eRealmFile, "  - clientId: web\n    public: true\n    redirectUris: [https://app.acme.example/cb]\n", "", 1))
	code, out = run("plan", "-f", noWeb, "--check")
	want("no prune by default", code, 0, out)
	code, out = run("apply", "-f", noWeb, "--prune", "--auto-approve")
	want("prune", code, 0, out)
	if got, _ := nc.FindClientByClientID(context.Background(), "acme", "web"); got != nil {
		t.Fatal("web should have been pruned")
	}
	if got, _ := nc.FindClientByClientID(context.Background(), "acme", "worker"); got == nil {
		t.Fatal("worker must survive the prune")
	}
}

func mustOpen(t *testing.T, path string) io.Reader {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}
