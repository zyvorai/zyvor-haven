// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/kubeauth"
	"github.com/zyvorai/haven/internal/idp/native"
	"github.com/zyvorai/haven/internal/idp/password"
	"sigs.k8s.io/yaml"
)

const kIssuer = "https://idp.example.com/realms/demo"

func kube(stdin string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := cmdKubeConfig(args, cfgIO{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb})
	return code, out.String(), errb.String()
}

func TestKubeConfigRefusals(t *testing.T) {
	gen := func(more ...string) []string { return append([]string{"generate", "--issuer", kIssuer}, more...) }
	for name, c := range map[string]struct {
		args []string
		code int
		text string
	}{
		"no subcommand":        {nil, exitUsage, "Usage"},
		"unknown subcommand":   {[]string{"apply"}, exitUsage, "Usage"},
		"no issuer":            {[]string{"generate"}, exitUsage, "--issuer"},
		"http issuer":          {[]string{"generate", "--issuer", "http://idp.example.com/realms/demo"}, exitError, "https"},
		"cluster-admin":        {gen("--bind", "a=cluster-admin"), exitError, "--allow-cluster-admin"},
		"system group":         {gen("--bind", "system:masters=view"), exitError, "refused group"},
		"system group slash":   {gen("--bind", "/system:masters=view", "--allow-cluster-admin"), exitError, "refused group"},
		"system role":          {gen("--bind", "a=system:node"), exitError, "system:"},
		"prefixed group":       {gen("--bind", "haven:devs=view"), exitError, "without the"},
		"prefixed group slash": {gen("--bind", "/haven:devs=view"), exitError, "without the"},
		"empty groups prefix":  {gen("--groups-prefix", ""), exitUsage, "must not be empty"},
		"empty user prefix":    {gen("--username-prefix="), exitUsage, "must not be empty"},
		"dash prefix":          {gen("--username-prefix", "-"), exitError, "prefix"},
		"system prefix":        {gen("--groups-prefix", "system:"), exitError, "reserved"},
		"bad only":             {gen("--only", "secrets"), exitUsage, "--only"},
		"only and out-dir":     {gen("--only", "rbac", "--out-dir", t.TempDir()), exitUsage, "cannot be combined"},
		"redirect alone":       {gen("--redirect", "http://localhost:8000"), exitUsage, "--ensure-client"},
		"update alone":         {gen("--update-client"), exitUsage, "--ensure-client"},
		"url alone":            {gen("--url", "https://idp.example.com"), exitUsage, "--ensure-client"},
		"positional":           {gen("extra"), exitUsage, "unexpected"},
		"missing ca":           {gen("--ca-file", filepath.Join(t.TempDir(), "nope")), exitUsage, "--ca-file"},
		"check no token flag":  {[]string{"check", "--issuer", kIssuer, "--token", "abc"}, exitUsage, "not defined"},
		"check require alone":  {[]string{"check", "--issuer", kIssuer, "--require-group", "a"}, exitUsage, "--token-file"},
		"check format":         {[]string{"check", "--issuer", kIssuer, "--format", "xml"}, exitUsage, "--format"},
		"check http":           {[]string{"check", "--issuer", "http://idp.example.com/realms/demo"}, exitError, ""},
	} {
		code, out, errs := kube("", c.args...)
		if code != c.code || !strings.Contains(out+errs, c.text) {
			t.Errorf("%s: exit %d want %d, %q\n%s%s", name, code, c.code, c.text, out, errs)
		}
		if name != "check http" && code != exitOK && strings.Contains(out, "kind:") {
			t.Errorf("%s: wrote configuration despite failing", name)
		}
	}
}

func TestKubeConfigGenerateOutput(t *testing.T) {
	code, out, errs := kube("", "generate", "--issuer", kIssuer, "--bind", "devs=view@default", "--only", "rbac")
	var m map[string]any
	if code != exitOK || yaml.UnmarshalStrict([]byte(out), &m) != nil || m["kind"] != "RoleBinding" {
		t.Fatalf("--only rbac must be pure YAML on stdout: %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = kube("", "generate", "--issuer", kIssuer, "--bind", "ops=cluster-admin", "--allow-cluster-admin")
	for _, want := range []string{"--oidc-issuer-url=" + kIssuer, "kind: AuthenticationConfiguration", "kind: ClusterConfiguration",
		"kube-apiserver-arg+:", "exec-credential", "name: \"haven:ops\"", "# WARNING: gives full control"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	for _, want := range []string{"HAVEN_IDP_GROUPS_CLAIM_CLIENTS=demo/kubernetes", "WARNING: gives full control", "never both"} {
		if !strings.Contains(errs, want) {
			t.Errorf("notes lack %q:\n%s", want, errs)
		}
	}
	if code != exitOK {
		t.Fatal(code)
	}

	dir := filepath.Join(t.TempDir(), "out")
	if code, _, errs = kube("", "generate", "--issuer", kIssuer, "--out-dir", dir); code != exitOK {
		t.Fatal(errs)
	}
	for _, f := range []string{"apiserver-flags.txt", "authn.yaml", "kubeadm.yaml", "k3s.yaml", "kubeconfig-user.yaml", "rbac.yaml"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, st, err)
		}
	}
	// No silent overwrite; --force replaces a symlink instead of writing through it.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "rbac.yaml")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authn.yaml"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs = kube("", "generate", "--issuer", kIssuer, "--out-dir", dir); code != exitError || !strings.Contains(errs, "already exists") {
		t.Fatalf("overwrite: %d %s", code, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "authn.yaml")); string(b) != "mine" {
		t.Fatal("file overwritten without --force")
	}
	if code, _, errs = kube("", "generate", "--issuer", kIssuer, "--out-dir", dir, "--force"); code != exitOK {
		t.Fatal(errs)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("--force wrote through a symlink")
	}
}

func TestKubeReadToken(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"raw":     {"  a.b.c\n", "a.b.c"},
		"execred": {`{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"a.b.c"}}`, "a.b.c"},
		"empty":   {"\n", ""},
		"badjson": {"{", ""},
		"nostat":  {"{}", ""},
	} {
		got, err := readToken("-", strings.NewReader(c.in))
		if got != c.want || (err == nil) != (c.want != "") {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
}

// --ensure-client against a real haven-idp and its Admin API.
func TestKubeEnsureClientEndToEnd(t *testing.T) {
	ready := make(chan string, 1)
	addr := listenFree(t)
	base := "http://" + addr
	cfg := Config{
		Listen: addr, BaseURL: base, Memory: true, CSRFKey: "k",
		BootstrapRealm: "demo", BootstrapUser: "demo", BootstrapPassword: "a-long-enough-pw-1",
		AdminClientSecret: "admin-secret-admin-secret-admin-secret", PasswordParams: password.TestParams,
		OnReady: func(a string) { ready <- a },
	}
	t.Setenv("HAVEN_IDP_GROUPS_CLAIM_CLIENTS", "demo/kubernetes")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
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
	t.Setenv("HAVEN_IDP_URL", "")
	t.Setenv("HAVEN_IDP_ADMIN_REALM", "demo")
	t.Setenv("HAVEN_IDP_ADMIN_CLIENT_SECRET", cfg.AdminClientSecret)
	run := func(more ...string) (int, string) {
		code, out, errs := kube("", append([]string{"generate", "--issuer", kIssuer, "--url", base, "--ensure-client", "--only", "flags"}, more...)...)
		if strings.Contains(out+errs, cfg.AdminClientSecret) {
			t.Fatal("the admin secret was printed")
		}
		return code, out + errs
	}
	if code, out := run(); code != exitOK || !strings.Contains(out, `"kubernetes" in realm "demo": created`) {
		t.Fatalf("create: %d %s", code, out)
	}
	if code, out := run(); code != exitOK || !strings.Contains(out, "unchanged") {
		t.Fatalf("again: %d %s", code, out)
	}
	api := native.New(native.Config{BaseURL: base, Realm: "demo", ClientID: "haven-admin", ClientSecret: cfg.AdminClientSecret})
	get := func() idp.Client {
		c, err := api.FindClientByClientID(context.Background(), "demo", "kubernetes")
		if err != nil || c == nil {
			t.Fatal(c, err)
		}
		return *c
	}
	c := get()
	if !c.PublicClient || !c.DeviceFlowEnabled || c.StandardFlowEnabled || c.ServiceAccountsEnabled {
		t.Fatalf("client: %+v", c)
	}
	if code, out := run("--redirect", "http://localhost:8000"); code != exitError || !strings.Contains(out, "--update-client") || get().StandardFlowEnabled {
		t.Fatalf("differs: %d %s", code, out)
	}
	if code, out := run("--redirect", "http://localhost:8000", "--update-client"); code != exitOK || !get().StandardFlowEnabled {
		t.Fatalf("update: %d %s", code, out)
	}
	if code, out := run("--client-id", "haven-admin", "--update-client"); code != exitError || !strings.Contains(out, "confidential") {
		t.Fatalf("admin client: %d %s", code, out)
	}
	// A failed ensure produces no configuration.
	code, out, _ := kube("", "generate", "--issuer", kIssuer, "--url", base, "--ensure-client", "--client-id", "haven-admin")
	if code != exitError || out != "" {
		t.Fatalf("configuration printed after a failed ensure: %q", out)
	}
}

// The admin secret is never sent over plain http to another machine.
func TestKubeEnsureClientRefusesPlainHTTP(t *testing.T) {
	saved := kubeAdmin
	t.Cleanup(func() { kubeAdmin = saved })
	called := false
	kubeAdmin = func(connInfo, []byte) (kubeauth.ClientAPI, error) { called = true; return nil, context.Canceled }
	t.Setenv("HAVEN_IDP_URL", "")
	t.Setenv("HAVEN_IDP_ADMIN_REALM", "demo")
	t.Setenv("HAVEN_IDP_ADMIN_CLIENT_SECRET", "s")
	for _, u := range []string{"http://idp.example.com", "http://10.0.0.5:8081", "ftp://127.0.0.1", "idp.example.com"} {
		code, _, errs := kube("", "generate", "--issuer", kIssuer, "--ensure-client", "--url", u)
		if code != exitError || called || !strings.Contains(errs, "https") {
			t.Errorf("%s: %d called=%v %s", u, code, called, errs)
		}
	}
	// Without --url the issuer's base is used.
	var got string
	kubeAdmin = func(c connInfo, _ []byte) (kubeauth.ClientAPI, error) { got = c.URL; return nil, context.Canceled }
	kube("", "generate", "--issuer", kIssuer, "--ensure-client")
	if got != "https://idp.example.com" {
		t.Errorf("default admin URL %q", got)
	}
}

func TestServeRefusesBadGroupsClaimList(t *testing.T) {
	t.Setenv("HAVEN_IDP_GROUPS_CLAIM_CLIENTS", "kubernetes")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := serve(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{Listen: listenFree(t), BaseURL: "http://127.0.0.1:1", Memory: true, PasswordParams: password.TestParams})
	if err == nil || !strings.Contains(err.Error(), "groups claim clients") {
		t.Fatalf("serve started with a malformed list: %v", err)
	}
}
