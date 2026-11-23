// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/configcode"
)

const testSecret = "s3cr3t-value-never-print"

type fakeEnv struct {
	spec     *configcode.Spec
	live     *configcode.Spec
	plan     *configcode.Plan
	applied  int
	secrets  map[string]string
	applyErr error
}

func setupFake(t *testing.T, e *fakeEnv) {
	t.Helper()
	old, oldConn := cfgEngine, cfgConnect
	t.Cleanup(func() { cfgEngine, cfgConnect = old, oldConn })
	cfgEngine.Parse = func(io.Reader) (*configcode.Spec, error) { return e.spec, nil }
	cfgEngine.Marshal = func(*configcode.Spec) ([]byte, error) { return []byte("realm: demo\n"), nil }
	cfgEngine.Read = func(context.Context, idp.Provider, string) (*configcode.Spec, error) {
		if e.live == nil {
			return nil, fmt.Errorf("realm: %w", idp.ErrNotFound)
		}
		return e.live, nil
	}
	cfgEngine.Diff = func(d, l *configcode.Spec, o configcode.Options) *configcode.Plan { return e.plan }
	cfgEngine.Apply = func(context.Context, idp.Provider, *configcode.Plan, *configcode.Spec) (*configcode.ApplyResult, error) {
		e.applied++
		return &configcode.ApplyResult{Applied: e.plan.Changes, NewSecrets: e.secrets}, e.applyErr
	}
	cfgConnect = func(connInfo) (idp.Provider, error) { return nil, nil }
	t.Setenv("HAVEN_IDP_URL", "http://127.0.0.1:1")
	t.Setenv("HAVEN_IDP_ADMIN_REALM", "demo")
	t.Setenv("HAVEN_IDP_ADMIN_CLIENT_SECRET", "adminsecret")
}

func run(t *testing.T, name string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cmdConfig(name, args, cfgIO{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	return code, out.String(), errb.String()
}

func goodSpec() *configcode.Spec {
	return &configcode.Spec{Realm: "demo", Clients: []configcode.Client{{ClientID: "web", Public: true, RedirectURIs: []string{"https://a.example.com/cb"}}}}
}

func risky() *configcode.Spec {
	tr := "none"
	return &configcode.Spec{Realm: "demo", Settings: configcode.Settings{TransportSecurity: &tr}}
}

func createPlan() *configcode.Plan {
	return &configcode.Plan{Realm: "demo", Changes: []configcode.Change{
		{Action: configcode.ActionCreate, Kind: configcode.KindOfClient, Name: "svc"},
	}}
}

func specFile(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "realm.yaml")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigFlagErrors(t *testing.T) {
	setupFake(t, &fakeEnv{spec: goodSpec(), plan: &configcode.Plan{Realm: "demo"}})
	for _, args := range [][]string{
		{"plan"}, // no -f
		{"plan", "-f", "x", "--fail-on", "bogus"}, // bad threshold
		{"plan", "-f", "x", "--format", "xml"},    // bad format
		{"plan", "-f", "x", "--nope"},             // unknown flag
		{"plan", "-f", specFile(t), "extra"},      // stray arg
		{"export"},                                // no realm
		{"export", "Bad Realm"},                   // invalid realm
	} {
		if code, _, _ := run(t, args[0], args[1:]...); code != exitError {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}

func TestValidateOfflineAndBlocked(t *testing.T) {
	e := &fakeEnv{spec: goodSpec()}
	setupFake(t, e)
	t.Setenv("HAVEN_IDP_URL", "") // validate must not need a connection
	cfgConnect = func(connInfo) (idp.Provider, error) { t.Fatal("validate connected"); return nil, nil }
	code, out, _ := run(t, "validate", "-f", specFile(t))
	if code != exitOK || !strings.Contains(out, "is valid") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	e.spec = risky()
	code, out, _ = run(t, "validate", "-f", specFile(t))
	if code != exitBlocked || !strings.Contains(out, "HAVEN014") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if code, _, _ = run(t, "validate", "-f", specFile(t), "--fail-on", "none"); code != exitOK {
		t.Fatalf("--fail-on none: %d", code)
	}
}

func TestPlanCheckExitCodes(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), live: goodSpec(), plan: &configcode.Plan{Realm: "demo"}}
	setupFake(t, e)
	f := specFile(t)
	code, out, _ := run(t, "plan", "-f", f, "--check")
	if code != exitOK || !strings.Contains(out, "No changes") {
		t.Fatalf("no drift: %d %s", code, out)
	}
	e.plan = createPlan()
	code, out, _ = run(t, "plan", "-f", f, "--check")
	if code != exitDrift || !strings.Contains(out, "+ client svc") {
		t.Fatalf("drift: %d %s", code, out)
	}
	if code, _, _ = run(t, "plan", "-f", f); code != exitOK {
		t.Fatalf("plan without --check must exit 0, got %d", code)
	}
	e.spec = risky()
	if code, _, _ = run(t, "plan", "-f", f, "--check"); code != exitBlocked {
		t.Fatalf("blocked must win over drift, got %d", code)
	}
}

func TestPlanJSONAndMissingRealm(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), plan: createPlan()} // live nil => ErrNotFound => nil live
	setupFake(t, e)
	code, out, _ := run(t, "plan", "-f", specFile(t), "--format", "json")
	if code != exitOK || !strings.Contains(out, `"drift": true`) || !strings.Contains(out, `"gate"`) {
		t.Fatalf("%d %s", code, out)
	}
}

func TestApplyRefusesWithoutApproval(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), plan: createPlan()}
	setupFake(t, e)
	code, _, errs := run(t, "apply", "-f", specFile(t))
	if code != exitError || e.applied != 0 || !strings.Contains(errs, "--auto-approve") {
		t.Fatalf("code=%d applied=%d err=%s", code, e.applied, errs)
	}
}

func TestApplyBlockedAndAllowFindings(t *testing.T) {
	e := &fakeEnv{spec: risky(), plan: createPlan()}
	setupFake(t, e)
	f := specFile(t)
	code, out, _ := run(t, "apply", "-f", f, "--auto-approve")
	if code != exitBlocked || e.applied != 0 || !strings.Contains(out, "BLOCKED") {
		t.Fatalf("code=%d applied=%d out=%s", code, e.applied, out)
	}
	code, _, errs := run(t, "apply", "-f", f, "--auto-approve", "--allow-findings")
	if code != exitOK || e.applied != 1 || !strings.Contains(errs, "WARNING") {
		t.Fatalf("code=%d applied=%d err=%s", code, e.applied, errs)
	}
}

func TestApplyConfirmPrompt(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), plan: createPlan()}
	setupFake(t, e)
	f := specFile(t)
	var out, errb bytes.Buffer
	io1 := cfgIO{Stdin: strings.NewReader("n\n"), Stdout: &out, Stderr: &errb, Interactive: true}
	if code := cmdConfig("apply", []string{"-f", f}, io1); code != exitError || e.applied != 0 {
		t.Fatalf("declined: code=%d applied=%d", code, e.applied)
	}
	if !strings.Contains(out.String(), "Apply these changes? [y/N]") {
		t.Fatalf("no prompt: %s", out.String())
	}
	io2 := cfgIO{Stdin: strings.NewReader("y\n"), Stdout: &out, Stderr: &errb, Interactive: true}
	if code := cmdConfig("apply", []string{"-f", f}, io2); code != exitOK || e.applied != 1 {
		t.Fatalf("accepted: code=%d applied=%d", code, e.applied)
	}
}

func TestApplySecretsNeverPrinted(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), plan: createPlan(), secrets: map[string]string{"svc": testSecret}}
	setupFake(t, e)
	code, out, errs := run(t, "apply", "-f", specFile(t), "--auto-approve")
	if code != exitOK || strings.Contains(out+errs, testSecret) || !strings.Contains(errs, "--secrets-file") {
		t.Fatalf("code=%d out=%s err=%s", code, out, errs)
	}
	// json output must not leak either
	code, out, errs = run(t, "apply", "-f", specFile(t), "--auto-approve", "--format", "json")
	if code != exitOK || strings.Contains(out+errs, testSecret) {
		t.Fatalf("json leaked: %s %s", out, errs)
	}
}

func TestApplySecretsFile(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), plan: createPlan(), secrets: map[string]string{"svc": testSecret, "a": "x"}}
	setupFake(t, e)
	sf := filepath.Join(t.TempDir(), "secrets.env")
	code, out, errs := run(t, "apply", "-f", specFile(t), "--auto-approve", "--secrets-file", sf)
	if code != exitOK || strings.Contains(out+errs, testSecret) {
		t.Fatalf("code=%d out=%s err=%s", code, out, errs)
	}
	b, err := os.ReadFile(sf)
	if err != nil || string(b) != "a=x\nsvc="+testSecret+"\n" {
		t.Fatalf("file=%q err=%v", b, err)
	}
	if st, _ := os.Stat(sf); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	// refuses to overwrite, before applying anything
	e.applied = 0
	code, _, errs = run(t, "apply", "-f", specFile(t), "--auto-approve", "--secrets-file", sf)
	if code != exitError || e.applied != 0 || !strings.Contains(errs, "refusing to overwrite") {
		t.Fatalf("code=%d applied=%d err=%s", code, e.applied, errs)
	}
	if b2, _ := os.ReadFile(sf); !bytes.Equal(b, b2) {
		t.Fatal("existing secrets file was modified")
	}
}

func TestApplySecretsWriteFailureReportsLoss(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), plan: createPlan(), secrets: map[string]string{"svc": testSecret}}
	setupFake(t, e)
	sf := filepath.Join(t.TempDir(), "no-such-dir", "s.env")
	code, out, errs := run(t, "apply", "-f", specFile(t), "--auto-approve", "--secrets-file", sf)
	if code != exitError || !strings.Contains(errs, "regenerate") || strings.Contains(out+errs, testSecret) {
		t.Fatalf("code=%d out=%s err=%s", code, out, errs)
	}
}

func TestApplyEngineError(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), plan: createPlan(), applyErr: errors.New("boom")}
	setupFake(t, e)
	code, _, errs := run(t, "apply", "-f", specFile(t), "--auto-approve")
	if code != exitError || !strings.Contains(errs, "boom") {
		t.Fatalf("code=%d err=%s", code, errs)
	}
}

func TestExportPrintsMarshal(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), live: goodSpec(), plan: &configcode.Plan{}}
	setupFake(t, e)
	code, out, _ := run(t, "export", "demo")
	if code != exitOK || out != "realm: demo\n" {
		t.Fatalf("%d %q", code, out)
	}
}

func TestConnectionSettingsRequired(t *testing.T) {
	e := &fakeEnv{spec: goodSpec(), plan: &configcode.Plan{Realm: "demo"}}
	setupFake(t, e)
	t.Setenv("HAVEN_IDP_URL", "")
	code, _, errs := run(t, "plan", "-f", specFile(t))
	if code != exitError || !strings.Contains(errs, "HAVEN_IDP_URL") {
		t.Fatalf("code=%d err=%s", code, errs)
	}
}
