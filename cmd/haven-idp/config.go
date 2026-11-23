// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/configcode"
	"github.com/zyvorai/haven/internal/idp/native"
	"github.com/zyvorai/haven/internal/posture"
)

// Exit codes of the config commands.
const (
	exitOK      = 0
	exitError   = 1
	exitDrift   = 2 // plan --check found drift
	exitBlocked = 3 // Haven Guard blocked the change
)

// cfgEngine holds the engine entry points; tests replace them.
var cfgEngine = struct {
	Parse   func(io.Reader) (*configcode.Spec, error)
	Marshal func(*configcode.Spec) ([]byte, error)
	Read    func(context.Context, idp.Provider, string) (*configcode.Spec, error)
	Diff    func(desired, live *configcode.Spec, o configcode.Options) *configcode.Plan
	Apply   func(context.Context, idp.Provider, *configcode.Plan, *configcode.Spec) (*configcode.ApplyResult, error)
}{configcode.Parse, configcode.Marshal, configcode.Read, configcode.Diff, configcode.Apply}

// cfgConnect opens the Admin API connection; tests replace it.
var cfgConnect = func(c connInfo) (idp.Provider, error) {
	return native.New(native.Config{BaseURL: c.URL, Realm: c.AdminRealm, ClientID: c.ClientID, ClientSecret: c.Secret}), nil
}

type connInfo struct {
	URL, AdminRealm, ClientID, Secret string
}

// cfgIO is the process environment of a config command.
type cfgIO struct {
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Color       bool
	Interactive bool // stdin is a terminal
}

func osCfgIO() cfgIO {
	isTTY := func(f *os.File) bool {
		st, err := f.Stat()
		return err == nil && st.Mode()&os.ModeCharDevice != 0
	}
	return cfgIO{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Color:       isTTY(os.Stdout) && os.Getenv("NO_COLOR") == "",
		Interactive: isTTY(os.Stdin),
	}
}

type cfgFlags struct {
	file, format, failOn, secretsFile  string
	prune, autoApprove, allowFindings  bool
	check, dev                         bool
	port                               int
	url, adminRealm, clientID, envFile string
}

func newCfgFlagSet(name string, f *cfgFlags) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.file, "f", "", "realm file (- for stdin)")
	fs.StringVar(&f.format, "format", "text", "output format: text or json")
	fs.StringVar(&f.failOn, "fail-on", "high", "Guard gate threshold: critical, high, medium, low, info or none")
	switch name {
	case "plan":
		fs.BoolVar(&f.prune, "prune", false, "plan deletion of live clients missing from the file (clients only; roles and groups are never pruned)")
		fs.BoolVar(&f.check, "check", false, "exit 2 when there is drift")
	case "apply":
		fs.BoolVar(&f.prune, "prune", false, "delete live clients missing from the file (clients only; roles and groups are never pruned)")
		fs.BoolVar(&f.autoApprove, "auto-approve", false, "do not ask for confirmation")
		fs.BoolVar(&f.allowFindings, "allow-findings", false, "apply even when Guard blocks the change")
		fs.StringVar(&f.secretsFile, "secrets-file", "", "write secrets of new confidential clients here (mode 0600, never overwritten)")
	}
	if name != "validate" {
		fs.BoolVar(&f.dev, "dev", false, "connect to the local `haven-idp dev` server")
		fs.IntVar(&f.port, "port", 8081, "port of the dev server (with --dev)")
		fs.StringVar(&f.url, "url", "", "haven-idp base URL (HAVEN_IDP_URL)")
		fs.StringVar(&f.adminRealm, "admin-realm", "", "realm of the admin client (HAVEN_IDP_ADMIN_REALM)")
		fs.StringVar(&f.clientID, "client-id", "", "admin client id (HAVEN_IDP_ADMIN_CLIENT_ID, default haven-admin)")
		fs.StringVar(&f.envFile, "env-file", os.Getenv("HAVEN_IDP_ENV_FILE"), "load KEY=VALUE pairs for variables that are not already set")
	}
	return fs
}

// cmdConfig runs validate, plan, apply or export and returns the exit code.
func cmdConfig(name string, args []string, io_ cfgIO) int {
	code, err := runConfig(name, args, io_)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(io_.Stderr, "haven-idp:", err)
		if code == exitOK {
			code = exitError
		}
	}
	return code
}

func runConfig(name string, args []string, io_ cfgIO) (int, error) {
	var f cfgFlags
	fs := newCfgFlagSet(name, &f)
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return exitError, fmt.Errorf("%w\n\n%s", err, usage)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	if f.format != "text" && f.format != "json" {
		return exitError, fmt.Errorf("--format must be text or json, got %q", f.format)
	}
	threshold, err := parseThreshold(f.failOn)
	if err != nil {
		return exitError, err
	}
	if name == "export" {
		if len(positional) != 1 || !validRealm(positional[0]) {
			return exitError, errors.New("usage: haven-idp export REALM [connection flags]")
		}
		return runExport(positional[0], f, io_)
	}
	if len(positional) > 0 {
		return exitError, fmt.Errorf("unexpected argument %q", positional[0])
	}
	if f.file == "" {
		return exitError, errors.New("-f FILE is required (use - for stdin)")
	}
	desired, err := loadSpec(f.file, io_)
	if err != nil {
		return exitError, err
	}
	switch name {
	case "validate":
		return runValidate(desired, threshold, f, io_)
	case "plan":
		return runPlan(desired, threshold, f, io_)
	default:
		return runApply(desired, threshold, f, io_)
	}
}

func parseThreshold(s string) (posture.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		return "", nil
	case "critical", "high", "medium", "low", "info":
		return posture.Severity(strings.ToLower(strings.TrimSpace(s))), nil
	}
	return "", fmt.Errorf("--fail-on must be critical, high, medium, low, info or none, got %q", s)
}

func loadSpec(path string, io_ cfgIO) (*configcode.Spec, error) {
	var r io.Reader = io_.Stdin
	if path != "-" {
		fh, err := os.Open(path) // #nosec G304 -- operator-provided path
		if err != nil {
			return nil, err
		}
		defer func() { _ = fh.Close() }()
		r = fh
	}
	spec, err := cfgEngine.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return spec, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

type gateJSON struct {
	ScoreBefore int               `json:"scoreBefore"`
	ScoreAfter  int               `json:"scoreAfter"`
	GradeBefore string            `json:"gradeBefore"`
	GradeAfter  string            `json:"gradeAfter"`
	New         []posture.Finding `json:"new"`
	Fixed       []posture.Finding `json:"fixed"`
	Blocked     []posture.Finding `json:"blocked"`
}

func toGateJSON(g configcode.GateResult) gateJSON {
	nz := func(f []posture.Finding) []posture.Finding {
		if f == nil {
			return []posture.Finding{}
		}
		return f
	}
	return gateJSON{g.Before.Score, g.After.Score, g.Before.Grade, g.After.Grade, nz(g.New), nz(g.Fixed), nz(g.Blocked)}
}

func runValidate(desired *configcode.Spec, th posture.Severity, f cfgFlags, io_ cfgIO) (int, error) {
	g := configcode.Gate(desired, nil, th)
	code := exitOK
	if len(g.Blocked) > 0 {
		code = exitBlocked
	}
	if f.format == "json" {
		return code, writeJSON(io_.Stdout, map[string]any{"valid": true, "realm": desired.Realm, "gate": toGateJSON(g)})
	}
	fmt.Fprintf(io_.Stdout, "%s is valid (realm %q).\n\nA fresh realm from this file would get this Guard result:\n", f.file, desired.Realm)
	g.Render(io_.Stdout, io_.Color)
	return code, nil
}

func runPlan(desired *configcode.Spec, th posture.Severity, f cfgFlags, io_ cfgIO) (int, error) {
	prov, err := connect(f)
	if err != nil {
		return exitError, err
	}
	plan, g, _, err := computePlan(desired, prov, th, f)
	if err != nil {
		return exitError, err
	}
	code := exitOK
	switch {
	case len(g.Blocked) > 0:
		code = exitBlocked
	case f.check && !plan.Empty():
		code = exitDrift
	}
	if f.format == "json" {
		return code, writeJSON(io_.Stdout, map[string]any{"plan": plan, "gate": toGateJSON(g), "drift": !plan.Empty()})
	}
	plan.Render(io_.Stdout, io_.Color)
	if !plan.Empty() {
		fmt.Fprintln(io_.Stdout)
		g.Render(io_.Stdout, io_.Color)
	}
	return code, nil
}

func computePlan(desired *configcode.Spec, prov idp.Provider, th posture.Severity, f cfgFlags) (*configcode.Plan, configcode.GateResult, *configcode.Spec, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	live, err := cfgEngine.Read(ctx, prov, desired.Realm)
	if errors.Is(err, idp.ErrNotFound) {
		live, err = nil, nil
	}
	if err != nil {
		return nil, configcode.GateResult{}, nil, fmt.Errorf("read live state of realm %q: %w", desired.Realm, err)
	}
	plan := cfgEngine.Diff(desired, live, configcode.Options{Prune: f.prune})
	return plan, configcode.Gate(desired, live, th), live, nil
}

func runApply(desired *configcode.Spec, th posture.Severity, f cfgFlags, io_ cfgIO) (int, error) {
	// Fail early on things that would lose data after the change is made.
	if f.secretsFile != "" {
		if _, err := os.Lstat(f.secretsFile); err == nil {
			return exitError, fmt.Errorf("--secrets-file %s already exists; refusing to overwrite it", f.secretsFile)
		}
	}
	prov, err := connect(f)
	if err != nil {
		return exitError, err
	}
	plan, g, _, err := computePlan(desired, prov, th, f)
	if err != nil {
		return exitError, err
	}
	if f.format == "text" {
		plan.Render(io_.Stdout, io_.Color)
	}
	if plan.Empty() {
		if f.format == "json" {
			return exitOK, writeJSON(io_.Stdout, map[string]any{"plan": plan, "applied": []configcode.Change{}})
		}
		return exitOK, nil
	}
	if f.format == "text" {
		fmt.Fprintln(io_.Stdout)
		g.Render(io_.Stdout, io_.Color)
	}
	if len(g.Blocked) > 0 {
		if !f.allowFindings {
			if f.format == "json" {
				_ = writeJSON(io_.Stdout, map[string]any{"plan": plan, "gate": toGateJSON(g), "blocked": true})
			}
			return exitBlocked, errors.New("not applied: Haven Guard blocked this change (see above)")
		}
		fmt.Fprintf(io_.Stderr, "WARNING: --allow-findings: applying despite %d blocking Guard finding(s).\n", len(g.Blocked))
	}
	newConf := newConfidentialClients(plan, desired)
	if len(newConf) > 0 && f.secretsFile == "" {
		fmt.Fprintf(io_.Stderr, "note: %d new confidential client(s) will get generated secrets; without --secrets-file they are discarded and must be regenerated.\n", len(newConf))
	}

	if !f.autoApprove {
		if !io_.Interactive || f.file == "-" {
			return exitError, errors.New("refusing to apply without confirmation: pass --auto-approve (stdin is not a terminal or is used for the file)")
		}
		fmt.Fprint(io_.Stdout, "\nApply these changes? [y/N] ")
		line, _ := bufio.NewReader(io_.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return exitError, errors.New("apply cancelled")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, applyErr := cfgEngine.Apply(ctx, prov, plan, desired)
	secretErr := error(nil)
	nSecrets := 0
	if res != nil {
		nSecrets = len(res.NewSecrets)
		if nSecrets > 0 {
			secretErr = saveSecrets(f.secretsFile, res.NewSecrets)
		}
	}
	if f.format == "json" {
		out := map[string]any{"plan": plan, "secretsCreated": nSecrets, "secretsSaved": nSecrets > 0 && secretErr == nil && f.secretsFile != ""}
		if res != nil {
			out["applied"] = res.Applied
		}
		_ = writeJSON(io_.Stdout, out)
	} else if res != nil {
		cr, up, de := countActions(res.Applied)
		fmt.Fprintf(io_.Stdout, "\nApply %s: %d created, %d updated, %d deleted.\n", map[bool]string{true: "stopped", false: "complete"}[applyErr != nil], cr, up, de)
	}
	if nSecrets > 0 {
		switch {
		case f.secretsFile == "":
			fmt.Fprintf(io_.Stderr, "%d new confidential client(s) were created and their secrets were NOT saved (not printed on purpose). Regenerate them and pass --secrets-file PATH next time.\n", nSecrets)
		case secretErr != nil:
			fmt.Fprintf(io_.Stderr, "ERROR: %d client secret(s) could not be written to %s: %v\nThe secrets are lost: regenerate them for the new clients.\n", nSecrets, f.secretsFile, secretErr)
		default:
			fmt.Fprintf(io_.Stderr, "Wrote %d client secret(s) to %s (mode 0600).\n", nSecrets, f.secretsFile)
		}
	}
	if applyErr != nil {
		return exitError, fmt.Errorf("apply: %w", applyErr)
	}
	if secretErr != nil {
		return exitError, errors.New("secrets were not saved")
	}
	return exitOK, nil
}

func countActions(cs []configcode.Change) (cr, up, de int) {
	for _, c := range cs {
		switch c.Action {
		case configcode.ActionCreate:
			cr++
		case configcode.ActionUpdate:
			up++
		case configcode.ActionDelete:
			de++
		}
	}
	return
}

// newConfidentialClients lists clients the plan creates that are not public.
func newConfidentialClients(plan *configcode.Plan, desired *configcode.Spec) []string {
	pub := map[string]bool{}
	for _, c := range desired.Clients {
		pub[c.ClientID] = c.Public
	}
	var out []string
	for _, c := range plan.Changes {
		if c.Action == configcode.ActionCreate && c.Kind == configcode.KindOfClient && !pub[c.Name] {
			out = append(out, c.Name)
		}
	}
	return out
}

// saveSecrets writes clientId=secret lines, never overwriting an existing file.
func saveSecrets(path string, secrets map[string]string) error {
	if path == "" {
		return nil
	}
	ids := make([]string, 0, len(secrets))
	for id := range secrets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		fmt.Fprintf(&b, "%s=%s\n", id, secrets[id])
	}
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-provided path
	if err != nil {
		return err
	}
	if _, err := fh.WriteString(b.String()); err != nil {
		_ = fh.Close()
		return err
	}
	return fh.Close()
}

func runExport(realm string, f cfgFlags, io_ cfgIO) (int, error) {
	prov, err := connect(f)
	if err != nil {
		return exitError, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	spec, err := cfgEngine.Read(ctx, prov, realm)
	if err != nil {
		return exitError, fmt.Errorf("read realm %q: %w", realm, err)
	}
	b, err := cfgEngine.Marshal(spec)
	if err != nil {
		return exitError, err
	}
	_, err = io_.Stdout.Write(b)
	return exitOK, err
}

// connect resolves the Admin API connection from flags and environment.
func connect(f cfgFlags) (idp.Provider, error) {
	var c connInfo
	if f.dev {
		path, err := devCredsPath()
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(path); err != nil {
			return nil, errors.New("no dev credentials found; start the server with `haven-idp dev` first")
		}
		creds, err := loadDevCreds(path, false)
		if err != nil {
			return nil, fmt.Errorf("dev credentials: %w", err)
		}
		c = connInfo{URL: fmt.Sprintf("http://127.0.0.1:%d", f.port), AdminRealm: "demo", ClientID: "haven-admin", Secret: creds.AdminSecret}
		return cfgConnect(c)
	}
	if f.envFile != "" {
		if err := loadEnvFile(f.envFile); err != nil {
			return nil, err
		}
	}
	first := func(vals ...string) string {
		for _, v := range vals {
			if v != "" {
				return v
			}
		}
		return ""
	}
	c.URL = first(f.url, os.Getenv("HAVEN_IDP_URL"))
	c.AdminRealm = first(f.adminRealm, os.Getenv("HAVEN_IDP_ADMIN_REALM"))
	c.ClientID = first(f.clientID, os.Getenv("HAVEN_IDP_ADMIN_CLIENT_ID"), "haven-admin")
	var err error
	c.Secret, err = fromFile(os.Getenv("HAVEN_IDP_ADMIN_CLIENT_SECRET"), os.Getenv("HAVEN_IDP_ADMIN_CLIENT_SECRET_FILE"), "admin client secret")
	if err != nil {
		return nil, err
	}
	var missing []string
	if c.URL == "" {
		missing = append(missing, "--url / HAVEN_IDP_URL")
	}
	if c.AdminRealm == "" {
		missing = append(missing, "--admin-realm / HAVEN_IDP_ADMIN_REALM")
	}
	if c.Secret == "" {
		missing = append(missing, "HAVEN_IDP_ADMIN_CLIENT_SECRET or HAVEN_IDP_ADMIN_CLIENT_SECRET_FILE")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing connection settings: %s (or use --dev)", strings.Join(missing, ", "))
	}
	return cfgConnect(c)
}
