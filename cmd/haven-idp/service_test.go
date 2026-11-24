// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baseOpts() serviceOpts {
	return serviceOpts{
		Label: "dev.zyvor.haven-idp", Binary: "/usr/local/bin/haven-idp",
		EnvFile: "/Users/me/Library/Application Support/haven-idp/haven-idp.env",
		DataDir: "/Users/me/Library/Application Support/haven-idp",
		LogPath: "/Users/me/Library/Logs/haven-idp/haven-idp.log",
	}
}

// plistValue is a minimal reader for the flat dicts we emit, so tests check
// the decoded document and not just substrings.
func decodePlist(t *testing.T, b []byte) map[string]any {
	t.Helper()
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	d.Entity = nil
	var stack []map[string]any
	var arrays [][]string
	var keys []string
	var cur string
	var text strings.Builder
	var inArray bool
	var root map[string]any
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch x := tok.(type) {
		case xml.StartElement:
			text.Reset()
			switch x.Name.Local {
			case "dict":
				m := map[string]any{}
				if len(stack) > 0 {
					stack[len(stack)-1][cur] = m
				} else {
					root = m
				}
				stack = append(stack, m)
				keys = append(keys, cur)
			case "array":
				inArray = true
				arrays = append(arrays, nil)
			}
		case xml.CharData:
			text.Write(x)
		case xml.EndElement:
			switch x.Name.Local {
			case "key":
				cur = text.String()
			case "string":
				if inArray {
					arrays[len(arrays)-1] = append(arrays[len(arrays)-1], text.String())
				} else {
					stack[len(stack)-1][cur] = text.String()
				}
			case "integer":
				stack[len(stack)-1][cur] = text.String()
			case "true", "false":
				stack[len(stack)-1][cur] = x.Name.Local
			case "array":
				inArray = false
				stack[len(stack)-1][cur] = arrays[len(arrays)-1]
				arrays = arrays[:len(arrays)-1]
			case "dict":
				stack = stack[:len(stack)-1]
				keys = keys[:len(keys)-1]
			}
		}
	}
	if root == nil {
		t.Fatalf("not a plist:\n%s", b)
	}
	return root
}

func TestPlistAgentContents(t *testing.T) {
	b, err := renderPlist(baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	m := decodePlist(t, b)
	args, _ := m["ProgramArguments"].([]string)
	if want := "/usr/local/bin/haven-idp|serve|--env-file|/Users/me/Library/Application Support/haven-idp/haven-idp.env"; strings.Join(args, "|") != want {
		t.Errorf("ProgramArguments = %v", args)
	}
	for k, want := range map[string]string{
		"Label": "dev.zyvor.haven-idp", "KeepAlive": "true", "RunAtLoad": "true", "Umask": "63",
		"StandardOutPath":   "/Users/me/Library/Logs/haven-idp/haven-idp.log",
		"StandardErrorPath": "/Users/me/Library/Logs/haven-idp/haven-idp.log",
		"WorkingDirectory":  "/Users/me/Library/Application Support/haven-idp",
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %s", k, m[k], want)
		}
	}
	if _, has := m["UserName"]; has {
		t.Error("a LaunchAgent must not set UserName (it runs as the logged-in user)")
	}
	if _, has := m["EnvironmentVariables"]; has {
		t.Error("no environment unless asked for")
	}
}

func TestPlistSystemRunsAsUnprivilegedUser(t *testing.T) {
	o := baseOpts()
	o.System, o.User = true, "_haven"
	b, err := renderPlist(o)
	if err != nil {
		t.Fatal(err)
	}
	if m := decodePlist(t, b); m["UserName"] != "_haven" {
		t.Errorf("UserName = %v", m["UserName"])
	}
	for _, u := range []string{"", "root", "0", "bad user", "x;y", "Admin"} {
		o.User = u
		if _, err := renderPlist(o); err == nil {
			t.Errorf("--user %q accepted for a daemon", u)
		}
	}
	o = baseOpts()
	o.User = "bob"
	if _, err := renderPlist(o); err == nil {
		t.Error("--user accepted without --system")
	}
}

func TestPlistEscapesXML(t *testing.T) {
	o := baseOpts()
	nasty := `/Users/a&b/<"x">'y'/Application Support`
	o.DataDir = nasty
	o.EnvFile = nasty + "/e&nv"
	o.LogPath = nasty + "/log"
	o.Env = map[string]string{"HAVEN_IDP_BASE_URL": `https://x/?a=1&b=<2>`}
	b, err := renderPlist(o)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, raw := range []string{"a&b", "<x>", "e&nv", "&b=<2>"} {
		if strings.Contains(s, raw) {
			t.Errorf("unescaped %q in plist:\n%s", raw, s)
		}
	}
	m := decodePlist(t, b)
	if m["WorkingDirectory"] != nasty {
		t.Errorf("round trip lost data: %v", m["WorkingDirectory"])
	}
	env, _ := m["EnvironmentVariables"].(map[string]any)
	if env["HAVEN_IDP_BASE_URL"] != `https://x/?a=1&b=<2>` {
		t.Errorf("env round trip: %v", env)
	}
}

func TestPlistRejectsInvalidText(t *testing.T) {
	for _, bad := range []string{"/a\x00b", "/a\x01b", "/a\nb", "/a\xffb"} {
		o := baseOpts()
		o.DataDir = bad
		if _, err := renderPlist(o); err == nil {
			t.Errorf("DataDir %q accepted", bad)
		}
	}
	for _, label := range []string{"", "a b", "a/b", "../x", "a<b", strings.Repeat("a", 200), "-lead"} {
		o := baseOpts()
		o.Label = label
		if _, err := renderPlist(o); err == nil {
			t.Errorf("label %q accepted", label)
		}
	}
	o := baseOpts()
	o.Binary = "haven-idp"
	if _, err := renderPlist(o); err == nil {
		t.Error("relative binary accepted")
	}
}

func TestPlistRefusesSecrets(t *testing.T) {
	bad := []map[string]string{
		{"HAVEN_IDP_SECRET_KEY": "abc"},
		{"HAVEN_IDP_DSN": "postgres://u@h/db"},
		{"HAVEN_IDP_BOOTSTRAP_PASSWORD": "x"},
		{"HAVEN_IDP_ADMIN_CLIENT_SECRET": "x"},
		{"HAVEN_IDP_CSRF_KEY": "x"},
		{"SOME_TOKEN": "x"},
		{"HAVEN_IDP_AUDIT": "webhook:https://u:pw@example.com/hook"},
		{"lower": "x"},
	}
	for _, env := range bad {
		o := baseOpts()
		o.Env = env
		if b, err := renderPlist(o); err == nil {
			t.Errorf("env %v accepted:\n%s", env, b)
		}
	}
	for _, env := range []map[string]string{
		{"HAVEN_IDP_SECRET_KEY_FILE": "/Users/me/secret.key"},
		{"HAVEN_IDP_SECRET_KEY_KEYCHAIN": "1"},
		{"HAVEN_IDP_LISTEN": "127.0.0.1:8081", "HAVEN_IDP_BASE_URL": "https://idp.example.com"},
	} {
		o := baseOpts()
		o.Env = env
		if _, err := renderPlist(o); err != nil {
			t.Errorf("env %v refused: %v", env, err)
		}
	}
}

// ---- install / uninstall / status against a fake launchctl ----

type fakeLaunchd struct {
	loaded map[string]string // target -> plist path
	pid    int
	calls  []string
}

func (f *fakeLaunchd) run(_ context.Context, args ...string) (string, int, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	switch args[0] {
	case "print":
		if p, ok := f.loaded[args[1]]; ok {
			return fmt.Sprintf("%s = {\n\tpath = %s\n\tstate = running\n\tpid = %d\n\tlast exit code = (never exited)\n}\n", args[1], p, f.pid), 0, nil
		}
		return "Could not find service", 113, nil
	case "bootstrap":
		f.loaded[args[1]+"/"+labelOf(args[2])] = args[2]
		return "", 0, nil
	case "bootout":
		delete(f.loaded, args[1])
		return "", 0, nil
	}
	return "", 1, nil
}

func labelOf(plist string) string { return strings.TrimSuffix(filepath.Base(plist), ".plist") }

type svcFixture struct {
	e     svcEnv
	out   *bytes.Buffer
	errb  *bytes.Buffer
	ld    *fakeLaunchd
	home  string
	env   string
	label string
}

func newSvcFixture(t *testing.T) *svcFixture {
	t.Helper()
	home := t.TempDir()
	bin := filepath.Join(home, "haven-idp")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- test stub
		t.Fatal(err)
	}
	data := filepath.Join(home, "Library", "Application Support", "haven-idp")
	if err := os.MkdirAll(data, 0o755); err != nil { // looser than 0700 on purpose
		t.Fatal(err)
	}
	envf := filepath.Join(data, "haven-idp.env")
	if err := os.WriteFile(envf, []byte("HAVEN_IDP_BASE_URL=http://localhost:8081\nHAVEN_IDP_SECRET_KEY=TOP-SECRET-VALUE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &svcFixture{out: &bytes.Buffer{}, errb: &bytes.Buffer{}, ld: &fakeLaunchd{loaded: map[string]string{}, pid: 4242}, home: home, env: envf, label: "dev.zyvor.haven-idp-test"}
	f.e = svcEnv{Out: f.out, Err: f.errb, Home: home, UID: 501, GOOS: "darwin", Exe: bin, Launchctl: f.ld.run}
	return f
}

func (f *svcFixture) plistPath() string {
	return filepath.Join(f.home, "Library", "LaunchAgents", f.label+".plist")
}

func TestInstallAgentWritesPrivateDirsAndLoads(t *testing.T) {
	f := newSvcFixture(t)
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err != nil {
		t.Fatalf("%v\n%s", err, f.errb)
	}
	data := filepath.Join(f.home, "Library", "Application Support", "haven-idp")
	logs := filepath.Join(f.home, "Library", "Logs", "haven-idp")
	for _, d := range []string{data, logs} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %v err %v (want 0700, also when it pre-existed looser)", d, fi, err)
		}
	}
	fi, err := os.Stat(f.plistPath())
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("plist: %v %v", fi, err)
	}
	b, _ := os.ReadFile(f.plistPath())
	if strings.Contains(string(b), "TOP-SECRET-VALUE") {
		t.Fatal("env file contents leaked into the plist")
	}
	if want := "bootstrap gui/501 " + f.plistPath(); f.ld.calls[len(f.ld.calls)-1] != want {
		t.Errorf("calls = %v", f.ld.calls)
	}
	if strings.Contains(f.out.String()+f.errb.String(), "TOP-SECRET-VALUE") {
		t.Error("secret printed")
	}
	// Idempotent: same plist, loaded -> reinstall replaces the loaded definition cleanly.
	f.ld.calls = nil
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.ld.calls, "|"), "bootout gui/501/"+f.label) {
		t.Errorf("reinstall must unload first: %v", f.ld.calls)
	}
}

func TestInstallRefusals(t *testing.T) {
	f := newSvcFixture(t)
	if err := os.Chmod(f.env, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("group/world readable env file must be refused: %v", err)
	}
	if err := os.Chmod(f.env, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.env); err != nil {
		t.Fatal(err)
	}
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err == nil || !strings.Contains(err.Error(), "haven-idp init") {
		t.Errorf("missing env file: %v", err)
	}
	if _, err := os.Stat(f.plistPath()); err == nil {
		t.Error("a plist was written despite the failed preflight")
	}
	f.e.UID = 0
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err == nil || !strings.Contains(err.Error(), "not as root") {
		t.Errorf("root must be refused for an agent: %v", err)
	}
	f.e.UID = 501
	if err := os.WriteFile(f.env, []byte("HAVEN_IDP_DEV=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.e.GOOS = "linux"
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err == nil || !strings.Contains(err.Error(), "macOS") {
		t.Errorf("non-mac: %v", err)
	}
}

func TestInstallDoesNotClobberDifferingPlistWithoutForce(t *testing.T) {
	f := newSvcFixture(t)
	if err := os.MkdirAll(filepath.Dir(f.plistPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.plistPath(), []byte("<plist>hand edited</plist>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("%v", err)
	}
	if b, _ := os.ReadFile(f.plistPath()); string(b) != "<plist>hand edited</plist>" {
		t.Error("file was overwritten")
	}
	if err := cmdInstallService([]string{"--label", f.label, "--force"}, f.e); err != nil {
		t.Fatal(err)
	}
}

func TestInstallRefusesForeignLoadedLabel(t *testing.T) {
	f := newSvcFixture(t)
	f.ld.loaded["gui/501/"+f.label] = "/Library/LaunchAgents/other.plist"
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err == nil || !strings.Contains(err.Error(), "already loaded") {
		t.Fatalf("%v", err)
	}
	for _, c := range f.ld.calls {
		if strings.HasPrefix(c, "bootout") || strings.HasPrefix(c, "bootstrap") {
			t.Errorf("touched a service that is not ours: %v", f.ld.calls)
		}
	}
}

func TestSystemModeNeverRunsAnythingAndPrintsSudo(t *testing.T) {
	f := newSvcFixture(t)
	out := filepath.Join(t.TempDir(), "d.plist")
	err := cmdInstallService([]string{"--system", "--user", "_haven", "--label", f.label, "--env-file", f.env, "--out", out}, f.e)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.ld.calls) != 0 {
		t.Fatalf("system mode ran launchctl: %v", f.ld.calls)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("plist not written: %v", err)
	}
	s := f.out.String()
	for _, want := range []string{
		"sudo install -d -m 0700 -o _haven '/Library/Application Support/haven-idp'",
		"sudo install -m 0644 -o root -g wheel " + out + " /Library/LaunchDaemons/" + f.label + ".plist",
		"sudo launchctl bootstrap system /Library/LaunchDaemons/" + f.label + ".plist",
		"does not run sudo",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "TOP-SECRET-VALUE") {
		t.Error("secret printed")
	}
	if err := cmdInstallService([]string{"--system", "--label", f.label, "--env-file", f.env, "--out", out}, f.e); err == nil {
		t.Error("--system without --user accepted")
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "<key>UserName</key>") {
		t.Error("daemon plist lacks UserName")
	}
}

func TestPrintWritesNothing(t *testing.T) {
	f := newSvcFixture(t)
	f.e.GOOS = "linux" // --print works anywhere
	if err := cmdInstallService([]string{"--print", "--label", f.label}, f.e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "<key>KeepAlive</key>") {
		t.Error("no plist printed")
	}
	if _, err := os.Stat(f.plistPath()); err == nil {
		t.Error("--print wrote the plist")
	}
}

func TestUninstallOnlyUnloadsOurOwnService(t *testing.T) {
	f := newSvcFixture(t)
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err != nil {
		t.Fatal(err)
	}
	f.ld.calls = nil
	if err := cmdUninstallService([]string{"--label", f.label}, f.e); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.ld.calls, "|"); got != "print gui/501/"+f.label+"|bootout gui/501/"+f.label {
		t.Errorf("calls = %s", got)
	}
	if _, err := os.Stat(f.plistPath()); err == nil {
		t.Error("plist left behind")
	}
	if _, err := os.Stat(f.env); err != nil {
		t.Error("uninstall must keep the env file / data")
	}
	if !strings.Contains(f.out.String(), "pid 4242") {
		t.Errorf("output should name the pid it stopped: %s", f.out)
	}
	// Foreign service under the same label: refuse, do not bootout.
	f.ld.calls = nil
	f.ld.loaded["gui/501/"+f.label] = "/Library/LaunchAgents/other.plist"
	if err := cmdUninstallService([]string{"--label", f.label}, f.e); err == nil || !strings.Contains(err.Error(), "not ours") {
		t.Fatalf("%v", err)
	}
	for _, c := range f.ld.calls {
		if strings.HasPrefix(c, "bootout") {
			t.Errorf("unloaded a foreign service: %v", f.ld.calls)
		}
	}
	// Nothing installed: harmless.
	delete(f.ld.loaded, "gui/501/"+f.label)
	f.out.Reset()
	if err := cmdUninstallService([]string{"--label", f.label}, f.e); err != nil || !strings.Contains(f.out.String(), "Nothing to do") {
		t.Errorf("%v %s", err, f.out)
	}
}

func TestUninstallSystemOnlyPrintsCommands(t *testing.T) {
	f := newSvcFixture(t)
	if err := cmdUninstallService([]string{"--system", "--label", f.label}, f.e); err != nil {
		t.Fatal(err)
	}
	if len(f.ld.calls) != 0 || !strings.Contains(f.out.String(), "sudo launchctl bootout system/"+f.label) {
		t.Errorf("calls %v out %s", f.ld.calls, f.out)
	}
}

func TestServiceStatus(t *testing.T) {
	f := newSvcFixture(t)
	if err := cmdServiceStatus([]string{"--label", f.label}, f.e); err == nil || !strings.Contains(f.out.String(), "not loaded") {
		t.Errorf("not installed must be a failure: %v / %s", err, f.out)
	}
	if err := cmdInstallService([]string{"--label", f.label}, f.e); err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
	if err := cmdServiceStatus([]string{"--label", f.label}, f.e); err != nil || !strings.Contains(f.out.String(), "running, pid 4242") {
		t.Errorf("%v / %s", err, f.out)
	}
	f.ld.pid = 0
	if err := cmdServiceStatus([]string{"--label", f.label}, f.e); err == nil {
		t.Error("loaded-but-not-running must fail")
	}
}

func TestParsePrint(t *testing.T) {
	s := parsePrint("gui/501/x = {\n\tactive count = 1\n\tpath = /Users/a b/Library/LaunchAgents/x.plist\n\tstate = running\n\n\tpid = 123\n\tlast exit code = 0\n}")
	if s.PID != 123 || s.State != "running" || s.Path != "/Users/a b/Library/LaunchAgents/x.plist" || s.LastExit != "0" {
		t.Errorf("%+v", s)
	}
}

func TestShq(t *testing.T) {
	for in, want := range map[string]string{"/a/b": "/a/b", "/a b": "'/a b'", "it's": `'it'\''s'`, "": "''"} {
		if got := shq(in); got != want {
			t.Errorf("shq(%q) = %q, want %q", in, got, want)
		}
	}
}
