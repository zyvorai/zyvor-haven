// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// macOS service management for `haven-idp serve` through launchd:
//
//	haven-idp install-service   [--system] [--label L] [--env-file F] ...
//	haven-idp uninstall-service [--system] [--label L]
//	haven-idp service-status    [--system] [--label L]
//
// The default is a per-user LaunchAgent (no root needed, runs while the user is
// logged in; add --system for a boot-time LaunchDaemon). For the daemon we
// only generate the plist and print the exact sudo commands: haven-idp never
// runs sudo itself. The plist never contains a secret: configuration comes from
// the 0600 env file, whose entries may point at files or at Keychain items.

const (
	defaultLabel = "dev.zyvor.haven-idp"
	launchAgents = "Library/LaunchAgents"
	launchDaemon = "/Library/LaunchDaemons"
)

var (
	labelRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	envKeyRE  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	secretish = regexp.MustCompile(`(?i)(SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|CREDENTIAL|_KEY|^KEY|DSN)`)
	urlSecret = regexp.MustCompile(`://[^/@\s]*:[^/@\s]+@`)
)

// serviceOpts is everything the plist and the install plan depend on.
type serviceOpts struct {
	Label   string
	System  bool
	Binary  string            // absolute path of haven-idp
	EnvFile string            // absolute path of the 0600 env file
	DataDir string            // working directory, 0700
	LogPath string            // stdout+stderr, JSON log lines
	User    string            // system daemon: unprivileged account to run as
	Env     map[string]string // non-secret environment only
}

// validateEnv refuses anything that looks like a secret: the plist is
// world-readable (0644) and shows up in `launchctl print`.
func validateEnv(env map[string]string) error {
	for k, v := range env {
		if !envKeyRE.MatchString(k) {
			return fmt.Errorf("--env %q: names are UPPER_SNAKE_CASE", k)
		}
		if secretish.MatchString(k) && !strings.HasSuffix(k, "_FILE") && !strings.HasSuffix(k, "_KEYCHAIN") {
			return fmt.Errorf("--env %s looks like a secret and would be readable in the plist; put it in the env file, a *_FILE file or the Keychain", k)
		}
		if urlSecret.MatchString(v) {
			return fmt.Errorf("--env %s contains a URL with an embedded password; put it in the env file or the Keychain", k)
		}
	}
	return nil
}

func (o serviceOpts) validate() error {
	if !labelRE.MatchString(o.Label) {
		return fmt.Errorf("--label %q: use letters, digits, '.', '_' or '-' (reverse-DNS style, at most 128)", o.Label)
	}
	for what, p := range map[string]string{"binary": o.Binary, "env file": o.EnvFile, "data dir": o.DataDir, "log path": o.LogPath} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s path %q must be absolute (launchd has no working directory to resolve it against)", what, p)
		}
	}
	if o.System {
		if o.User == "" || o.User == "root" || o.User == "0" {
			return errors.New("--system needs --user NAME, an unprivileged account to run as (never root)")
		}
		if !regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`).MatchString(o.User) {
			return fmt.Errorf("--user %q is not a valid short account name", o.User)
		}
	} else if o.User != "" {
		return errors.New("--user only applies to --system (a LaunchAgent already runs as you)")
	}
	return validateEnv(o.Env)
}

// xmlStr escapes s for a plist <string>. XML 1.0 cannot carry control
// characters at all, so they are refused instead of silently dropped.
func xmlStr(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", errors.New("value is not valid UTF-8")
	}
	for _, r := range s {
		if r < 0x20 && r != '\t' || r == 0x7f || r == 0xfffe || r == 0xffff {
			return "", fmt.Errorf("value %q contains a control character", s)
		}
	}
	var b bytes.Buffer
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return "", err
	}
	return b.String(), nil
}

// renderPlist produces the launchd property list for opts.
func renderPlist(o serviceOpts) ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	var werr error
	str := func(s string) string {
		e, err := xmlStr(s)
		if err != nil && werr == nil {
			werr = err
		}
		return e
	}
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	w("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	w("<plist version=\"1.0\">\n<dict>\n")
	w("\t<key>Label</key>\n\t<string>%s</string>\n", str(o.Label))
	w("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, a := range []string{o.Binary, "serve", "--env-file", o.EnvFile} {
		w("\t\t<string>%s</string>\n", str(a))
	}
	w("\t</array>\n")
	w("\t<key>WorkingDirectory</key>\n\t<string>%s</string>\n", str(o.DataDir))
	if o.System {
		w("\t<key>UserName</key>\n\t<string>%s</string>\n", str(o.User))
	}
	w("\t<key>RunAtLoad</key>\n\t<true/>\n")
	w("\t<key>KeepAlive</key>\n\t<true/>\n")
	w("\t<key>ThrottleInterval</key>\n\t<integer>10</integer>\n")
	w("\t<key>ExitTimeOut</key>\n\t<integer>30</integer>\n")
	w("\t<key>ProcessType</key>\n\t<string>Background</string>\n")
	w("\t<key>Umask</key>\n\t<integer>63</integer>\n") // 0077: new files are private
	w("\t<key>StandardOutPath</key>\n\t<string>%s</string>\n", str(o.LogPath))
	w("\t<key>StandardErrorPath</key>\n\t<string>%s</string>\n", str(o.LogPath))
	if len(o.Env) > 0 {
		keys := make([]string, 0, len(o.Env))
		for k := range o.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
		for _, k := range keys {
			w("\t\t<key>%s</key>\n\t\t<string>%s</string>\n", str(k), str(o.Env[k]))
		}
		w("\t</dict>\n")
	}
	w("</dict>\n</plist>\n")
	if werr != nil {
		return nil, werr
	}
	return b.Bytes(), nil
}

// servicePlan is where things go for a mode.
type servicePlan struct {
	PlistPath string // where launchd reads it
	Domain    string // gui/UID or system
}

func (p servicePlan) target(label string) string { return p.Domain + "/" + label }

// defaults fills the per-mode locations the flags left empty.
func serviceDefaults(system bool, home string) (dataDir, logPath string) {
	if system {
		return "/Library/Application Support/haven-idp", "/var/log/haven-idp.log"
	}
	return filepath.Join(home, "Library", "Application Support", "haven-idp"),
		filepath.Join(home, "Library", "Logs", "haven-idp", "haven-idp.log")
}

// launchctlFn runs `launchctl args...` (replaced in tests).
type launchctlFn func(ctx context.Context, args ...string) (out string, exit int, err error)

func execLaunchctl(ctx context.Context, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, "launchctl", args...) // #nosec G204 -- fixed binary; label and paths are validated
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return buf.String(), 0, nil
	case errors.As(err, &ee):
		return buf.String(), ee.ExitCode(), nil
	}
	return "", -1, err
}

// svcEnv bundles the process-level inputs so the commands are testable.
type svcEnv struct {
	Out, Err  io.Writer
	Home      string
	UID       int
	GOOS      string
	Exe       string // path of the running haven-idp
	Launchctl launchctlFn
}

func osSvcEnv() (svcEnv, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return svcEnv{}, errors.New("cannot determine your home directory")
	}
	exe, err := os.Executable()
	if err != nil {
		return svcEnv{}, err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return svcEnv{Out: os.Stdout, Err: os.Stderr, Home: home, UID: os.Getuid(), GOOS: runtime.GOOS, Exe: exe, Launchctl: execLaunchctl}, nil
}

// svcFlags are shared by the three commands.
type svcFlags struct {
	label, binary, envFile, dataDir, logPath, user, out string
	system, force, noLoad, printOnly                    bool
	env                                                 envList
}

type envList []string

func (e *envList) String() string     { return strings.Join(*e, ",") }
func (e *envList) Set(v string) error { *e = append(*e, v); return nil }

func (f *svcFlags) bind(fs *flag.FlagSet, name string) {
	fs.StringVar(&f.label, "label", defaultLabel, "launchd label (also the plist file name)")
	fs.BoolVar(&f.system, "system", false, "system LaunchDaemon (boot time); only prints sudo commands, never runs them")
	if name == "install-service" {
		fs.StringVar(&f.binary, "binary", "", "haven-idp binary to run (default: this one)")
		fs.StringVar(&f.envFile, "env-file", "", "0600 env file for `serve` (default: DATA_DIR/haven-idp.env; create it with `haven-idp init`)")
		fs.StringVar(&f.dataDir, "data-dir", "", "working/data directory, created 0700")
		fs.StringVar(&f.logPath, "log", "", "log file (default ~/Library/Logs/haven-idp/haven-idp.log, or /var/log/haven-idp.log with --system)")
		fs.StringVar(&f.user, "user", "", "--system: unprivileged account to run as (required)")
		fs.StringVar(&f.out, "out", "", "--system: where to write the generated plist (default ./LABEL.plist)")
		fs.Var(&f.env, "env", "extra NAME=VALUE for the service (non-secret only; repeatable)")
		fs.BoolVar(&f.force, "force", false, "replace an installed plist that differs")
		fs.BoolVar(&f.noLoad, "no-load", false, "write the plist but do not load it")
		fs.BoolVar(&f.printOnly, "print", false, "print the plist and the plan; write nothing")
	}
}

func parseEnvList(l envList) (map[string]string, error) {
	if len(l) == 0 {
		return nil, nil
	}
	m := map[string]string{}
	for _, kv := range l {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--env %q: expected NAME=VALUE", kv)
		}
		m[k] = v
	}
	return m, nil
}

func newSvcFlagSet(name string, f *svcFlags) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f.bind(fs, name)
	return fs
}

// resolve turns flags into validated options and the launchd plan.
func (f *svcFlags) resolve(e svcEnv) (serviceOpts, servicePlan, error) {
	o := serviceOpts{Label: f.label, System: f.system, User: f.user, Binary: f.binary, EnvFile: f.envFile, DataDir: f.dataDir, LogPath: f.logPath}
	dd, lp := serviceDefaults(f.system, e.Home)
	if o.DataDir == "" {
		o.DataDir = dd
	}
	if o.LogPath == "" {
		o.LogPath = lp
	}
	if o.Binary == "" {
		o.Binary = e.Exe
	}
	if o.EnvFile == "" {
		o.EnvFile = filepath.Join(o.DataDir, "haven-idp.env")
	}
	env, err := parseEnvList(f.env)
	if err != nil {
		return o, servicePlan{}, err
	}
	o.Env = env
	if err := o.validate(); err != nil {
		return o, servicePlan{}, err
	}
	return o, planFor(f.system, o.Label, e), nil
}

// planFor says where launchd looks for the plist and which domain loads it.
func planFor(system bool, label string, e svcEnv) servicePlan {
	if system {
		return servicePlan{PlistPath: filepath.Join(launchDaemon, label+".plist"), Domain: "system"}
	}
	return servicePlan{PlistPath: filepath.Join(e.Home, launchAgents, label+".plist"), Domain: "gui/" + strconv.Itoa(e.UID)}
}

func shq(s string) string { // POSIX single-quote for the commands we print
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// preflight checks what must hold before we change anything.
func preflight(o serviceOpts, e svcEnv, writing bool) error {
	fi, err := os.Stat(o.Binary)
	if err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("binary %s is not an executable file", o.Binary)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		_, _ = fmt.Fprintf(e.Err, "haven-idp: warning: %s is writable by group/others; anyone who can replace it controls the service\n", o.Binary)
	}
	if !writing {
		return nil
	}
	efi, err := os.Stat(o.EnvFile)
	if err != nil {
		return fmt.Errorf("env file: %w (create one with `haven-idp init --dir %s`)", err, shq(filepath.Dir(o.EnvFile)))
	}
	if !efi.Mode().IsRegular() {
		return fmt.Errorf("env file %s is not a regular file", o.EnvFile)
	}
	if efi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("env file %s is readable by other users (mode %o); chmod 600 it", o.EnvFile, efi.Mode().Perm())
	}
	return nil
}

// ensurePrivateDir creates dir 0700 and tightens a looser existing one.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return os.Chmod(dir, 0o700) // #nosec G302 -- directory: needs the execute bit; 0700 is owner-only
	}
	return nil
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".haven-idp-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// svcState is what `launchctl print` told us.
type svcState struct {
	Loaded   bool
	PID      int
	State    string
	Path     string
	LastExit string
}

var (
	rePID   = regexp.MustCompile(`(?m)^\s*pid = (\d+)\s*$`)
	reState = regexp.MustCompile(`(?m)^\s*state = (\S+)\s*$`)
	rePath  = regexp.MustCompile(`(?m)^\s*path = (.+?)\s*$`)
	reExit  = regexp.MustCompile(`(?m)^\s*last exit code = (.+?)\s*$`)
)

func parsePrint(out string) svcState {
	s := svcState{Loaded: true}
	if m := rePID.FindStringSubmatch(out); m != nil {
		s.PID, _ = strconv.Atoi(m[1])
	}
	if m := reState.FindStringSubmatch(out); m != nil {
		s.State = m[1]
	}
	if m := rePath.FindStringSubmatch(out); m != nil {
		s.Path = m[1]
	}
	if m := reExit.FindStringSubmatch(out); m != nil {
		s.LastExit = m[1]
	}
	return s
}

func queryService(ctx context.Context, e svcEnv, p servicePlan, label string) (svcState, error) {
	out, exit, err := e.Launchctl(ctx, "print", p.target(label))
	if err != nil {
		return svcState{}, err
	}
	if exit != 0 {
		return svcState{}, nil // not loaded
	}
	return parsePrint(out), nil
}

func requireMac(e svcEnv) error {
	if e.GOOS != "darwin" {
		return errors.New("launchd exists only on macOS (use --print to preview the plist anywhere)")
	}
	return nil
}

// sudoInstall lists the commands the operator runs for a LaunchDaemon.
func sudoInstall(o serviceOpts, p servicePlan, generated string) []string {
	return []string{
		fmt.Sprintf("sudo install -d -m 0700 -o %s %s", shq(o.User), shq(o.DataDir)),
		fmt.Sprintf("sudo install -m 0600 -o %s YOUR_ENV_FILE %s   # a copy of your env file, readable only by the service account", shq(o.User), shq(o.EnvFile)),
		fmt.Sprintf("sudo install -m 0640 -o %s -g wheel /dev/null %s", shq(o.User), shq(o.LogPath)),
		fmt.Sprintf("sudo install -m 0644 -o root -g wheel %s %s", shq(generated), shq(p.PlistPath)),
		fmt.Sprintf("sudo launchctl bootstrap system %s", shq(p.PlistPath)),
		fmt.Sprintf("sudo launchctl print %s", shq(p.target(o.Label))),
	}
}

// cmdService dispatches the three launchd commands.
func cmdService(name string, args []string) error {
	e, err := osSvcEnv()
	if err != nil {
		return err
	}
	switch name {
	case "install-service":
		return cmdInstallService(args, e)
	case "uninstall-service":
		return cmdUninstallService(args, e)
	}
	return cmdServiceStatus(args, e)
}

func cmdInstallService(args []string, e svcEnv) error {
	var f svcFlags
	fs := newSvcFlagSet("install-service", &f)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n\n%s", err, usage)
	}
	o, p, err := f.resolve(e)
	if err != nil {
		return err
	}
	if !f.system && e.UID == 0 {
		return errors.New("run install-service as the unprivileged user that should own the service, not as root (use --system for a boot-time daemon)")
	}
	plist, err := renderPlist(o)
	if err != nil {
		return err
	}
	if f.printOnly {
		_, _ = fmt.Fprintf(e.Out, "# %s (%s)\n%s", p.PlistPath, p.Domain, plist)
		return nil
	}
	if err := preflight(o, e, !f.system); err != nil {
		return err
	}
	if f.system {
		return installSystem(o, p, plist, f.out, e)
	}
	if err := requireMac(e); err != nil {
		return err
	}
	return installAgent(context.Background(), o, p, plist, f, e)
}

// installSystem writes the plist where the user can review it and prints the
// sudo commands. It never escalates.
func installSystem(o serviceOpts, p servicePlan, plist []byte, out string, e svcEnv) error {
	if out == "" {
		out = o.Label + ".plist"
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(abs, plist, 0o644); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(e.Out, "Wrote %s (a LaunchDaemon that runs as %q; no secrets inside).\n\n", abs, o.User)
	_, _ = fmt.Fprintf(e.Out, "haven-idp does not run sudo. To install it, run these yourself, as an administrator:\n\n")
	for _, c := range sudoInstall(o, p, abs) {
		_, _ = fmt.Fprintf(e.Out, "  %s\n", c)
	}
	_, _ = fmt.Fprintf(e.Out, "\nTo remove it later: haven-idp uninstall-service --system --label %s\n", o.Label)
	_, _ = fmt.Fprintf(e.Out, "Note: a daemon cannot read your login Keychain; keep its secrets in 0600 files (HAVEN_IDP_SECRET_KEY_FILE etc.).\n")
	return nil
}

func installAgent(ctx context.Context, o serviceOpts, p servicePlan, plist []byte, f svcFlags, e svcEnv) error {
	existing, rerr := os.ReadFile(p.PlistPath)
	exists := rerr == nil
	if exists && !bytes.Equal(existing, plist) && !f.force {
		return fmt.Errorf("%s exists and differs; pass --force to replace it (or uninstall-service first)", p.PlistPath)
	}
	st, err := queryService(ctx, e, p, o.Label)
	if err != nil {
		return err
	}
	if st.Loaded && st.Path != "" && st.Path != p.PlistPath {
		return fmt.Errorf("label %s is already loaded from %s, not from our plist; choose another --label", o.Label, st.Path)
	}
	for _, d := range []string{o.DataDir, filepath.Dir(o.LogPath), filepath.Dir(p.PlistPath)} {
		if err := ensurePrivateDir(d); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(p.PlistPath, plist, 0o644); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(e.Out, "Wrote %s\n", p.PlistPath)
	if f.noLoad {
		_, _ = fmt.Fprintf(e.Out, "Not loading (--no-load). Load it with: launchctl bootstrap %s %s\n", p.Domain, shq(p.PlistPath))
		return nil
	}
	if st.Loaded { // replacing a definition that launchd already has
		if out, exit, err := e.Launchctl(ctx, "bootout", p.target(o.Label)); err != nil || exit != 0 {
			return fmt.Errorf("could not unload the old definition (exit %d): %s", exit, firstLine(out))
		}
	}
	if out, exit, err := e.Launchctl(ctx, "bootstrap", p.Domain, p.PlistPath); err != nil || exit != 0 {
		return fmt.Errorf("launchctl bootstrap failed (exit %d): %s", exit, firstLine(out))
	}
	_, _ = fmt.Fprintf(e.Out, "Loaded %s. It starts at login and is restarted if it exits.\nLogs: %s\nStatus: haven-idp service-status --label %s\n", p.target(o.Label), o.LogPath, o.Label)
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func cmdUninstallService(args []string, e svcEnv) error {
	var f svcFlags
	fs := newSvcFlagSet("uninstall-service", &f)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n\n%s", err, usage)
	}
	if !labelRE.MatchString(f.label) {
		return fmt.Errorf("--label %q is not a valid label", f.label)
	}
	p := planFor(f.system, f.label, e)
	if f.system {
		_, _ = fmt.Fprintf(e.Out, "haven-idp does not run sudo. To remove the daemon, run:\n\n  sudo launchctl bootout %s\n  sudo rm %s\n\n", shq(p.target(f.label)), shq(p.PlistPath))
		_, _ = fmt.Fprintln(e.Out, "Its data directory and logs are left in place.")
		return nil
	}
	if err := requireMac(e); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := queryService(ctx, e, p, f.label)
	if err != nil {
		return err
	}
	if st.Loaded {
		if st.Path != p.PlistPath {
			return fmt.Errorf("label %s is loaded from %q, which is not %s; refusing to unload a service that is not ours", f.label, st.Path, p.PlistPath)
		}
		if out, exit, err := e.Launchctl(ctx, "bootout", p.target(f.label)); err != nil || exit != 0 {
			return fmt.Errorf("launchctl bootout failed (exit %d): %s", exit, firstLine(out))
		}
		_, _ = fmt.Fprintf(e.Out, "Stopped and unloaded %s (was pid %d).\n", p.target(f.label), st.PID)
	}
	switch err := os.Remove(p.PlistPath); {
	case err == nil:
		_, _ = fmt.Fprintf(e.Out, "Removed %s\n", p.PlistPath)
	case errors.Is(err, os.ErrNotExist):
		if !st.Loaded {
			_, _ = fmt.Fprintf(e.Out, "Nothing to do: %s is not installed.\n", f.label)
		}
	default:
		return err
	}
	_, _ = fmt.Fprintln(e.Out, "The data directory, env file and logs were left in place.")
	return nil
}

func cmdServiceStatus(args []string, e svcEnv) error {
	var f svcFlags
	fs := newSvcFlagSet("service-status", &f)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n\n%s", err, usage)
	}
	if !labelRE.MatchString(f.label) {
		return fmt.Errorf("--label %q is not a valid label", f.label)
	}
	p := planFor(f.system, f.label, e)
	_, perr := os.Stat(p.PlistPath)
	_, _ = fmt.Fprintf(e.Out, "Label:   %s\nPlist:   %s (%s)\n", f.label, p.PlistPath, map[bool]string{true: "present", false: "missing"}[perr == nil])
	if err := requireMac(e); err != nil {
		return err
	}
	st, err := queryService(context.Background(), e, p, f.label)
	if err != nil {
		return err
	}
	switch {
	case !st.Loaded && f.system:
		_, _ = fmt.Fprintf(e.Out, "State:   not visible without root; run: sudo launchctl print %s\n", shq(p.target(f.label)))
		return errors.New("daemon state unknown")
	case !st.Loaded:
		_, _ = fmt.Fprintln(e.Out, "State:   not loaded")
		return errors.New("service is not running")
	case st.PID == 0:
		_, _ = fmt.Fprintf(e.Out, "State:   loaded but not running (%s, last exit code %s)\n", st.State, st.LastExit)
		return errors.New("service is not running")
	}
	_, _ = fmt.Fprintf(e.Out, "State:   running, pid %d (last exit code %s)\n", st.PID, st.LastExit)
	return nil
}
