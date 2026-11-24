// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package havencli implements the "haven" command-line client: it logs a human
// in to haven-idp (or any RFC 8628 capable OIDC provider) with the OAuth 2.0
// Device Authorization Grant and hands the credentials to other tools.
//
// Exit codes: 0 ok, 1 error, 2 usage, 3 not logged in.
package havencli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/keychain"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitNotLoggedIn = 3
)

// Version is set by the main package (-ldflags or build info).
var Version = "dev"

// Env is everything Run needs from the outside world, so tests can fake the
// clock, the browser and the filesystem location.
type Env struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	UserHomeDir    func() (string, error)
	Now            func() time.Time
	Sleep          func(ctx context.Context, d time.Duration) error
	// OpenBrowser opens a URL; nil disables. Errors are never fatal.
	OpenBrowser func(url string) error
	// Vault is the macOS Keychain for `haven login --keychain`; nil elsewhere.
	Vault Vault
}

// DefaultEnv wires the real process environment.
func DefaultEnv() *Env {
	e := &Env{
		Stdout: os.Stdout, Stderr: os.Stderr,
		Getenv: os.Getenv, UserHomeDir: os.UserHomeDir,
		Now: time.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		OpenBrowser: openBrowser,
	}
	if kc := keychain.New(); kc.Available() {
		e.Vault = kc
	}
	return e
}

func openBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "linux", "freebsd", "openbsd", "netbsd":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return errors.New("no display")
		}
		cmd = exec.Command("xdg-open", u)
	default:
		return errors.New("unsupported platform")
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }
func usageErrorf(f string, a ...any) error {
	return &usageError{fmt.Sprintf(f, a...)}
}

type notLoggedInError struct{ msg string }

func (e *notLoggedInError) Error() string { return e.msg }
func notLoggedInf(f string, a ...any) error {
	return &notLoggedInError{fmt.Sprintf(f, a...)}
}

const usageText = `haven: log in to haven-idp (or any OIDC provider with RFC 8628) from a terminal

Usage:
  haven login  --issuer URL --client-id ID [--scope "openid offline_access profile email"]
               [--profile NAME] [--no-browser] [--ca-file PEM] [--keychain (macOS)]
  haven token  [--profile NAME] [--id-token] [--min-validity 60s]
  haven whoami [--profile NAME] [--json]
  haven logout [--profile NAME]
  haven exec-credential --issuer URL --client-id ID [--profile NAME]   (kubectl exec plugin)
  haven version | help

Common flags (every command that talks to the network):
  --ca-file PEM                    trust this extra CA (remembered per profile by login)
  --insecure-http                  allow a plain http:// issuer on a non-loopback host (DANGEROUS)
  --allow-cross-origin-endpoints   accept discovery endpoints on another origin than the issuer

Credentials live in $XDG_CONFIG_HOME/haven/credentials.json (default ~/.config/haven), mode 0600.
On macOS, login --keychain keeps the tokens in the login Keychain instead.
Tokens are never accepted on the command line. See docs/haven-cli.md.

Exit codes: 0 ok, 1 error, 2 usage, 3 not logged in.
`

// Run executes one haven invocation and returns the process exit code.
func Run(ctx context.Context, args []string, env *Env) int {
	if env.Stdout == nil {
		env.Stdout = io.Discard
	}
	if env.Stderr == nil {
		env.Stderr = io.Discard
	}
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usageText)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	a := &app{env: env}
	var err error
	switch cmd {
	case "login":
		err = a.cmdLogin(ctx, rest)
	case "token":
		err = a.cmdToken(ctx, rest)
	case "whoami":
		err = a.cmdWhoami(ctx, rest)
	case "logout":
		err = a.cmdLogout(ctx, rest)
	case "exec-credential":
		err = a.cmdExecCredential(ctx, rest)
	case "version", "--version", "-v":
		fmt.Fprintln(env.Stdout, "haven", Version)
	case "help", "--help", "-h":
		fmt.Fprint(env.Stdout, usageText)
	default:
		err = usageErrorf("unknown command %q", cmd)
	}
	return exitCode(err, env.Stderr)
}

func exitCode(err error, stderr io.Writer) int {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	var ue *usageError
	var ne *notLoggedInError
	switch {
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "haven: %s\n\nRun `haven help` for usage.\n", ue.msg)
		return ExitUsage
	case errors.As(err, &ne):
		fmt.Fprintf(stderr, "haven: %s\n", ne.msg)
		return ExitNotLoggedIn
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(stderr, "haven: cancelled")
		return ExitError
	}
	fmt.Fprintf(stderr, "haven: %s\n", err)
	return ExitError
}

type app struct{ env *Env }

// flagSet builds a quiet flag set; parse errors become usage errors.
func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageErrorf("%v", err)
	}
	if fs.NArg() > 0 {
		return usageErrorf("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

// common holds the flags shared by every network command.
type common struct {
	profile string
	net     netOpts
}

func (c *common) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.profile, "profile", "default", "credentials profile name")
	fs.StringVar(&c.net.CAFile, "ca-file", "", "PEM file with an extra CA to trust")
	fs.BoolVar(&c.net.InsecureHTTP, "insecure-http", false, "allow plain http:// issuers on non-loopback hosts (dangerous)")
	fs.BoolVar(&c.net.AllowCross, "allow-cross-origin-endpoints", false, "accept discovery endpoints on a different origin than the issuer")
}

func (a *app) store() (*store, error) { return newStore(a.env) }

// sanitize makes server-provided text safe to print.
func sanitize(s string) string { return clean(strings.TrimSpace(s), 300) }
