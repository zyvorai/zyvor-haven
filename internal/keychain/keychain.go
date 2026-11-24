// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package keychain reads and writes generic-password items in the macOS
// Keychain through the `security` command-line tool. There is no cgo and no
// dependency: it is a thin, injectable wrapper so haven-idp (server secrets)
// and haven (CLI tokens) share one audited path.
//
// Secrets never appear on a command line (visible in `ps`): reads use
// `security find-generic-password -w` (the secret is on the child's stdout,
// which we capture), and writes are fed to `security -i` on stdin. Error
// values never contain the secret or the tool's output, only the exit status.
package keychain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var (
	// ErrNotFound means the item does not exist.
	ErrNotFound = errors.New("keychain item not found")
	// ErrUnavailable means this platform has no usable Keychain (not macOS, or
	// the security tool is missing).
	ErrUnavailable = errors.New("the macOS Keychain is not available here")
)

// exitNotFound is the exit status of `security` when an item does not exist
// (errSecItemNotFound).
const exitNotFound = 44

// Runner executes `security` with args, feeding stdin, and returns stdout and
// the exit status (-1 when it could not be started).
type Runner func(ctx context.Context, stdin string, args ...string) (stdout []byte, exit int, err error)

// Client talks to the Keychain. The zero value is unavailable; use New.
type Client struct {
	run Runner
	ok  bool
}

// New returns a Client that runs `security`; it is unavailable on anything
// but darwin.
func New() *Client {
	return &Client{run: execRunner, ok: runtime.GOOS == "darwin" && hasSecurity()}
}

// NewWithRunner builds a Client around a fake tool (tests).
func NewWithRunner(r Runner) *Client { return &Client{run: r, ok: true} }

func hasSecurity() bool {
	_, err := exec.LookPath("security")
	return err == nil
}

// Available reports whether Get/Set/Delete can work.
func (c *Client) Available() bool { return c != nil && c.ok }

func execRunner(ctx context.Context, stdin string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "security", args...) // #nosec G204 -- fixed binary, validated arguments
	var out bytes.Buffer
	cmd.Stdout = &out
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.Bytes(), 0, nil
	case errors.As(err, &ee):
		return out.Bytes(), ee.ExitCode(), nil
	default:
		return nil, -1, err
	}
}

// validName accepts the service and account labels: no control characters,
// bounded. They are quoted for `security -i`, so quotes and backslashes are
// escaped rather than rejected.
func validName(what, s string) error {
	if s == "" || len(s) > 256 {
		return fmt.Errorf("keychain %s must be 1-256 characters", what)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("keychain %s contains a control character", what)
		}
	}
	return nil
}

// validSecret restricts what we are willing to put on `security -i`'s stdin
// unquoted: the base64 / base64url / hex / token alphabet. Callers with other
// data encode it first.
func validSecret(s string) error {
	if s == "" || len(s) > 64<<10 {
		return errors.New("keychain secret must be 1 byte to 64 KiB")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '=' || c == '-' || c == '_' || c == '.' || c == '~':
		default:
			return errors.New("keychain secret has characters outside the base64/token alphabet; encode it first")
		}
	}
	return nil
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func checkNames(service, account string) error {
	if err := validName("service", service); err != nil {
		return err
	}
	return validName("account", account)
}

// Get returns the item's secret, or ErrNotFound.
func (c *Client) Get(ctx context.Context, service, account string) (string, error) {
	if !c.Available() {
		return "", ErrUnavailable
	}
	if err := checkNames(service, account); err != nil {
		return "", err
	}
	out, exit, err := c.run(ctx, "", "find-generic-password", "-s", service, "-a", account, "-w")
	switch {
	case err != nil:
		return "", fmt.Errorf("keychain: cannot run security: %w", err)
	case exit == exitNotFound:
		return "", ErrNotFound
	case exit != 0:
		return "", fmt.Errorf("keychain: security exited with status %d", exit)
	}
	return strings.TrimSuffix(string(out), "\n"), nil
}

// Set creates or updates the item.
func (c *Client) Set(ctx context.Context, service, account, secret string) error {
	if !c.Available() {
		return ErrUnavailable
	}
	if err := checkNames(service, account); err != nil {
		return err
	}
	if err := validSecret(secret); err != nil {
		return err
	}
	script := "add-generic-password -U -s " + quote(service) + " -a " + quote(account) + " -w " + secret + "\n"
	_, exit, err := c.run(ctx, script, "-i")
	switch {
	case err != nil:
		return fmt.Errorf("keychain: cannot run security: %w", err)
	case exit != 0:
		return fmt.Errorf("keychain: security exited with status %d while storing the item", exit)
	}
	return nil
}

// Delete removes the item; a missing item is not an error.
func (c *Client) Delete(ctx context.Context, service, account string) error {
	if !c.Available() {
		return ErrUnavailable
	}
	if err := checkNames(service, account); err != nil {
		return err
	}
	_, exit, err := c.run(ctx, "", "delete-generic-password", "-s", service, "-a", account)
	switch {
	case err != nil:
		return fmt.Errorf("keychain: cannot run security: %w", err)
	case exit == exitNotFound || exit == 0:
		return nil
	}
	return fmt.Errorf("keychain: security exited with status %d while deleting the item", exit)
}
