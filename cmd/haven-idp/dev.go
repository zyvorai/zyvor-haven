// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
)

const (
	devPlaygroundClient = "dev-playground"
	devAppClient        = "demo-app"
	devCLIClient        = "demo-cli" // public, device flow (haven login)
)

// playgroundHandler serves the browser-based OIDC playground at /dev/. It is
// set by dev_playground.go; dev works without it.
var playgroundHandler func(issuer, clientID string) http.Handler

// devCreds survive restarts so the test user, secrets and CSRF key do not
// change under the developer's feet. They only protect a loopback-only,
// in-memory server; the file is still written 0600.
type devCreds struct {
	Password    string `json:"password"`
	AdminSecret string `json:"adminSecret"`
	CSRFKey     string `json:"csrfKey"`
}

func devCredsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "haven-idp", "dev.json"), nil
}

// loadDevCreds returns the stored credentials, creating them on first use.
// A corrupt or incomplete file is replaced rather than trusted.
func loadDevCreds(path string, reset bool) (devCreds, error) {
	var c devCreds
	if !reset {
		if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- fixed per-user path
			if json.Unmarshal(b, &c) == nil && c.Password != "" && c.AdminSecret != "" && c.CSRFKey != "" {
				return c, nil
			}
		}
	}
	c = devCreds{Password: secret(18), AdminSecret: secret(32), CSRFKey: secret(32)}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return c, err
	}
	b, _ := json.Marshal(c)
	return c, os.WriteFile(path, b, 0o600)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdDev(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("dev", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Int("port", 8081, "port to listen on (loopback only)")
	realm := fs.String("realm", "demo", "realm to create")
	user := fs.String("user", "demo", "test user name")
	open := fs.Bool("open", false, "open the playground in your browser")
	reset := fs.Bool("reset-creds", false, "generate a new test password and secrets")
	var redirects multiFlag
	fs.Var(&redirects, "redirect", "redirect URI for the "+devAppClient+" client (repeatable; default http://localhost:3000/callback)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n\n%s", err, usage)
	}
	if *port < 1 || *port > 65535 {
		return errors.New("--port must be between 1 and 65535")
	}
	if !validRealm(*realm) {
		return fmt.Errorf("--realm %q is not a valid realm name (lowercase letters, digits, . _ -)", *realm)
	}
	if len(redirects) == 0 {
		redirects = multiFlag{"http://localhost:3000/callback"}
	}

	path, err := devCredsPath()
	if err != nil {
		return fmt.Errorf("find a place for dev credentials: %w", err)
	}
	creds, err := loadDevCreds(path, *reset)
	if err != nil {
		return fmt.Errorf("dev credentials: %w", err)
	}

	base := fmt.Sprintf("http://127.0.0.1:%d", *port)
	issuer := base + "/realms/" + *realm
	outbox := mail.NewOutbox(100)
	cfg := Config{
		Mailer:                  outbox,                             // no real email in dev: see /dev/mail
		Listen:                  fmt.Sprintf("127.0.0.1:%d", *port), // loopback only: this server is for development
		BaseURL:                 base,
		Memory:                  true,
		MetricsOnMain:           true,
		CSRFKey:                 creds.CSRFKey,
		BootstrapRealm:          *realm,
		BootstrapUser:           *user,
		BootstrapPassword:       creds.Password,
		AdminClientSecret:       creds.AdminSecret,
		ConsoleClientID:         devPlaygroundClient,
		ConsoleRedirects:        []string{base + "/dev/"},
		BackchannelAllowPrivate: true, // dev: loopback IdP, apps on localhost
		PostBootstrap: func(ctx context.Context, st core.Store, _ core.PasswordHasher) error {
			err := st.CreateClient(ctx, core.Client{
				Realm: *realm, ClientID: devAppClient, Name: "Demo app", Enabled: true,
				Public: true, AuthCodeFlow: true, RequirePKCE: true, RedirectURIs: redirects,
			})
			if err != nil && !errors.Is(err, idp.ErrConflict) {
				return err
			}
			// Device flow demo client: no redirect URIs needed.
			err = st.CreateClient(ctx, core.Client{
				Realm: *realm, ClientID: devCLIClient, Name: "Demo CLI", Enabled: true,
				Public: true, DeviceFlow: true,
			})
			if err != nil && !errors.Is(err, idp.ErrConflict) {
				return err
			}
			return nil
		},
		Mount: func(mux *http.ServeMux) {
			mux.Handle("/dev/mail", devMailHandler(outbox))
			if playgroundHandler != nil {
				mux.Handle("/dev/", playgroundHandler(issuer, devPlaygroundClient))
			}
		},
		OnReady: func(string) {
			printDevBanner(out, base, issuer, *realm, *user, creds, redirects, playgroundHandler != nil)
			if *open && playgroundHandler != nil {
				openBrowser(base + "/dev/")
			}
		},
	}

	// Readable logs for humans; errors still go to stderr.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, log, cfg)
}

func printDevBanner(w io.Writer, base, issuer, realm, user string, c devCreds, redirects []string, playground bool) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("\nhaven-idp dev: in-memory and loopback only (data resets on restart)\n\n")
	p("  Issuer       %s\n", issuer)
	p("  Discovery    %s/.well-known/openid-configuration\n", issuer)
	if playground {
		p("  Playground   %s/dev/   sign in and inspect, verify and refresh tokens\n", base)
	}
	p("  Dev mailbox  %s/dev/mail   password-reset and verification emails land here\n", base)
	p("  Test user    %s / %s\n", user, c.Password)
	p("  Test client  %s (public, PKCE S256)  redirect: %s\n", devAppClient, strings.Join(redirects, ", "))
	p("  CLI client   %s (public, device flow)   haven login --issuer %s --client-id %s\n", devCLIClient, issuer, devCLIClient)
	p("  Admin API    %s/admin/v1   (client haven-admin)\n", base)
	p("  Metrics      %s/metrics   (Prometheus)\n\n", base)
	p("Use it from an app:\n")
	p("  OIDC_ISSUER=%s OIDC_CLIENT_ID=%s\n\n", issuer, devAppClient)
	p("Use it from the Haven console:\n")
	p("  HAVEN_IDP_BACKEND=native HAVEN_IDP_URL=%s HAVEN_IDP_ADMIN_REALM=%s \\\n", base, realm)
	p("  HAVEN_IDP_ADMIN_CLIENT_SECRET=%s haven-console\n\n", c.AdminSecret)
	p("Ctrl-C to stop.\n\n")
}

// openBrowser is best effort; failure just means the user clicks the link.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url) // #nosec G204 -- fixed binary, loopback URL we built
	case "linux":
		cmd = exec.Command("xdg-open", url) // #nosec G204 -- fixed binary, loopback URL we built
	default:
		return
	}
	_ = cmd.Start()
}
