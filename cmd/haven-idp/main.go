// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Command haven-idp is Haven's own OIDC identity server.
//
//	haven-idp dev                try it locally in one command (in-memory, loopback only)
//	haven-idp init               write a production config with generated secrets
//	haven-idp serve [--env-file] run the server (default when no command is given)
//	haven-idp import-keycloak | import-users  migrate a Keycloak realm; users keep their passwords
//	haven-idp version | help
//
// `serve` is configured by environment (an env file fills in unset variables):
//
//	HAVEN_IDP_LISTEN             listen address (default :8081)
//	HAVEN_IDP_BASE_URL           public base URL, required; issuer = BASE/realms/{realm}
//	HAVEN_IDP_DSN                PostgreSQL DSN (required unless HAVEN_IDP_DEV=1)
//	HAVEN_IDP_DEV=1              allow the in-memory store (data lost on restart)
//	HAVEN_IDP_CSRF_KEY           shared secret for login-form CSRF (random if unset; set it for replicas)
//	HAVEN_IDP_TRUST_PROXY=1      take client IP from X-Forwarded-For
//	HAVEN_IDP_BOOTSTRAP_REALM    seed this realm on start (idempotent)
//	HAVEN_IDP_BOOTSTRAP_USER     admin username in that realm
//	HAVEN_IDP_BOOTSTRAP_PASSWORD admin password (or ..._PASSWORD_FILE)
//	HAVEN_IDP_CONSOLE_REDIRECTS  comma-separated redirect URIs for the haven-console client
//	HAVEN_IDP_ADMIN_REALM        realm whose tokens may call /admin/v1 (default: the bootstrap realm;
//	                             the Admin API is not mounted when both are empty)
//	HAVEN_IDP_ADMIN_CLIENT_SECRET secret of the "haven-admin" service-account client (or ..._SECRET_FILE);
//	                             created in the bootstrap realm, rotated on restart when changed
//	HAVEN_IDP_SECRET_KEY         32-byte key (base64 or hex; comma separated for rotation, newest first) that encrypts
//	                             TOTP seeds and upstream IdP secrets; _FILE variant supported; `haven-idp keygen` makes one
//	HAVEN_IDP_WEBAUTHN_RPID      passkey relying party id (default: host of HAVEN_IDP_BASE_URL); see docs/passkeys.md
//	HAVEN_IDP_WEBAUTHN_ORIGINS   comma-separated allowed passkey origins (default: HAVEN_IDP_BASE_URL's origin)
//	HAVEN_IDP_METRICS_LISTEN     serve Prometheus /metrics (only) on this separate address, e.g. :9100 (empty = off)
//	HAVEN_IDP_AUDIT              audit event sink: stdout, file:PATH or webhook:URL (empty = none)
//	HAVEN_IDP_AUDIT_WEBHOOK_SECRET HMAC secret signing webhook audit deliveries
//	OTEL_EXPORTER_OTLP_ENDPOINT  export request traces over OTLP/HTTP (also OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
//	                             OTEL_EXPORTER_OTLP_HEADERS, OTEL_SERVICE_NAME, OTEL_TRACES_SAMPLER_ARG ratio 0..1)
//	HAVEN_IDP_ENV_FILE           same as --env-file
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
)

const usage = `haven-idp: Haven's own identity server

Usage:
  haven-idp dev     [--port 8081] [--realm demo] [--redirect URL]... [--open]
  haven-idp init    [--dir .] [--base-url URL] [--realm platform] [--user admin] [--memory] [--force] [--print]
  haven-idp serve   [--env-file haven-idp.env]
  haven-idp validate -f FILE [--fail-on high]
  haven-idp plan     -f FILE [--prune] [--check] [--format text|json] [--dev | --url URL --admin-realm R]
  haven-idp apply    -f FILE [--prune] [--auto-approve] [--allow-findings] [--secrets-file PATH] [--dev | ...]
  haven-idp export   REALM [--dev | --url URL --admin-realm R]
  haven-idp import-keycloak -f EXPORT.json [--realm NAME] [--out-dir DIR] [--format text|json]
  haven-idp import-users    -f users.json --realm NAME [--dev | --url URL --admin-realm R]
  haven-idp keygen          print a new HAVEN_IDP_SECRET_KEY (TOTP seeds, upstream IdP secrets)
  haven-idp version

New here? Run "haven-idp dev".
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "init":
		err = cmdInit(args, os.Stdout)
	case "dev":
		err = cmdDev(args, os.Stdout)
	case "validate", "plan", "apply", "export":
		os.Exit(cmdConfig(cmd, args, osCfgIO()))
	case "import-keycloak", "import-users":
		os.Exit(cmdImport(cmd, args, osCfgIO()))
	case "keygen":
		// A fresh HAVEN_IDP_SECRET_KEY (encrypts TOTP seeds and upstream IdP secrets).
		fmt.Println(secretbox.GenerateKey())
	case "version":
		fmt.Println(version())
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "haven-idp: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "haven-idp:", err)
		os.Exit(1)
	}
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	envFile := fs.String("env-file", os.Getenv("HAVEN_IDP_ENV_FILE"), "load KEY=VALUE pairs for variables that are not already set")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\n\n%s", err, usage)
	}
	if *envFile != "" {
		if err := loadEnvFile(*envFile); err != nil {
			return err
		}
	}
	cfg, err := configFromEnv()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, log, cfg); err != nil {
		log.Error("haven-idp failed", "error", err.Error())
		return err
	}
	return nil
}
