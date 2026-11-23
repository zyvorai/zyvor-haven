// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Command haven-idp is Haven's own OIDC identity server.
//
// Configuration (environment):
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
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/store/pgstore"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("haven-idp failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	base := strings.TrimRight(os.Getenv("HAVEN_IDP_BASE_URL"), "/")
	if base == "" {
		return errors.New("HAVEN_IDP_BASE_URL is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var st core.Store
	switch dsn := os.Getenv("HAVEN_IDP_DSN"); {
	case dsn != "":
		pg, err := pgstore.Open(ctx, dsn)
		if err != nil {
			return errors.New("open postgres store: " + err.Error())
		}
		defer pg.Close()
		st = pg
	case os.Getenv("HAVEN_IDP_DEV") == "1":
		log.Warn("using the in-memory store: all data is lost on restart")
		st = memstore.New()
	default:
		return errors.New("HAVEN_IDP_DSN is required (set HAVEN_IDP_DEV=1 for the in-memory store)")
	}

	hasher := password.New(password.DefaultParams)
	signer := keys.New(st, keys.Options{})

	adminPW := os.Getenv("HAVEN_IDP_BOOTSTRAP_PASSWORD")
	if f := os.Getenv("HAVEN_IDP_BOOTSTRAP_PASSWORD_FILE"); f != "" && adminPW == "" {
		b, err := os.ReadFile(f) // #nosec G304 -- operator-provided secret path
		if err != nil {
			return errors.New("read bootstrap password file: " + err.Error())
		}
		adminPW = strings.TrimSpace(string(b))
	}
	res, err := bootstrap.Run(ctx, st, hasher, signer, bootstrap.Options{
		Realm:         os.Getenv("HAVEN_IDP_BOOTSTRAP_REALM"),
		AdminUser:     os.Getenv("HAVEN_IDP_BOOTSTRAP_USER"),
		AdminPassword: adminPW,
		RedirectURIs:  splitList(os.Getenv("HAVEN_IDP_CONSOLE_REDIRECTS")),
	})
	if err != nil {
		return errors.New("bootstrap: " + err.Error())
	}
	if os.Getenv("HAVEN_IDP_BOOTSTRAP_REALM") != "" {
		log.Info("bootstrap complete", "realmCreated", res.RealmCreated, "userCreated", res.UserCreated, "clientCreated", res.ClientCreated)
	}

	provider := oidc.New(oidc.Config{
		Store: st, Signer: signer, Hasher: hasher, BaseURL: base, Logger: log,
		TrustProxy: os.Getenv("HAVEN_IDP_TRUST_PROXY") == "1",
		CSRFKey:    []byte(os.Getenv("HAVEN_IDP_CSRF_KEY")),
	})

	mux := http.NewServeMux()
	mux.Handle("/realms/", provider)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		c, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if _, err := st.ListRealms(c); err != nil {
			http.Error(w, "store unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	addr := os.Getenv("HAVEN_IDP_LISTEN")
	if addr == "" {
		addr = ":8081"
	}
	srv := &http.Server{
		Addr: addr, Handler: mux,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}

	go purgeLoop(ctx, st, log)

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("haven-idp listening", "addr", addr, "baseURL", base)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

func purgeLoop(ctx context.Context, st core.Store, log *slog.Logger) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n, err := st.PurgeExpired(ctx, now); err != nil {
				log.Warn("purge expired failed", "error", err.Error())
			} else if n > 0 {
				log.Info("purged expired rows", "count", n)
			}
		}
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
