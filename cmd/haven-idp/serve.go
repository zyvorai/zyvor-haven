// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/store/pgstore"
)

// Config is everything serve needs. `serve` builds it from the environment;
// `dev` builds it in code with safe local defaults.
type Config struct {
	Listen  string // default :8081
	BaseURL string // public base URL, required
	DSN     string // PostgreSQL DSN
	Memory  bool   // allow the in-memory store (data lost on restart)

	CSRFKey    string
	TrustProxy bool

	BootstrapRealm    string
	BootstrapUser     string
	BootstrapPassword string
	ConsoleRedirects  []string
	ConsoleClientID   string // default haven-console
	AdminRealm        string // default: BootstrapRealm
	AdminClientSecret string

	PasswordParams password.Params // zero = production defaults

	// Hooks (optional).
	PostBootstrap func(ctx context.Context, st core.Store, h core.PasswordHasher) error
	Mount         func(mux *http.ServeMux)
	OnReady       func(addr string) // called once the listener is bound
}

// configFromEnv reads the HAVEN_IDP_* environment (see the usage text).
func configFromEnv() (Config, error) {
	c := Config{
		Listen:            os.Getenv("HAVEN_IDP_LISTEN"),
		BaseURL:           strings.TrimRight(os.Getenv("HAVEN_IDP_BASE_URL"), "/"),
		DSN:               os.Getenv("HAVEN_IDP_DSN"),
		Memory:            os.Getenv("HAVEN_IDP_DEV") == "1",
		CSRFKey:           os.Getenv("HAVEN_IDP_CSRF_KEY"),
		TrustProxy:        os.Getenv("HAVEN_IDP_TRUST_PROXY") == "1",
		BootstrapRealm:    os.Getenv("HAVEN_IDP_BOOTSTRAP_REALM"),
		BootstrapUser:     os.Getenv("HAVEN_IDP_BOOTSTRAP_USER"),
		ConsoleRedirects:  splitList(os.Getenv("HAVEN_IDP_CONSOLE_REDIRECTS")),
		AdminRealm:        os.Getenv("HAVEN_IDP_ADMIN_REALM"),
		BootstrapPassword: os.Getenv("HAVEN_IDP_BOOTSTRAP_PASSWORD"),
		AdminClientSecret: os.Getenv("HAVEN_IDP_ADMIN_CLIENT_SECRET"),
	}
	var err error
	if c.BootstrapPassword, err = fromFile(c.BootstrapPassword, os.Getenv("HAVEN_IDP_BOOTSTRAP_PASSWORD_FILE"), "bootstrap password"); err != nil {
		return c, err
	}
	if c.AdminClientSecret, err = fromFile(c.AdminClientSecret, os.Getenv("HAVEN_IDP_ADMIN_CLIENT_SECRET_FILE"), "admin client secret"); err != nil {
		return c, err
	}
	return c, nil
}

// fromFile returns val, or the trimmed contents of path when val is empty.
func fromFile(val, path, what string) (string, error) {
	if val != "" || path == "" {
		return val, nil
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-provided secret path
	if err != nil {
		return "", fmt.Errorf("read %s file: %w", what, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// serve runs the identity server until ctx is cancelled.
func serve(ctx context.Context, log *slog.Logger, cfg Config) error {
	if cfg.BaseURL == "" {
		return errors.New("HAVEN_IDP_BASE_URL is required")
	}
	var st core.Store
	switch {
	case cfg.DSN != "":
		pg, err := pgstore.Open(ctx, cfg.DSN)
		if err != nil {
			return errors.New("open postgres store: " + err.Error())
		}
		defer pg.Close()
		st = pg
	case cfg.Memory:
		log.Warn("using the in-memory store: all data is lost on restart")
		st = memstore.New()
	default:
		return errors.New("HAVEN_IDP_DSN is required (set HAVEN_IDP_DEV=1 for the in-memory store, or run `haven-idp dev`)")
	}

	params := cfg.PasswordParams
	if params == (password.Params{}) {
		params = password.DefaultParams
	}
	hasher := password.New(params)
	signer := keys.New(st, keys.Options{})

	res, err := bootstrap.Run(ctx, st, hasher, signer, bootstrap.Options{
		Realm:             cfg.BootstrapRealm,
		AdminUser:         cfg.BootstrapUser,
		AdminPassword:     cfg.BootstrapPassword,
		ConsoleClient:     cfg.ConsoleClientID,
		RedirectURIs:      cfg.ConsoleRedirects,
		AdminClientSecret: cfg.AdminClientSecret,
	})
	if err != nil {
		return errors.New("bootstrap: " + err.Error())
	}
	if cfg.BootstrapRealm != "" {
		log.Info("bootstrap complete", "realmCreated", res.RealmCreated, "userCreated", res.UserCreated, "clientCreated", res.ClientCreated)
	}
	if cfg.PostBootstrap != nil {
		if err := cfg.PostBootstrap(ctx, st, hasher); err != nil {
			return errors.New("post-bootstrap: " + err.Error())
		}
	}

	provider := oidc.New(oidc.Config{
		Store: st, Signer: signer, Hasher: hasher, BaseURL: cfg.BaseURL, Logger: log,
		TrustProxy: cfg.TrustProxy,
		CSRFKey:    []byte(cfg.CSRFKey),
	})

	mux := http.NewServeMux()
	mux.Handle("/realms/", provider)
	adminRealm := cfg.AdminRealm
	if adminRealm == "" {
		adminRealm = cfg.BootstrapRealm
	}
	if adminRealm == "" {
		log.Warn("HAVEN_IDP_ADMIN_REALM and HAVEN_IDP_BOOTSTRAP_REALM are empty: the Admin API (/admin/v1) is NOT mounted")
	} else {
		mux.Handle("/admin/v1/", admin.New(admin.Config{
			Store: st, Signer: signer, Hasher: hasher, BaseURL: cfg.BaseURL,
			AdminRealm: adminRealm, Logger: log,
		}))
		log.Info("admin API mounted", "path", "/admin/v1", "realm", adminRealm)
	}
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
	if cfg.Mount != nil {
		cfg.Mount(mux)
	}

	addr := cfg.Listen
	if addr == "" {
		addr = ":8081"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w (is another process using that port?)", addr, err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}

	go purgeLoop(ctx, st, log)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("haven-idp listening", "addr", ln.Addr().String(), "baseURL", cfg.BaseURL)
	if cfg.OnReady != nil {
		cfg.OnReady(ln.Addr().String())
	}

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
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
