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
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/backchannel"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/obs"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/safehttp"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/sessions"
	"github.com/zyvorai/haven/internal/idp/ssf"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/store/pgstore"
	"github.com/zyvorai/haven/internal/idp/upstream"
)

// Config is everything serve needs. `serve` builds it from the environment;
// `dev` builds it in code with safe local defaults.
type Config struct {
	Listen  string // default :8081
	BaseURL string // public base URL, required
	DSN     string // PostgreSQL DSN
	Memory  bool   // allow the in-memory store (data lost on restart)
	// PersistDir (dev only, needs Memory) keeps the in-memory store's state in
	// this directory across restarts (state.json, mode 0600).
	PersistDir string

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

	// Observability. MetricsListen serves only /metrics on a separate listener
	// (empty = disabled). MetricsOnMain also serves /metrics on the main
	// listener (used by `dev`, which is loopback only). AuditSpec is an audit
	// sink spec (stdout, file:PATH, webhook:URL; empty = none).
	MetricsListen      string
	MetricsOnMain      bool
	AuditSpec          string
	AuditWebhookSecret string
	// BreachFilter is the path of an operator-built bloom filter of breached
	// passwords (see docs/password-policy.md). Only consulted by realms whose
	// password policy contains notBreached(). Empty = no filter registered.
	BreachFilter string
	Observer     *obs.Observer // built by serve when nil

	// Email (verification and password reset). Mailer, when set, wins (dev
	// mode installs an in-memory outbox); otherwise SMTPHost enables SMTP.
	// With neither, the email flows are off.
	Mailer       mail.Sender
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	SMTPTLS      string // starttls (default) | implicit | none

	// SecretKey encrypts TOTP seeds and upstream IdP secrets: 32 bytes as base64
	// or 64 hex chars; several keys comma separated, newest first (rotation).
	// Empty in dev mode = a random per-process key; empty otherwise = the
	// features that need it are off.
	SecretKey string

	// WebAuthn overrides the passkey relying party (HAVEN_IDP_WEBAUTHN_RPID,
	// HAVEN_IDP_WEBAUTHN_ORIGINS comma separated). Empty = derive from BaseURL.
	WebAuthnRPID    string
	WebAuthnOrigins []string

	// Hooks (optional).
	PostBootstrap func(ctx context.Context, st core.Store, h core.PasswordHasher) error
	Mount         func(mux *http.ServeMux)
	OnReady       func(addr string) // called once the listener is bound
	// BackchannelAllowPrivate lifts the SSRF policy of back-channel logout
	// (loopback/private targets, http to localhost). Dev only.
	BackchannelAllowPrivate bool
	// FederationAllowPrivate lifts the SSRF policy for upstream identity
	// providers (loopback/private issuers, http to localhost). Dev only.
	FederationAllowPrivate bool

	OnMetricsReady func(addr string) // called once the metrics listener is bound
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

		MetricsListen:      os.Getenv("HAVEN_IDP_METRICS_LISTEN"),
		AuditSpec:          os.Getenv("HAVEN_IDP_AUDIT"),
		AuditWebhookSecret: os.Getenv("HAVEN_IDP_AUDIT_WEBHOOK_SECRET"),
		BreachFilter:       os.Getenv("HAVEN_IDP_BREACH_FILTER"),
		SecretKey:          os.Getenv("HAVEN_IDP_SECRET_KEY"),

		WebAuthnRPID:    os.Getenv("HAVEN_IDP_WEBAUTHN_RPID"),
		WebAuthnOrigins: splitList(os.Getenv("HAVEN_IDP_WEBAUTHN_ORIGINS")),
	}
	c.SMTPHost = os.Getenv("HAVEN_IDP_SMTP_HOST")
	c.SMTPUser = os.Getenv("HAVEN_IDP_SMTP_USER")
	c.SMTPPassword = os.Getenv("HAVEN_IDP_SMTP_PASSWORD")
	c.SMTPFrom = os.Getenv("HAVEN_IDP_SMTP_FROM")
	c.SMTPTLS = os.Getenv("HAVEN_IDP_SMTP_TLS")
	var err error
	if c.SecretKey, err = fromFile(c.SecretKey, os.Getenv("HAVEN_IDP_SECRET_KEY_FILE"), "secret key"); err != nil {
		return c, err
	}
	if v := os.Getenv("HAVEN_IDP_SMTP_PORT"); v != "" {
		if c.SMTPPort, err = strconv.Atoi(v); err != nil || c.SMTPPort < 1 || c.SMTPPort > 65535 {
			return c, fmt.Errorf("HAVEN_IDP_SMTP_PORT %q is not a port", v)
		}
	}
	if c.SMTPPassword, err = fromFile(c.SMTPPassword, os.Getenv("HAVEN_IDP_SMTP_PASSWORD_FILE"), "smtp password"); err != nil {
		return c, err
	}
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

// buildMailer returns the configured mail sender, or nil when email is off.
func buildMailer(cfg Config) (mail.Sender, error) {
	if cfg.Mailer != nil {
		return cfg.Mailer, nil
	}
	if cfg.SMTPHost == "" {
		if cfg.SMTPFrom != "" || cfg.SMTPUser != "" || cfg.SMTPPassword != "" {
			return nil, errors.New("HAVEN_IDP_SMTP_* is set but HAVEN_IDP_SMTP_HOST is empty: refusing to start with email half-configured")
		}
		return nil, nil
	}
	if cfg.SMTPFrom == "" {
		return nil, errors.New("HAVEN_IDP_SMTP_FROM is required when HAVEN_IDP_SMTP_HOST is set")
	}
	return mail.NewSMTP(mail.SMTPConfig{Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUser,
		Password: cfg.SMTPPassword, From: cfg.SMTPFrom, TLS: cfg.SMTPTLS})
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
	case cfg.Memory && cfg.PersistDir != "":
		ms, pers, err := memstore.OpenPersistent(cfg.PersistDir)
		if err != nil {
			return errors.New("open persisted dev state: " + err.Error())
		}
		log.Warn("dev state is persisted to disk (plain JSON incl. password hashes and signing keys; dev only)", "dir", pers.Dir())
		st = ms
		pctx, pcancel := context.WithCancel(context.Background())
		pdone := make(chan struct{})
		go func() {
			defer close(pdone)
			pers.Run(pctx, 2*time.Second, func(err error) { log.Error("persist dev state", "error", err.Error()) })
		}()
		defer func() { pcancel(); <-pdone }() // final save after the server has stopped
	case cfg.Memory:
		log.Warn("using the in-memory store: all data is lost on restart")
		st = memstore.New()
	default:
		return errors.New("HAVEN_IDP_DSN is required (set HAVEN_IDP_DEV=1 for the in-memory store, or run `haven-idp dev`)")
	}

	observer := cfg.Observer
	if observer == nil {
		reg := prometheus.NewRegistry()
		var sink obs.AuditSink
		if cfg.AuditSpec != "" {
			var err error
			sink, err = obs.NewAuditSink(cfg.AuditSpec, obs.AuditOptions{Logger: log, Registerer: reg, WebhookSecret: cfg.AuditWebhookSecret})
			if err != nil {
				return errors.New("audit sink: " + err.Error())
			}
		}
		var err error
		observer, err = obs.New(obs.Config{Registry: reg, Audit: sink, Version: version(), Logger: log})
		if err != nil {
			return errors.New("observability: " + err.Error())
		}
		if sink != nil {
			st = obs.AuditStore(st, sink)
		}
	}
	// Flush traces and the audit stream on every exit path.
	defer func() {
		fc, fcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer fcancel()
		if err := observer.Shutdown(fc); err != nil {
			log.Warn("observability shutdown", "error", err.Error())
		}
	}()

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

	if cfg.BreachFilter != "" {
		bf, err := password.LoadBreachFilter(cfg.BreachFilter)
		if err != nil {
			return err // a configured but unreadable filter must not silently weaken the policy
		}
		password.SetBreachFilter(bf)
		log.Info("breach filter loaded", "path", cfg.BreachFilter)
	}
	var box *secretbox.Box
	switch {
	case cfg.SecretKey != "":
		keys, err := secretbox.ParseKeys(cfg.SecretKey)
		if err != nil {
			return fmt.Errorf("HAVEN_IDP_SECRET_KEY: %w", err)
		}
		if box, err = secretbox.New(keys...); err != nil {
			return fmt.Errorf("HAVEN_IDP_SECRET_KEY: %w", err)
		}
	case cfg.Memory:
		// Dev only: the store is in memory too, so a per-process key loses nothing.
		k, _ := secretbox.ParseKey(secretbox.GenerateKey())
		box, _ = secretbox.New(k)
	default:
		log.Info("HAVEN_IDP_SECRET_KEY is not set: TOTP and federation are off (generate one with: haven-idp keygen)")
	}
	mailer, err := buildMailer(cfg)
	if err != nil {
		return err
	}
	var act *actions.Service
	if mailer != nil {
		act = &actions.Service{Store: st, Mailer: mailer, BaseURL: cfg.BaseURL}
		log.Info("email enabled: password reset and email verification are available")
	} else {
		log.Info("email not configured: password reset and email verification are off (set HAVEN_IDP_SMTP_HOST)")
	}
	notifier := backchannel.New(backchannel.Config{
		Store: st, Signer: signer, BaseURL: cfg.BaseURL, Logger: log, AllowPrivate: cfg.BackchannelAllowPrivate,
	})
	// Let in-flight back-channel logouts finish (bounded) on every exit path.
	defer func() {
		done := make(chan struct{})
		go func() { notifier.Drain(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			log.Warn("back-channel logout drain timed out")
		}
	}()
	// Shared Signals (SSF) transmitter: the decorator signals user/session
	// changes, the worker pushes the outbox. Off when the store has no SSFStore.
	if _, ok := core.StoreAs[core.SSFStore](st); ok {
		rawStore := st
		tx := &ssf.Transmitter{Builder: ssf.Builder{Signer: signer, BaseURL: cfg.BaseURL}, Store: rawStore, Logger: log, AllowPrivate: cfg.BackchannelAllowPrivate}
		st = ssf.Wrap(rawStore, tx)
		ssfw := &ssf.Worker{Store: rawStore, Box: box, Logger: log, AllowPrivate: cfg.BackchannelAllowPrivate}
		go ssfw.Run(ctx)
		defer func() {
			done := make(chan struct{})
			go func() { ssfw.Drain(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				log.Warn("shared signals drain timed out")
			}
		}()
		log.Info("shared signals transmitter enabled (SSF 1.0, push delivery)")
	}
	sess := &sessions.Service{Store: st, Notifier: notifier}
	oidcCfg := oidc.Config{
		Sessions: sess,
		Actions:  act,
		Store:    st, Signer: signer, Hasher: hasher, BaseURL: cfg.BaseURL, Logger: log,
		TrustProxy: cfg.TrustProxy,
		CSRFKey:    []byte(cfg.CSRFKey),
		SecretBox:  box,
		WebAuthn:   oidc.WebAuthnConfig{RPID: cfg.WebAuthnRPID, Origins: cfg.WebAuthnOrigins},
		DPoPNonce:  os.Getenv("HAVEN_IDP_DPOP_NONCE") == "1",
		Federation: upstream.NewManager(safehttp.Options{AllowPrivate: cfg.FederationAllowPrivate}, nil),
	}
	adminCfg := admin.Config{}

	mux := http.NewServeMux()
	adminRealm := cfg.AdminRealm
	if adminRealm == "" {
		adminRealm = cfg.BootstrapRealm
	}
	if adminRealm == "" {
		log.Warn("HAVEN_IDP_ADMIN_REALM and HAVEN_IDP_BOOTSTRAP_REALM are empty: the Admin API (/admin/v1) is NOT mounted")
	} else {
		adminCfg = admin.Config{
			Store: st, Signer: signer, Hasher: hasher, BaseURL: cfg.BaseURL,
			AdminRealm: adminRealm, Logger: log, Actions: act, SecretBox: box, Sessions: sess,
			Guard:                 guardConfigFromEnv(),
			AllowPrivateUpstreams: cfg.FederationAllowPrivate,
		}
		if err := adminCfg.Guard.Validate(time.Now()); err != nil {
			return err
		}
		withObs(observer, &oidcCfg, &adminCfg)
		mux.Handle("/admin/v1/", admin.New(adminCfg))
		log.Info("admin API mounted", "path", "/admin/v1", "realm", adminRealm)
	}
	withObs(observer, &oidcCfg, nil)
	oidcHandler := oidc.New(oidcCfg)
	mux.Handle("/realms/", oidcHandler)
	mux.Handle("/.well-known/ssf-configuration/", oidcHandler) // SSF 1.0 well-known path
	if cfg.MetricsOnMain {
		mux.Handle("/metrics", observer.Handler())
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		_, d, err := obs.PingStore(r.Context(), st)
		observer.SetStoreUp(err == nil, d)
		if err != nil {
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
		Handler:           observer.Middleware(mux),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}

	go purgeLoop(ctx, st, log)
	go obs.WatchStore(ctx, st, observer, 15*time.Second)

	var msrv *http.Server
	if cfg.MetricsListen != "" {
		mln, err := net.Listen("tcp", cfg.MetricsListen)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("metrics listen on %s: %w", cfg.MetricsListen, err)
		}
		mmux := http.NewServeMux()
		mmux.Handle("GET /metrics", observer.Handler())
		msrv = &http.Server{
			Handler:           mmux,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
			MaxHeaderBytes: 64 << 10,
		}
		go func() { _ = msrv.Serve(mln) }()
		log.Info("metrics listening", "addr", mln.Addr().String())
		if cfg.OnMetricsReady != nil {
			cfg.OnMetricsReady(mln.Addr().String())
		}
	}

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
	if msrv != nil {
		_ = msrv.Shutdown(shutdown)
	}
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
			// Time-boxed grants: audit newly expired ones, drop old ended rows.
			if n, err := core.PurgeGrants(ctx, st, now); err != nil {
				log.Warn("purge expired grants failed", "error", err.Error())
			} else if n > 0 {
				log.Info("purged expired grants", "count", n)
			}
			// Agent identities: drop long-ended credential rows.
			if as, ok := core.StoreAs[core.AgentStore](st); ok {
				if n, err := as.PurgeAgentCredentials(ctx, now); err != nil {
					log.Warn("purge agent credentials failed", "error", err.Error())
				} else if n > 0 {
					log.Info("purged agent credentials", "count", n)
				}
			}
			if ds, ok := core.StoreAs[core.DeviceStore](st); ok {
				if n, err := ds.PurgeExpiredDeviceCodes(ctx, now); err != nil {
					log.Warn("purge expired device codes failed", "error", err.Error())
				} else if n > 0 {
					log.Info("purged expired device codes", "count", n)
				}
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
