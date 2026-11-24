// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package oidc serves the OpenID Connect provider endpoints of haven-idp for
// every realm, under Keycloak-compatible paths.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/obs"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/sessions"
	"github.com/zyvorai/haven/internal/idp/upstream"
)

const (
	maxBody        = 64 << 10
	defaultCodeTTL = 60 * time.Second
	defaultAccess  = 5 * time.Minute
	defaultRefresh = 30 * 24 * time.Hour
	lockThreshold  = 5
	lockDuration   = 15 * time.Minute
	csrfTTL        = 15 * time.Minute
	oidcPath       = "/protocol/openid-connect"
)

// Config configures a Provider.
type Config struct {
	Store   core.Store
	Signer  core.Signer
	Hasher  core.PasswordHasher
	BaseURL string // public base URL; issuer = BaseURL/realms/{realm}
	Clock   func() time.Time
	Logger  *slog.Logger
	CodeTTL time.Duration // default 60s
	// TrustProxy makes the client IP come from X-Forwarded-For (last entry).
	// Leave false unless a trusted proxy sets the header.
	TrustProxy bool
	// CSRFKey keys the login-form CSRF tokens. Random per process if empty;
	// set it when several replicas serve the same login form.
	CSRFKey []byte
	// Actions enables self-service email verification and password reset.
	// Nil (or a Service without a Mailer) disables both: the pages answer 404
	// and the login page shows no "Forgot password" link.
	Actions *actions.Service
	// SecretBox encrypts secrets that must be read back (TOTP seeds, upstream
	// IdP client secrets). Nil disables the features that need it (they must
	// fail closed and say why), it never falls back to storing plaintext.
	SecretBox *secretbox.Box
	// Sessions ends SSO sessions (logout, admin revoke). Built from Store with
	// no notifier when nil; set it to enable back-channel logout.
	Sessions *sessions.Service
	// Obs receives protocol and security signals (enums and realm names
	// only). Nil records nothing.
	Obs obs.Recorder
	// Federation performs the upstream OIDC calls of identity brokering. Nil
	// builds one with the default SSRF policy (federation.go); dev and tests
	// pass one with AllowPrivate / test RootCAs.
	Federation *upstream.Manager
}

// Provider is the http.Handler for all realms.
type Provider struct {
	cfg    Config
	base   string
	secure bool
	mux    *http.ServeMux

	csrfKey []byte

	dummyOnce sync.Once
	dummyHash string

	bg sync.WaitGroup // in-flight background emails

	mu       sync.Mutex
	ensured  map[string]bool
	codeFams map[string]codeFam // code hash -> refresh family issued from it
}

type codeFam struct {
	family  string
	expires time.Time
}

// New builds the provider. It panics if Store, Signer, Hasher or BaseURL are
// missing, since that is a wiring bug.
func New(cfg Config) *Provider {
	if cfg.Store == nil || cfg.Signer == nil || cfg.Hasher == nil || cfg.BaseURL == "" {
		panic("oidc: Store, Signer, Hasher and BaseURL are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	if cfg.Obs == nil {
		cfg.Obs = obs.Nop{}
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = defaultCodeTTL
	}
	p := &Provider{
		cfg:      cfg,
		base:     strings.TrimRight(cfg.BaseURL, "/"),
		secure:   strings.HasPrefix(strings.ToLower(cfg.BaseURL), "https://"),
		mux:      http.NewServeMux(),
		csrfKey:  cfg.CSRFKey,
		ensured:  map[string]bool{},
		codeFams: map[string]codeFam{},
	}
	if len(p.csrfKey) == 0 {
		p.csrfKey = randBytes(32)
	}
	r := "/realms/{realm}"
	defer func() {
		for _, f := range featureRoutes {
			f(p, p.mux)
		}
	}()
	p.mux.HandleFunc("GET "+r+"/.well-known/openid-configuration", p.discovery)
	p.mux.HandleFunc("GET "+r+oidcPath+"/certs", p.certs)
	p.mux.HandleFunc("GET "+r+oidcPath+"/auth", p.authorize)
	p.mux.HandleFunc("POST "+r+oidcPath+"/auth", p.authorize)
	p.mux.HandleFunc("POST "+r+oidcPath+"/token", p.token)
	p.mux.HandleFunc("GET "+r+oidcPath+"/userinfo", p.userinfo)
	p.mux.HandleFunc("POST "+r+oidcPath+"/userinfo", p.userinfo)
	p.mux.HandleFunc("GET "+r+oidcPath+"/logout", p.logout)
	p.mux.HandleFunc("POST "+r+oidcPath+"/logout", p.logout)
	p.mux.HandleFunc("POST "+r+oidcPath+"/revoke", p.revoke)
	p.mux.HandleFunc("POST "+r+oidcPath+"/token/introspect", p.introspect)
	la := r + "/login-actions"
	p.mux.HandleFunc("GET "+la+"/forgot-password", p.forgotPassword)
	p.mux.HandleFunc("POST "+la+"/forgot-password", p.forgotPassword)
	p.mux.HandleFunc("GET "+la+"/reset-password", p.resetPassword)
	p.mux.HandleFunc("POST "+la+"/reset-password", p.resetPassword)
	p.mux.HandleFunc("GET "+la+"/verify-email", p.verifyEmail)
	p.mux.HandleFunc("POST "+la+"/verify-email", p.verifyEmail)
	return p
}

type discard struct{}

func (discard) Write(b []byte) (int, error) { return len(b), nil }

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	p.mux.ServeHTTP(w, r)
}

// HashSecret returns the sha256 hex digest used to store client secrets and
// refresh tokens.
func HashSecret(secret string) string {
	s := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(s[:])
}

func (p *Provider) sessions() *sessions.Service {
	if p.cfg.Sessions != nil {
		return p.cfg.Sessions
	}
	return &sessions.Service{Store: p.cfg.Store}
}

func (p *Provider) now() time.Time { return p.cfg.Clock() }

func (p *Provider) issuer(realm string) string { return p.base + "/realms/" + realm }

func (p *Provider) endpoint(realm, name string) string {
	return p.issuer(realm) + oidcPath + "/" + name
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("oidc: entropy source failed: " + err.Error())
	}
	return b
}

func randToken(n int) string { return base64.RawURLEncoding.EncodeToString(randBytes(n)) }

// secretEq compares a presented secret to a stored sha256 hex hash in
// constant time. An empty stored hash never matches.
func secretEq(presented, storedHash string) bool {
	h := HashSecret(presented)
	ok := subtle.ConstantTimeCompare([]byte(h), []byte(storedHash))
	return ok == 1 && storedHash != ""
}

func (p *Provider) realm(ctx context.Context, name string) (core.Realm, bool) {
	rl, err := p.cfg.Store.GetRealm(ctx, name)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load realm", "realm", name, "err", err)
		}
		return core.Realm{}, false
	}
	return rl, rl.Enabled
}

func (p *Provider) ensureKey(ctx context.Context, realm string) error {
	p.mu.Lock()
	done := p.ensured[realm]
	p.mu.Unlock()
	if done {
		return nil
	}
	if err := p.cfg.Signer.EnsureKey(ctx, realm); err != nil {
		return err
	}
	p.mu.Lock()
	p.ensured[realm] = true
	p.mu.Unlock()
	return nil
}

func (p *Provider) clientIP(r *http.Request) string {
	if p.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (p *Provider) event(ctx context.Context, rl core.Realm, typ, userID, clientID, ip, detail string) {
	if !rl.AuthEventsLogged {
		return
	}
	err := p.cfg.Store.AppendEvent(ctx, core.Event{Time: p.now(), Realm: rl.Name, Type: typ,
		UserID: userID, ClientID: clientID, IP: ip, Detail: detail})
	if err != nil {
		p.cfg.Logger.Error("oidc: append event", "err", err)
	}
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	if _, ok := p.realm(r.Context(), name); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	doc := map[string]any{
		"issuer":                                        p.issuer(name),
		"authorization_endpoint":                        p.endpoint(name, "auth"),
		"token_endpoint":                                p.endpoint(name, "token"),
		"userinfo_endpoint":                             p.endpoint(name, "userinfo"),
		"jwks_uri":                                      p.endpoint(name, "certs"),
		"end_session_endpoint":                          p.endpoint(name, "logout"),
		"revocation_endpoint":                           p.endpoint(name, "revoke"),
		"introspection_endpoint":                        p.endpoint(name, "token/introspect"),
		"response_types_supported":                      []string{"code"},
		"response_modes_supported":                      []string{"query"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"ES256"},
		"scopes_supported":                              []string{"openid", "profile", "email", "roles", "offline_access"},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":              []string{"S256"},
		"prompt_values_supported":                       []string{"none", "login"},
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
			"preferred_username", "email", "email_verified", "name", "given_name", "family_name", "realm_access", "sid"},
		"backchannel_logout_supported":                   true,
		"backchannel_logout_session_supported":           true,
		"authorization_response_iss_parameter_supported": true,
	}
	for _, h := range discoveryHooks {
		h(p, name, doc)
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (p *Provider) certs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	if _, ok := p.realm(r.Context(), name); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	if err := p.ensureKey(r.Context(), name); err != nil {
		p.cfg.Logger.Error("oidc: ensure key", "realm", name, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	b, err := p.cfg.Signer.JWKS(r.Context(), name)
	if err != nil {
		p.cfg.Logger.Error("oidc: jwks", "realm", name, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
