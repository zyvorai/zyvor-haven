// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp/safehttp"
)

// Limits and cache lifetimes.
const (
	CacheTTL        = 10 * time.Minute // discovery document and JWKS
	jwksRefetchGap  = 30 * time.Second // minimum gap between forced JWKS refreshes
	maxCacheEntries = 256
	maxJWKSKeys     = 64
	maxDocBody      = 256 << 10 // discovery and JWKS
	maxTokenBody    = 256 << 10 // token endpoint response
)

// Error is an upstream failure. Kind is a stable, secret-free label for logs
// and metrics; the wrapped error is for tests and never shown to end users.
type Error struct {
	Kind string
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "upstream: " + e.Kind
	}
	return "upstream: " + e.Kind + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

func fail(kind string, err error) *Error { return &Error{Kind: kind, Err: err} }

// Discovery is the subset of the OIDC discovery document that is used.
type Discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

type cachedDisco struct {
	d       *Discovery
	fetched time.Time
}

type cachedJWKS struct {
	keys     []jwk
	fetched  time.Time
	forcedAt time.Time
}

// Manager performs the upstream calls with a shared SSRF-safe client and
// caches. It is safe for concurrent use.
type Manager struct {
	http         *safehttp.Client
	allowPrivate bool
	now          func() time.Time

	mu    sync.Mutex
	disco map[string]cachedDisco
	jwks  map[string]*cachedJWKS
}

// NewManager builds a Manager. now defaults to time.Now.
func NewManager(o safehttp.Options, now func() time.Time) *Manager {
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.MaxBody <= 0 {
		o.MaxBody = maxDocBody
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{http: safehttp.New(o), allowPrivate: o.AllowPrivate, now: now,
		disco: map[string]cachedDisco{}, jwks: map[string]*cachedJWKS{}}
}

// AllowPrivate reports whether the manager runs without the IP policy (dev).
func (m *Manager) AllowPrivate() bool { return m.allowPrivate }

// SeedDiscovery installs a discovery document for a URL without fetching it.
// Tests only: it lets a test point endpoints at addresses the IP policy refuses.
func (m *Manager) SeedDiscovery(discoveryURL string, d Discovery) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dd := d
	m.disco[discoveryURL] = cachedDisco{d: &dd, fetched: m.now()}
}

func (m *Manager) get(ctx context.Context, raw string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, fail("bad_request", nil)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "haven-idp-federation")
	st, body, err := m.http.Fetch(req)
	if err != nil {
		return nil, netErr(err)
	}
	if st != http.StatusOK {
		return nil, fail("http_status", fmt.Errorf("status %d", st))
	}
	return body, nil
}

func netErr(err error) *Error {
	switch {
	case safehttp.IsBlocked(err):
		return fail("blocked_address", err)
	case errors.Is(err, safehttp.ErrTooLarge):
		return fail("too_large", err)
	case errors.Is(err, context.DeadlineExceeded):
		return fail("timeout", err)
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		return fail("timeout", err)
	}
	return fail("network", err)
}

// Discover returns the provider's discovery document, from cache when fresh.
// The document's issuer must equal the configured issuer exactly, and every
// endpoint must be an acceptable URL (https; http only on loopback in dev).
func (m *Manager) Discover(ctx context.Context, s Spec) (*Discovery, error) {
	m.mu.Lock()
	c, ok := m.disco[s.DiscoveryURL]
	m.mu.Unlock()
	if ok && m.now().Sub(c.fetched) < CacheTTL {
		return c.d, nil
	}
	if _, err := safehttp.ValidateURL(s.DiscoveryURL, m.allowPrivate, "discovery url", maxURL); err != nil {
		return nil, fail("bad_url", err)
	}
	body, err := m.get(ctx, s.DiscoveryURL)
	if err != nil {
		return nil, err
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fail("bad_discovery", nil)
	}
	if d.Issuer != s.Issuer {
		return nil, fail("issuer_mismatch", errors.New("discovery issuer differs from the configured issuer"))
	}
	for _, e := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if _, err := safehttp.ValidateURL(e, m.allowPrivate, "endpoint", maxURL); err != nil {
			return nil, fail("bad_discovery", err)
		}
	}
	m.mu.Lock()
	if len(m.disco) >= maxCacheEntries {
		m.disco = map[string]cachedDisco{}
	}
	m.disco[s.DiscoveryURL] = cachedDisco{d: &d, fetched: m.now()}
	m.mu.Unlock()
	return &d, nil
}

// AuthURL builds the upstream authorization request (code flow, PKCE S256,
// nonce, state).
func AuthURL(s Spec, d *Discovery, redirectURI, state, nonce, challenge string) (string, error) {
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", s.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(s.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if s.HostedDomain != "" {
		q.Set("hd", s.HostedDomain)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange trades the authorization code for the raw ID token. secret may be
// empty (public client with PKCE). The client authenticates with
// client_secret_basic unless the provider only lists client_secret_post.
func (m *Manager) Exchange(ctx context.Context, s Spec, d *Discovery, secret, code, redirectURI, verifier string) (string, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}
	basic := false
	if secret != "" {
		basic = len(d.TokenAuthMethods) == 0 || containsStr(d.TokenAuthMethods, "client_secret_basic")
		if !basic && !containsStr(d.TokenAuthMethods, "client_secret_post") {
			basic = true // an unknown list: use the default method
		}
		if !basic {
			form.Set("client_id", s.ClientID)
			form.Set("client_secret", secret)
		}
	} else {
		form.Set("client_id", s.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fail("bad_request", nil)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "haven-idp-federation")
	if basic {
		req.SetBasicAuth(url.QueryEscape(s.ClientID), url.QueryEscape(secret))
	}
	st, body, err := m.http.Fetch(req)
	if err != nil {
		return "", netErr(err)
	}
	if st != http.StatusOK {
		return "", fail("token_rejected", fmt.Errorf("status %d", st))
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.IDToken == "" {
		return "", fail("no_id_token", nil)
	}
	return tr.IDToken, nil
}

func containsStr(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// ---- JWKS ----

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`

	pub any // *rsa.PublicKey | *ecdsa.PublicKey
}

func (k *jwk) parse() bool {
	if k.Use != "" && k.Use != "sig" {
		return false
	}
	switch k.Kty {
	case "RSA":
		n, e := b64Int(k.N), b64Int(k.E)
		if n == nil || e == nil || n.BitLen() < 2048 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return false
		}
		k.pub = &rsa.PublicKey{N: n, E: int(e.Int64())}
	case "EC":
		if k.Crv != "P-256" {
			return false
		}
		x, y := b64Int(k.X), b64Int(k.Y)
		if x == nil || y == nil || !elliptic.P256().IsOnCurve(x, y) {
			return false
		}
		k.pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	default:
		return false
	}
	return true
}

func b64Int(s string) *big.Int {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(b) == 0 || len(b) > 1024 {
		return nil
	}
	return new(big.Int).SetBytes(b)
}

// keys returns the provider's usable keys. force refetches (unknown kid),
// at most once per jwksRefetchGap.
func (m *Manager) keys(ctx context.Context, uri string, force bool) ([]jwk, error) {
	m.mu.Lock()
	c := m.jwks[uri]
	fresh := c != nil && m.now().Sub(c.fetched) < CacheTTL
	var lastForced time.Time
	if c != nil {
		lastForced = c.forcedAt
	}
	canForce := lastForced.IsZero() || m.now().Sub(lastForced) >= jwksRefetchGap
	if fresh && !(force && canForce) {
		keys := c.keys
		m.mu.Unlock()
		return keys, nil
	}
	m.mu.Unlock()

	body, err := m.get(ctx, uri)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fail("bad_jwks", nil)
	}
	if len(doc.Keys) > maxJWKSKeys {
		doc.Keys = doc.Keys[:maxJWKSKeys]
	}
	var ok []jwk
	for _, k := range doc.Keys {
		if k.parse() {
			ok = append(ok, k)
		}
	}
	if len(ok) == 0 {
		return nil, fail("bad_jwks", errors.New("no usable keys"))
	}
	if force {
		lastForced = m.now()
	}
	m.mu.Lock()
	if len(m.jwks) >= maxCacheEntries {
		m.jwks = map[string]*cachedJWKS{}
	}
	m.jwks[uri] = &cachedJWKS{keys: ok, fetched: m.now(), forcedAt: lastForced}
	m.mu.Unlock()
	return ok, nil
}
