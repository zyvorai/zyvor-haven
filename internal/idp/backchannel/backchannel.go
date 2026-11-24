// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package backchannel delivers OIDC Back-Channel Logout 1.0 notifications.
//
// The target URL is admin-configured but the IdP runs inside a cluster, so
// every request is treated as a potential SSRF: no redirects, no proxy from
// the environment, and the destination IP is checked at dial time (after DNS
// resolution, so rebinding cannot bypass it).
//
// Delivery is asynchronous and best effort. Notify never blocks or fails the
// logout that triggered it.
package backchannel

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
)

const (
	eventURI     = "http://schemas.openid.net/event/backchannel-logout"
	maxURILen    = 2048
	tokenTTL     = 2 * time.Minute
	maxDrainBody = 4 << 10
)

// Config configures a Notifier.
type Config struct {
	Store   core.Store
	Signer  core.Signer
	BaseURL string // public issuer base, e.g. https://idp.example
	Logger  *slog.Logger
	Clock   func() time.Time
	// AllowPrivate lifts the IP policy and permits http to loopback. Dev only.
	AllowPrivate  bool
	Timeout       time.Duration // per attempt; default 5s
	Retries       int           // extra attempts after the first; default 2 (negative = 0)
	Backoff       time.Duration // base backoff, doubled per retry; default 200ms
	MaxConcurrent int           // default 8
	// RootCAs overrides the trust roots. Tests only.
	RootCAs *x509.CertPool
}

// Notifier implements sessions.Notifier.
type Notifier struct {
	cfg    Config
	client *http.Client
	sem    chan struct{}
	wg     sync.WaitGroup
}

// New builds a Notifier, applying defaults.
func New(cfg Config) *Notifier {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Retries == 0 {
		cfg.Retries = 2
	} else if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 200 * time.Millisecond
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 8
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	n := &Notifier{cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrent)}
	n.client = newClient(cfg)
	return n
}

// errBlocked marks a destination refused by the IP policy.
var errBlocked = safehttp.ErrBlocked

func newClient(cfg Config) *http.Client {
	return safehttp.New(safehttp.Options{AllowPrivate: cfg.AllowPrivate, RootCAs: cfg.RootCAs, Timeout: cfg.Timeout}).HTTP
}

// blockedIP reports whether a destination address is off limits.
func blockedIP(a netip.Addr) bool { return safehttp.BlockedIP(a) }

// ValidateURI checks a back-channel logout URI syntactically: length, scheme,
// host, no userinfo, no fragment. The IP policy is enforced at dial time.
// With allowPrivate, http is accepted for localhost and loopback IPs.
func ValidateURI(raw string, allowPrivate bool) error {
	if raw == "" || len(raw) > maxURILen {
		return errors.New("backchannel_logout_uri must be 1-2048 characters")
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f {
			return errors.New("backchannel_logout_uri contains control characters or spaces")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("backchannel_logout_uri is not a valid URL")
	}
	if u.User != nil {
		return errors.New("backchannel_logout_uri must not contain credentials")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("backchannel_logout_uri must not contain a fragment")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("backchannel_logout_uri needs a host")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowPrivate || !isLoopbackHost(host) {
			return errors.New("backchannel_logout_uri must use https")
		}
	default:
		return errors.New("backchannel_logout_uri must use https")
	}
	return nil
}

func isLoopbackHost(h string) bool { return safehttp.IsLoopbackHost(h) }

// Drain waits for in-flight deliveries (tests, graceful shutdown).
func (n *Notifier) Drain() { n.wg.Wait() }

// Notify implements sessions.Notifier. It returns immediately; delivery runs
// in the background under its own timeouts.
func (n *Notifier) Notify(_ context.Context, realm string, s core.Session) {
	seen := map[string]bool{}
	for _, id := range s.Clients {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		n.wg.Add(1)
		go func(clientID string) {
			defer n.wg.Done()
			n.sem <- struct{}{}
			defer func() { <-n.sem }()
			defer func() {
				if r := recover(); r != nil {
					n.cfg.Logger.Error("backchannel: panic", "realm", realm, "client", clientID)
				}
			}()
			n.deliver(realm, clientID, s)
		}(id)
	}
}

func (n *Notifier) deliver(realm, clientID string, s core.Session) {
	ctx, cancel := context.WithTimeout(context.Background(), n.cfg.Timeout)
	cl, err := n.cfg.Store.GetClientByClientID(ctx, realm, clientID)
	cancel()
	if err != nil || !cl.Enabled || cl.BackchannelLogoutURI == "" {
		return
	}
	if err := ValidateURI(cl.BackchannelLogoutURI, n.cfg.AllowPrivate); err != nil {
		n.cfg.Logger.Warn("backchannel: invalid logout uri", "realm", realm, "client", clientID)
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), n.cfg.Timeout)
	tok, err := n.logoutToken(ctx, realm, clientID, s)
	cancel()
	if err != nil {
		n.cfg.Logger.Warn("backchannel: sign failed", "realm", realm, "client", clientID)
		return
	}
	body := url.Values{"logout_token": {tok}}.Encode()
	attempts := n.cfg.Retries + 1
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(n.cfg.Backoff << (i - 1))
		}
		outcome, retry := n.post(cl.BackchannelLogoutURI, body)
		if outcome == "ok" {
			n.cfg.Logger.Info("backchannel: delivered", "realm", realm, "client", clientID, "attempt", i+1)
			return
		}
		if !retry || i == attempts-1 {
			n.cfg.Logger.Warn("backchannel: failed", "realm", realm, "client", clientID, "outcome", outcome, "attempt", i+1)
			return
		}
		n.cfg.Logger.Info("backchannel: retrying", "realm", realm, "client", clientID, "outcome", outcome, "attempt", i+1)
	}
}

// post makes one attempt and returns an outcome label (never carrying URL or
// body text) and whether the failure is worth retrying.
func (n *Notifier) post(target, body string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), n.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return "bad_request", false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "haven-idp-backchannel-logout")
	resp, err := n.client.Do(req)
	if err != nil {
		if errors.Is(err, errBlocked) {
			return "blocked_address", false
		}
		return "network_error", true
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.CopyN(io.Discard, resp.Body, maxDrainBody)
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent:
		return "ok", false
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Sprintf("status_%d", resp.StatusCode), true
	default:
		return fmt.Sprintf("status_%d", resp.StatusCode), false
	}
}

func (n *Notifier) logoutToken(ctx context.Context, realm, clientID string, s core.Session) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	iat := n.cfg.Clock()
	claims := core.Claims{
		"iss":    n.cfg.BaseURL + "/realms/" + realm,
		"aud":    clientID,
		"iat":    iat.Unix(),
		"exp":    iat.Add(tokenTTL).Unix(),
		"jti":    base64.RawURLEncoding.EncodeToString(b),
		"sub":    s.UserID,
		"sid":    s.ID,
		"events": map[string]any{eventURI: map[string]any{}},
	}
	return n.cfg.Signer.Sign(ctx, realm, claims)
}
