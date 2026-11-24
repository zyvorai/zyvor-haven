// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package safehttp is the HTTP client for every outbound request whose target
// an administrator (or a remote document, such as an OIDC discovery document)
// chooses: back-channel logout, upstream identity providers.
//
// The IdP runs inside a cluster, so each request is treated as a potential
// SSRF: no redirects, no proxy from the environment, timeouts everywhere,
// bounded response bodies, and the destination IP is checked at dial time
// (after DNS resolution, so rebinding cannot bypass it).
package safehttp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// DefaultTimeout bounds one request when Options.Timeout is zero.
const DefaultTimeout = 5 * time.Second

// DefaultMaxBody bounds a response body when Options.MaxBody is zero.
const DefaultMaxBody = 1 << 20

// ErrBlocked marks a destination refused by the IP policy.
var ErrBlocked = errors.New("safehttp: destination address not allowed")

// ErrTooLarge marks a response body over the size limit.
var ErrTooLarge = errors.New("safehttp: response too large")

// Options configures a Client.
type Options struct {
	// AllowPrivate lifts the IP policy and permits http to loopback. Dev only.
	AllowPrivate bool
	// RootCAs overrides the trust roots. Tests only.
	RootCAs *x509.CertPool
	// MaxBody caps the bytes Fetch returns (default 1 MiB).
	MaxBody int64
	// Timeout covers one whole request (default 5s).
	Timeout time.Duration
}

// Client is an http.Client with the SSRF policy plus a body limit.
type Client struct {
	HTTP         *http.Client
	MaxBody      int64
	AllowPrivate bool
}

// New builds a Client from opts.
func New(o Options) *Client {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	d := &net.Dialer{Timeout: o.Timeout}
	if !o.AllowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || BlockedIP(ap.Addr()) {
				return ErrBlocked
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy:                 nil, // never from the environment
		DialContext:           d.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		TLSHandshakeTimeout:   o.Timeout,
		ResponseHeaderTimeout: o.Timeout,
		DisableKeepAlives:     true,
	}
	return &Client{
		HTTP: &http.Client{
			Transport:     tr,
			Timeout:       o.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		MaxBody:      o.MaxBody,
		AllowPrivate: o.AllowPrivate,
	}
}

// Fetch sends req and returns the status and at most MaxBody bytes of body. A
// larger body fails with ErrTooLarge instead of being truncated silently.
// Redirects are never followed (the 3xx status is returned).
func (c *Client) Fetch(req *http.Request) (status int, body []byte, err error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, c.MaxBody+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if int64(len(body)) > c.MaxBody {
		return resp.StatusCode, nil, ErrTooLarge
	}
	return resp.StatusCode, body, nil
}

// IsBlocked reports whether err came from the IP policy.
func IsBlocked(err error) bool { return errors.Is(err, ErrBlocked) }

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"100.64.0.0/10", // CGNAT
		"64:ff9b::/96",  // NAT64 (embeds an arbitrary IPv4)
		"fc00::/7",      // ULA
		"192.0.0.0/24",  // IETF protocol assignments
		"198.18.0.0/15", // benchmarking
		"240.0.0.0/4",   // reserved
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// BlockedIP reports whether a destination address is off limits.
func BlockedIP(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsLoopbackHost reports whether h names the loopback interface.
func IsLoopbackHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Unmap().IsLoopback()
}

// ValidateURL checks an outbound URL syntactically: length, no control
// characters, https (http only for loopback with allowPrivate), a host, no
// userinfo, no fragment. what names the field in error messages. The IP policy
// itself is enforced at dial time.
func ValidateURL(raw string, allowPrivate bool, what string, maxLen int) (*url.URL, error) {
	if raw == "" || len(raw) > maxLen {
		return nil, fmt.Errorf("%s must be 1-%d characters", what, maxLen)
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f {
			return nil, fmt.Errorf("%s contains control characters or spaces", what)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid URL", what)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s must not contain credentials", what)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%s must not contain a fragment", what)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%s needs a host", what)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowPrivate || !IsLoopbackHost(host) {
			return nil, fmt.Errorf("%s must use https", what)
		}
	default:
		return nil, fmt.Errorf("%s must use https", what)
	}
	return u, nil
}
