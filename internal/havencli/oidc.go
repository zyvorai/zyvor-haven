// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	maxResponseBytes = 1 << 20 // 1 MiB
	httpTimeout      = 30 * time.Second
	grantDevice      = "urn:ietf:params:oauth:grant-type:device_code"
)

// netOpts are the transport-security knobs shared by every network command.
type netOpts struct {
	CAFile       string
	InsecureHTTP bool // allow a plain http:// issuer on a non-loopback host
	AllowCross   bool // allow endpoints on another origin than the issuer
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// origin is scheme://host:port with default ports made explicit.
func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

// parseIssuer validates the issuer URL: absolute, no query/fragment/userinfo,
// https unless loopback (or --insecure-http, which the caller warns about).
func parseIssuer(raw string, o netOpts) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, usageErrorf("invalid issuer %q: expected an absolute https:// URL", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, usageErrorf("invalid issuer %q: must not contain a query, fragment or credentials", raw)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) && !o.InsecureHTTP {
		return nil, usageErrorf("refusing plain http:// issuer %q: tokens would cross the network unencrypted (use https, a loopback host, or --insecure-http)", raw)
	}
	return u, nil
}

// checkEndpoint enforces the rules for URLs the discovery document hands us:
// https (or loopback http, or --insecure-http) and the issuer's origin.
func checkEndpoint(name, raw string, issuer *url.URL, o netOpts) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("discovery %s is not a valid absolute URL", name)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) && !o.InsecureHTTP {
		return fmt.Errorf("discovery %s %q is plain http on a non-loopback host; refusing", name, raw)
	}
	if !o.AllowCross && origin(u) != origin(issuer) {
		return fmt.Errorf("discovery %s %q is on a different origin than the issuer %s; refusing (override with --allow-cross-origin-endpoints only if you trust the issuer)", name, raw, origin(issuer))
	}
	return nil
}

// httpClient builds the hardened client: timeout, optional private CA, TLS 1.2+,
// and a redirect policy that never follows a redirect of a POST (token, device,
// revocation) and only follows same-origin GET redirects (discovery, JWKS,
// userinfo), so credentials cannot be bounced to another origin.
func httpClient(o netOpts) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading --ca-file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca-file %s contains no PEM certificates", o.CAFile)
		}
		tc.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       tc,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: httpTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: httpTimeout, CheckRedirect: checkRedirect}, nil
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("too many redirects")
	}
	first := via[0]
	if first.Method != http.MethodGet {
		return errors.New("refusing to follow a redirect of a POST request")
	}
	if origin(req.URL) != origin(first.URL) {
		return fmt.Errorf("refusing cross-origin redirect to %s", req.URL.Host)
	}
	return nil
}

// oidc is a client bound to one issuer.
type oidc struct {
	hc     *http.Client
	issuer *url.URL
	opts   netOpts
}

func newOIDC(issuerRaw string, o netOpts, warn io.Writer) (*oidc, error) {
	iu, err := parseIssuer(issuerRaw, o)
	if err != nil {
		return nil, err
	}
	if iu.Scheme == "http" && !isLoopbackHost(iu.Hostname()) {
		_, _ = fmt.Fprintf(warn, "haven: WARNING: --insecure-http: talking to %s over plain HTTP; tokens can be read and stolen on the network\n", iu.Host)
	}
	hc, err := httpClient(o)
	if err != nil {
		return nil, err
	}
	return &oidc{hc: hc, issuer: iu, opts: o}, nil
}

// do performs the request and returns the status and at most 1 MiB of body.
func (c *oidc) do(req *http.Request) (int, []byte, error) {
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		// url.Error carries the URL; request bodies (tokens) are never part of it.
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(b) > maxResponseBytes {
		return 0, nil, fmt.Errorf("response from %s exceeds %d bytes; refusing", req.URL.Host, maxResponseBytes)
	}
	return resp.StatusCode, b, nil
}

func (c *oidc) postForm(ctx context.Context, endpoint string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

func (c *oidc) get(ctx context.Context, endpoint, bearer string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c.do(req)
}

// discovery is the subset of the OpenID Provider Metadata we use.
type discovery struct {
	Issuer                      string `json:"issuer"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
	RevocationEndpoint          string `json:"revocation_endpoint"`
	JWKSURI                     string `json:"jwks_uri"`
}

func (c *oidc) discover(ctx context.Context) (*discovery, error) {
	u := strings.TrimRight(c.issuer.String(), "/") + "/.well-known/openid-configuration"
	st, b, err := c.get(ctx, u, "")
	if err != nil {
		return nil, fmt.Errorf("fetching discovery document: %w", err)
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("discovery document: HTTP %d from %s", st, u)
	}
	var d discovery
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("discovery document is not valid JSON")
	}
	// Mix-up defence (RFC 8414 3.3 / OIDC Discovery 4.3): the document must
	// name exactly the issuer we asked about.
	if d.Issuer != c.issuer.String() {
		return nil, fmt.Errorf("discovery issuer mismatch: asked for %q but the document says %q", c.issuer.String(), d.Issuer)
	}
	for _, e := range []struct{ n, v string }{
		{"device_authorization_endpoint", d.DeviceAuthorizationEndpoint},
		{"token_endpoint", d.TokenEndpoint},
		{"userinfo_endpoint", d.UserinfoEndpoint},
		{"revocation_endpoint", d.RevocationEndpoint},
		{"jwks_uri", d.JWKSURI},
	} {
		if err := checkEndpoint(e.n, e.v, c.issuer, c.opts); err != nil {
			return nil, err
		}
	}
	return &d, nil
}

// tokenError is an RFC 6749 / 8628 error response.
type tokenError struct{ Code, Desc string }

func (e *tokenError) Error() string {
	if e.Desc != "" {
		return e.Code + ": " + e.Desc
	}
	return e.Code
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
}

// tokenRequest posts a grant. Non-200 answers become *tokenError (the body is
// parsed for error/error_description only and is never echoed whole).
func (c *oidc) tokenRequest(ctx context.Context, endpoint string, form url.Values) (*tokenResp, error) {
	st, b, err := c.postForm(ctx, endpoint, form)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		var e struct {
			Error string `json:"error"`
			Desc  string `json:"error_description"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return nil, &tokenError{Code: clean(e.Error, 64), Desc: clean(e.Desc, 200)}
		}
		return nil, fmt.Errorf("token endpoint answered HTTP %d", st)
	}
	var t tokenResp
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, errors.New("token endpoint answered with invalid JSON")
	}
	if t.AccessToken == "" {
		return nil, errors.New("token response has no access_token")
	}
	if t.TokenType != "" && !strings.EqualFold(t.TokenType, "bearer") {
		return nil, fmt.Errorf("unsupported token_type %q", clean(t.TokenType, 32))
	}
	return &t, nil
}

type deviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURL         string `json:"verification_url"` // Google-style alias
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

func (c *oidc) deviceAuthorize(ctx context.Context, endpoint, clientID, scope string) (*deviceAuth, error) {
	if endpoint == "" {
		return nil, errors.New("the issuer does not advertise a device_authorization_endpoint (RFC 8628 unsupported?)")
	}
	form := url.Values{"client_id": {clientID}}
	if scope != "" {
		form.Set("scope", scope)
	}
	st, b, err := c.postForm(ctx, endpoint, form)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		var e struct{ Error, ErrorDescription string }
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("device authorization refused: %s", (&tokenError{clean(e.Error, 64), clean(e.ErrorDescription, 200)}).Error())
		}
		return nil, fmt.Errorf("device authorization endpoint answered HTTP %d", st)
	}
	var d deviceAuth
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("device authorization endpoint answered with invalid JSON")
	}
	if d.VerificationURI == "" {
		d.VerificationURI = d.VerificationURL
	}
	if d.DeviceCode == "" || d.UserCode == "" || d.VerificationURI == "" {
		return nil, errors.New("device authorization response is missing device_code, user_code or verification_uri")
	}
	if d.Interval <= 0 {
		d.Interval = 5
	}
	if d.ExpiresIn <= 0 {
		d.ExpiresIn = 600
	}
	for _, s := range []string{d.VerificationURI, d.VerificationURIComplete} {
		if s == "" {
			continue
		}
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || (!isLoopbackHost(u.Hostname()) && !c.opts.InsecureHTTP))) {
			return nil, errors.New("device authorization response has a verification URI that is not https; refusing")
		}
	}
	return &d, nil
}

func (c *oidc) userinfo(ctx context.Context, endpoint, accessToken string) (map[string]any, error) {
	if endpoint == "" {
		return nil, errors.New("the issuer does not advertise a userinfo_endpoint")
	}
	st, b, err := c.get(ctx, endpoint, accessToken)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint answered HTTP %d", st)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, errors.New("userinfo answered with invalid JSON")
	}
	return m, nil
}

// revoke posts RFC 7009 revocation. The token travels in the body, never in
// argv or the URL.
func (c *oidc) revoke(ctx context.Context, endpoint, clientID, token, hint string) error {
	st, _, err := c.postForm(ctx, endpoint, url.Values{"token": {token}, "token_type_hint": {hint}, "client_id": {clientID}})
	if err != nil {
		return err
	}
	if st != http.StatusOK {
		return fmt.Errorf("revocation endpoint answered HTTP %d", st)
	}
	return nil
}

// clean strips control characters (terminal escape injection from a hostile
// server) and truncates.
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			continue
		}
		if n++; n > max {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
