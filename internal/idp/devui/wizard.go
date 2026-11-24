// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package devui

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The add-an-app backend. The browser never sees the admin credential: this
// handler holds it server-side (via Config.AdminSecret), registers the client
// through the Admin API and returns the generated client secret exactly once,
// in the response to the request that created it. Nothing here logs, stores or
// re-serves a secret. DEV MODE ONLY, loopback only.

const (
	maxBody       = 16 << 10 // request body limit
	maxUpstream   = 1 << 20  // upstream response body limit
	maxRedirects  = 10
	maxNameLen    = 100
	csrfHeader    = "X-Haven-Dev"
	adminClientID = "haven-admin"
)

// App types the wizard can register.
const (
	TypeSPA    = "spa"
	TypeWeb    = "web"
	TypeNative = "native"
	TypeM2M    = "m2m"
)

type createReq struct {
	Type               string   `json:"type"`
	Name               string   `json:"name"`
	RedirectURIs       []string `json:"redirectUris"`
	PlaygroundCallback bool     `json:"playgroundCallback"`
}

type createResp struct {
	ID           string   `json:"id"`
	ClientID     string   `json:"clientId"`
	Type         string   `json:"type"`
	Name         string   `json:"name"`
	Public       bool     `json:"public"`
	RedirectURIs []string `json:"redirectUris"`
	Secret       string   `json:"secret,omitempty"`
}

// ValidateRedirect applies the wizard's redirect URI policy: https, or http
// only for localhost, 127.0.0.1 and [::1]; no wildcard, fragment, userinfo,
// whitespace or control characters. The JS twin in lib.js must agree (both
// are tested against the same vectors).
func ValidateRedirect(raw string) error {
	if raw == "" || len(raw) > 2048 {
		return errors.New("redirect URI must be 1 to 2048 characters")
	}
	for _, c := range raw {
		if c <= 0x20 || c == 0x7f || unicode.IsSpace(c) || unicode.IsControl(c) {
			return errors.New("redirect URI must not contain spaces or control characters")
		}
	}
	if strings.Contains(raw, "*") {
		return errors.New("wildcards are not allowed in redirect URIs")
	}
	if strings.Contains(raw, "#") {
		return errors.New("redirect URIs must not contain a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return errors.New("redirect URI must be an absolute http(s) URL")
	}
	if u.User != nil {
		return errors.New("redirect URIs must not contain credentials")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("redirect URI has no host")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("redirect URI has an invalid port")
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopbackName(host) {
			return errors.New("http is only allowed for localhost, 127.0.0.1 and [::1]; use https")
		}
	default:
		return errors.New("redirect URI scheme must be https (or http for loopback)")
	}
	return nil
}

func isLoopbackName(h string) bool {
	h = strings.ToLower(h)
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

var clientSlugRE = regexp.MustCompile(`[^a-z0-9]+`)

func newClientID(name string) string {
	slug := strings.Trim(clientSlugRE.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	if slug == "" {
		slug = "app"
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return slug + "-" + hex.EncodeToString(b)
}

func validName(s string) bool {
	if strings.TrimSpace(s) == "" || len(s) > maxNameLen {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func validateCreate(in createReq) error {
	switch in.Type {
	case TypeSPA, TypeWeb, TypeNative, TypeM2M:
	default:
		return errors.New("type must be spa, web, native or m2m")
	}
	if !validName(in.Name) {
		return errors.New("name must be 1 to 100 printable characters")
	}
	if in.Type == TypeM2M {
		if len(in.RedirectURIs) > 0 || in.PlaygroundCallback {
			return errors.New("machine-to-machine apps have no redirect URIs")
		}
		return nil
	}
	if len(in.RedirectURIs) == 0 {
		return errors.New("at least one redirect URI is required")
	}
	if len(in.RedirectURIs) > maxRedirects {
		return errors.New("too many redirect URIs")
	}
	seen := map[string]bool{}
	for _, u := range in.RedirectURIs {
		if err := ValidateRedirect(u); err != nil {
			return errors.New(err.Error() + ": " + truncate(u, 80))
		}
		if seen[u] {
			return errors.New("duplicate redirect URI: " + truncate(u, 80))
		}
		seen[u] = true
		if in.Type == TypeNative {
			p, _ := url.Parse(u)
			if !strings.EqualFold(p.Scheme, "http") || !isLoopbackName(p.Hostname()) {
				return errors.New("native apps use a loopback redirect (http on 127.0.0.1, localhost or [::1]): " + truncate(u, 80))
			}
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// sameOriginPost is the CSRF and DNS-rebinding gate for state-changing calls:
// a loopback Host, the custom header (which forces a CORS preflight that this
// server never grants), an exact same-origin Origin and a JSON content type.
func sameOriginPost(r *http.Request) (int, string) {
	host := r.Host
	hn := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hn = h
	}
	hn = strings.Trim(hn, "[]")
	if !isLoopbackName(hn) {
		return http.StatusForbidden, "dev API only answers on a loopback host"
	}
	if r.Header.Get(csrfHeader) != "1" {
		return http.StatusForbidden, "missing " + csrfHeader + " header"
	}
	if r.Header.Get("Origin") != "http://"+host {
		return http.StatusForbidden, "cross-origin request refused"
	}
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" {
		return http.StatusForbidden, "cross-site request refused"
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if mt != "application/json" {
		return http.StatusUnsupportedMediaType, "Content-Type must be application/json"
	}
	return 0, ""
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errOut(w http.ResponseWriter, code int, msg string) {
	jsonOut(w, code, map[string]string{"error": msg})
}

func (c Config) createClient(w http.ResponseWriter, r *http.Request) {
	if code, msg := sameOriginPost(r); code != 0 {
		errOut(w, code, msg)
		return
	}
	if c.AdminSecret == nil {
		errOut(w, http.StatusServiceUnavailable, "add-an-app is not configured on this server")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var in createReq
	if err := dec.Decode(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			errOut(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		errOut(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if dec.More() {
		errOut(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateCreate(in); err != nil {
		errOut(w, http.StatusBadRequest, err.Error())
		return
	}
	uris := append([]string(nil), in.RedirectURIs...)
	if in.PlaygroundCallback {
		// Register the page the browser is on, so "Test login" can come back to it.
		uris = append(uris, "http://"+r.Host+"/dev/")
	}
	base, realm, err := adminBase(c.Issuer)
	if err != nil {
		errOut(w, http.StatusInternalServerError, "dev server issuer is not a loopback realm URL")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	cl := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	tok, err := adminToken(ctx, cl, c, base, realm)
	if err != nil {
		errOut(w, http.StatusBadGateway, "could not get an admin token from the dev IdP")
		return
	}

	public := in.Type == TypeSPA || in.Type == TypeNative
	clientID := newClientID(in.Name)
	body := map[string]any{
		"clientId": clientID, "name": in.Name, "enabled": true, "protocol": "openid-connect",
		"publicClient": public, "standardFlowEnabled": in.Type != TypeM2M,
		"serviceAccountsEnabled": in.Type == TypeM2M,
		"attributes":             map[string]string{"pkce.code.challenge.method": "S256"},
	}
	if in.Type != TypeM2M {
		body["redirectUris"] = uris
	}
	if in.Type == TypeSPA {
		if o := originsOf(uris); len(o) > 0 {
			body["webOrigins"] = o
		}
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/admin/v1/realms/"+url.PathEscape(realm)+"/clients", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := cl.Do(req)
	if err != nil {
		errOut(w, http.StatusBadGateway, "could not reach the dev IdP admin API")
		return
	}
	defer res.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(res.Body, maxUpstream))
	switch {
	case res.StatusCode == http.StatusConflict:
		errOut(w, http.StatusConflict, "a client with that id already exists; try again")
		return
	case res.StatusCode == http.StatusBadRequest:
		// Admin validation messages are about our input, never about secrets.
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(rb, &e)
		msg := "the admin API rejected the client"
		if e.Error != "" && len(e.Error) < 200 {
			msg += ": " + e.Error
		}
		errOut(w, http.StatusBadRequest, msg)
		return
	case res.StatusCode != http.StatusCreated:
		errOut(w, http.StatusBadGateway, "the admin API returned an unexpected status")
		return
	}
	var created struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if json.Unmarshal(rb, &created) != nil {
		errOut(w, http.StatusBadGateway, "unreadable admin API response")
		return
	}
	out := createResp{ID: created.ID, ClientID: clientID, Type: in.Type, Name: in.Name, Public: public, RedirectURIs: uris}
	if !public {
		out.Secret = created.Secret
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOut(w, http.StatusCreated, out)
}

func originsOf(uris []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		o := u.Scheme + "://" + u.Host
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}

// adminBase returns scheme://host for the issuer and its realm. The issuer must
// be a loopback URL so the admin credential can only be sent to this machine.
func adminBase(issuer string) (base, realm string, err error) {
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !isLoopbackName(u.Hostname()) {
		return "", "", errors.New("issuer is not loopback")
	}
	p := strings.Trim(u.Path, "/")
	if !strings.HasPrefix(p, "realms/") || strings.Count(p, "/") != 1 {
		return "", "", errors.New("issuer has no realm")
	}
	return u.Scheme + "://" + u.Host, strings.TrimPrefix(p, "realms/"), nil
}

func adminToken(ctx context.Context, cl *http.Client, c Config, base, realm string) (string, error) {
	sec, err := c.AdminSecret()
	if err != nil || sec == "" {
		return "", errors.New("no admin secret")
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/realms/"+url.PathEscape(realm)+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(adminClientID, sec)
	res, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, maxUpstream))
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if res.StatusCode != http.StatusOK || json.Unmarshal(b, &t) != nil || t.AccessToken == "" {
		return "", errors.New("token request failed")
	}
	return t.AccessToken, nil
}
