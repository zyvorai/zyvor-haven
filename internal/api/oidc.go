// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/zyvorai/haven/internal/auth"
)

const (
	oidcVerifierCookie = "haven_oidc_verifier"
	oidcStateCookie    = "haven_oidc_state"
)

type oidcDiscovery struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	Userinfo      string `json:"userinfo_endpoint"`
}

func oidcIssuerFrom(baseURL string) string {
	if v := strings.TrimSpace(os.Getenv("HAVEN_OIDC_ISSUER")); v != "" {
		return strings.TrimRight(v, "/")
	}
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
	}
	if base == "" {
		return ""
	}
	return base + "/realms/" + keycloakBootstrapRealm()
}

func keycloakBootstrapRealm() string {
	if v := strings.TrimSpace(os.Getenv("HAVEN_BOOTSTRAP_REALM")); v != "" {
		return v
	}
	return "platform"
}

func (s *Server) liveKeycloakURL() string {
	if s.KC == nil {
		return strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
	}
	url, _ := s.KC.Config()
	if url != "" {
		return strings.TrimRight(url, "/")
	}
	return strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
}

func (s *Server) oidcIssuer() string {
	return oidcIssuerFrom(s.liveKeycloakURL())
}

func oidcClientID() string {
	if v := strings.TrimSpace(os.Getenv("HAVEN_OIDC_CLIENT_ID")); v != "" {
		return v
	}
	return "haven-console"
}

func (s *Server) oidcEnabled() bool {
	return s.oidcIssuer() != ""
}

func (s *Server) publicBase(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		host = fh
	}
	return scheme + "://" + host
}

func (s *Server) requestSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func randomURLToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	issuer := s.oidcIssuer()
	if issuer == "" {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "OIDC is not configured — connect Keycloak in Settings or set HAVEN_OIDC_ISSUER",
		})
		return
	}

	base := s.publicBase(r)
	if s.KC != nil && s.KC.Client() != nil {
		realm := keycloakBootstrapRealm()
		if err := s.KC.Client().EnsureHavenConsoleClient(r.Context(), realm, base); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error": "OIDC client setup failed: " + err.Error() + " — reconnect Keycloak in Settings",
			})
			return
		}
		if auth.LabDemoEnabled() {
			_ = s.KC.Client().EnsureUserPassword(r.Context(), realm, "demo", "demo")
		}
	}

	disc, err := s.fetchOIDCDiscovery(r, issuer)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "OIDC discovery failed: " + err.Error()})
		return
	}
	authURL := disc.AuthEndpoint
	if authURL == "" {
		authURL = issuer + "/protocol/openid-connect/auth"
	}
	target, err := url.Parse(authURL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid authorization endpoint"})
		return
	}

	verifier := randomURLToken(32)
	state := randomURLToken(24)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	secure := s.requestSecure(r)
	// #nosec G124 -- HttpOnly always; Lax is required for the IdP redirect back; Secure follows the request scheme for HTTP dev installs
	http.SetCookie(w, &http.Cookie{Name: oidcVerifierCookie, Value: verifier, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure, MaxAge: 600})
	// #nosec G124 -- same attributes as the verifier cookie above
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: state, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure, MaxAge: 600})

	q := target.Query()
	q.Set("client_id", oidcClientID())
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("redirect_uri", s.publicBase(r)+"/api/v1/auth/oidc/callback")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Server) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		http.Error(w, "OIDC error: "+errMsg+" — "+r.URL.Query().Get("error_description"), http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}
	wantState, _ := r.Cookie(oidcStateCookie)
	if wantState == nil || wantState.Value == "" || state == "" || wantState.Value != state {
		http.Error(w, "invalid OIDC state", http.StatusBadRequest)
		return
	}
	verifierCookie, _ := r.Cookie(oidcVerifierCookie)
	if verifierCookie == nil || verifierCookie.Value == "" {
		http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
		return
	}

	issuer := s.oidcIssuer()
	disc, err := s.fetchOIDCDiscovery(r, issuer)
	if err != nil {
		http.Error(w, "OIDC discovery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.publicBase(r)+"/api/v1/auth/oidc/callback")
	form.Set("client_id", oidcClientID())
	form.Set("code_verifier", verifierCookie.Value)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		http.Error(w, fmt.Sprintf("token exchange HTTP %d: %s", res.StatusCode, string(body)), http.StatusBadGateway)
		return
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		http.Error(w, "invalid token response", http.StatusBadGateway)
		return
	}

	user := oidcPreferredUser(tok.IDToken, tok.AccessToken, disc.Userinfo, r)
	if user == "" {
		user = "oidc-user"
	}
	if s.Auth == nil {
		http.Error(w, "auth store unavailable", http.StatusInternalServerError)
		return
	}
	sess := s.Auth.Issue(user, "admin", "oidc")

	secure := s.requestSecure(r)
	// #nosec G124 -- expiring the PKCE cookies; Secure follows the request scheme
	http.SetCookie(w, &http.Cookie{Name: oidcVerifierCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure})
	// #nosec G124 -- expiring the PKCE cookies; Secure follows the request scheme
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure})

	// Hand Bearer token to SPA via query (sessionStorage); single-use from UI perspective.
	redir := "/login?haven_token=" + url.QueryEscape(sess.Token) + "&sso=1"
	http.Redirect(w, r, redir, http.StatusFound)
}

func (s *Server) fetchOIDCDiscovery(r *http.Request, issuer string) (oidcDiscovery, error) {
	var out oidcDiscovery
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return out, fmt.Errorf("issuer not configured")
	}
	u := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u, nil)
	if err != nil {
		return out, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return out, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return out, fmt.Errorf("discovery HTTP %d: %s", res.StatusCode, string(b))
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return out, err
	}
	if issuerURL, err := url.Parse(issuer); err == nil && issuerURL.Host != "" {
		rewrite := func(ep string) string {
			u, err := url.Parse(ep)
			if err != nil || u.Host == "" {
				return ep
			}
			if u.Hostname() == issuerURL.Hostname() && u.Host != issuerURL.Host {
				u.Host = issuerURL.Host
				u.Scheme = issuerURL.Scheme
				return u.String()
			}
			return ep
		}
		out.AuthEndpoint = rewrite(out.AuthEndpoint)
		out.TokenEndpoint = rewrite(out.TokenEndpoint)
		out.Userinfo = rewrite(out.Userinfo)
	}
	return out, nil
}

func oidcPreferredUser(idToken, accessToken, userinfoURL string, r *http.Request) string {
	if claims := decodeJWTClaims(idToken); claims != nil {
		if u := firstNonEmpty(claims["preferred_username"], claims["email"], claims["sub"]); u != "" {
			return u
		}
	}
	if accessToken != "" && userinfoURL != "" {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, userinfoURL, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+accessToken)
			if res, err := http.DefaultClient.Do(req); err == nil {
				defer func() { _ = res.Body.Close() }()
				var info map[string]any
				if json.NewDecoder(res.Body).Decode(&info) == nil {
					return firstNonEmpty(
						asString(info["preferred_username"]),
						asString(info["email"]),
						asString(info["sub"]),
					)
				}
			}
		}
	}
	return ""
}

func asString(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func decodeJWTClaims(jwt string) map[string]string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range claims {
		switch t := v.(type) {
		case string:
			out[k] = t
		}
	}
	return out
}
