// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/zyvorai/haven/internal/auth"
)

func (s *Server) AuthProviders(w http.ResponseWriter, r *http.Request) {
	_, _, hasLocal := auth.LocalCreds()
	oidc := map[string]any{"enabled": false}
	if s.oidcEnabled() {
		oidc = map[string]any{
			"enabled":   true,
			"login_url": "/api/v1/auth/oidc/login",
			"issuer":    s.oidcIssuer(),
			"client_id": oidcClientID(),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"local": map[string]any{
			"enabled": true,
			"default_username": firstNonEmpty(
				os.Getenv("HAVEN_CONSOLE_USER"),
				os.Getenv("KEYCLOAK_ADMIN_USER"),
				"admin",
			),
		},
		"lab": map[string]any{
			"operator_login": auth.LabDemoEnabled(),
			"hint":           "demo / demo",
		},
		"oidc":          oidc,
		"saml":          map[string]any{"enabled": false},
		"hasLocalCreds": hasLocal,
	})
}

func (s *Server) AuthLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	user := strings.TrimSpace(body.Username)
	pass := body.Password
	if user == "" || pass == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}

	var method, role string
	switch {
	case auth.MatchLabDemo(user, pass):
		method = "lab"
		role = "operator"
	case s.Auth != nil && s.Auth.MatchLocal(user, pass):
		method = "local"
		role = "admin"
	default:
		url, _ := s.KC.Config()
		if url == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		if err := s.KC.Reconfigure(r.Context(), url, user, pass); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		method = "keycloak"
		role = "admin"
	}

	if s.Auth == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth store unavailable"})
		return
	}
	sess := s.Auth.Issue(user, role, method)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":     sess.Token,
		"user":      sess.User,
		"role":      sess.Role,
		"auth":      sess.Auth,
		"expiresAt": sess.ExpiresAt,
	})
}

func (s *Server) AuthSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":      sess.User,
		"role":      sess.Role,
		"auth":      sess.Auth,
		"expiresAt": sess.ExpiresAt,
		"mode":      "haven",
	})
}

func (s *Server) AuthLogout(w http.ResponseWriter, r *http.Request) {
	if tok := bearerToken(r); tok != "" && s.Auth != nil {
		s.Auth.Revoke(tok)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ChangeConsolePassword updates the local Haven console sign-in password
// (in-memory until restart; does not change lab demo/demo).
func (s *Server) ChangeConsolePassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if len(body.NewPassword) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new password must be at least 8 characters"})
		return
	}
	if s.Auth == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth store unavailable"})
		return
	}
	user := sess.User
	if auth.MatchLabDemo(user, body.CurrentPassword) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "lab demo account cannot change password — use Keycloak admin or set HAVEN_CONSOLE_PASSWORD",
		})
		return
	}
	okCreds := s.Auth.MatchLocal(user, body.CurrentPassword) || auth.MatchLocal(user, body.CurrentPassword)
	if !okCreds {
		if url, _ := s.KC.Config(); url != "" {
			if err := s.KC.Reconfigure(r.Context(), url, user, body.CurrentPassword); err == nil {
				okCreds = true
			}
		}
	}
	if !okCreds {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}
	s.Auth.SetLocalCreds(user, body.NewPassword)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"user": user,
		"note": "Console password updated for this process. Persist via HAVEN_CONSOLE_PASSWORD / secret for restarts.",
	})
}

func (s *Server) sessionFromRequest(r *http.Request) (auth.Session, bool) {
	if s.Auth == nil {
		return auth.Session{}, false
	}
	tok := bearerToken(r)
	if tok == "" {
		return auth.Session{}, false
	}
	return s.Auth.Get(tok)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func requireAuth(s *Server, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.sessionFromRequest(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
