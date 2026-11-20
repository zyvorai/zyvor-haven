// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/zyvorai/haven/internal/auth"
	"github.com/zyvorai/haven/internal/keycloak"
	"github.com/zyvorai/haven/internal/plane"
)

type Server struct {
	KC    *keycloak.Manager
	Plane *plane.Reader
	Auth  *auth.Store
}

func (s *Server) kc() *keycloak.AdminClient {
	return s.KC.Client()
}

func (s *Server) KeycloakConfig(w http.ResponseWriter, r *http.Request) {
	url, user := s.KC.Config()
	writeJSON(w, http.StatusOK, map[string]string{
		"keycloakUrl": url,
		"adminUser":   user,
	})
}

func (s *Server) ConnectKeycloak(w http.ResponseWriter, r *http.Request) {
	var body struct {
		KeycloakURL string `json:"keycloakUrl"`
		AdminUser   string `json:"adminUser"`
		Password    string `json:"password"`
		ConsoleURL  string `json:"consoleUrl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.KC.Reconfigure(r.Context(), body.KeycloakURL, body.AdminUser, body.Password); err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if s.Auth != nil && body.AdminUser != "" && body.Password != "" {
		s.Auth.SetLocalCreds(body.AdminUser, body.Password)
	}

	consoleBase := strings.TrimRight(strings.TrimSpace(body.ConsoleURL), "/")
	if consoleBase == "" {
		consoleBase = s.publicBase(r)
	}
	realm := keycloak.BootstrapRealm()
	if err := s.kc().EnsureHavenConsoleClient(r.Context(), realm, consoleBase); err != nil {
		writeKCError(w, http.StatusBadGateway, "connected, but OIDC client setup failed: "+err.Error(), nil)
		return
	}
	if auth.LabDemoEnabled() {
		_ = s.kc().EnsureUserPassword(r.Context(), realm, "demo", "demo")
	}

	st, err := s.kc().Status(r.Context())
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// ChangeKeycloakAdminPassword resets the Keycloak master-realm admin password
// and updates Haven's live connection credentials.
func (s *Server) ChangeKeycloakAdminPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if len(body.NewPassword) < 8 {
		writeKCError(w, http.StatusBadRequest, "new password must be at least 8 characters", nil)
		return
	}
	baseURL, adminUser := s.KC.Config()
	if baseURL == "" || adminUser == "" {
		writeKCError(w, http.StatusBadRequest, "Keycloak is not connected", nil)
		return
	}
	if err := s.KC.Reconfigure(r.Context(), baseURL, adminUser, body.CurrentPassword); err != nil {
		writeKCError(w, http.StatusUnauthorized, "current password is incorrect", nil)
		return
	}
	users, err := s.kc().ListUsers(r.Context(), "master", adminUser)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	var adminID string
	for _, u := range users {
		if u.Username == adminUser {
			adminID = u.ID
			break
		}
	}
	if adminID == "" {
		writeKCError(w, http.StatusNotFound, "admin user not found in master realm", nil)
		return
	}
	code, raw, err := s.kc().ResetPassword(r.Context(), "master", adminID, keycloak.PasswordReset{
		Type:      "password",
		Value:     body.NewPassword,
		Temporary: false,
	})
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	if err := s.KC.Reconfigure(r.Context(), baseURL, adminUser, body.NewPassword); err != nil {
		writeKCError(w, http.StatusBadGateway, "password changed but reconnect failed: "+err.Error(), nil)
		return
	}
	if s.Auth != nil {
		s.Auth.SetLocalCreds(adminUser, body.NewPassword)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"user": adminUser,
		"note": "Keycloak admin password updated. Also update the haven-keycloak-admin secret for restarts.",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeKCError(w http.ResponseWriter, status int, msg string, raw []byte) {
	var kc json.RawMessage
	if len(raw) > 0 {
		kc = json.RawMessage(raw)
	}
	writeJSON(w, status, keycloak.APIError{Error: msg, Keycloak: kc, Status: status})
}

func (s *Server) PlaneStatus(w http.ResponseWriter, r *http.Request) {
	if s.Plane == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "message": "plane reader not configured"})
		return
	}
	var hint *plane.KeycloakHint
	if st, err := s.kc().Status(r.Context()); err == nil && st.Connected {
		hint = &plane.KeycloakHint{
			Connected:  true,
			Version:    st.Version,
			RealmCount: st.RealmCount,
			URL:        st.KeycloakURL,
		}
	}
	writeJSON(w, http.StatusOK, s.Plane.Status(r.Context(), hint))
}

func (s *Server) PlaneCapabilities(w http.ResponseWriter, r *http.Request) {
	if s.Plane == nil {
		writeJSON(w, http.StatusOK, plane.Capabilities{Message: "plane reader not configured"})
		return
	}
	writeJSON(w, http.StatusOK, s.Plane.Capabilities(r.Context()))
}

func (s *Server) CreatePlane(w http.ResponseWriter, r *http.Request) {
	if s.Plane == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plane reader not configured"})
		return
	}
	var body plane.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	created, err := s.Plane.CreatePlane(r.Context(), body)
	if err != nil {
		msg := err.Error()
		status := http.StatusBadGateway
		switch {
		case strings.Contains(msg, "already exists"):
			status = http.StatusConflict
		case strings.Contains(msg, "forbidden") || strings.Contains(msg, "not running in cluster"):
			status = http.StatusForbidden
		case strings.Contains(msg, "required") || strings.Contains(msg, "invalid"):
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]string{"error": msg})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":      created.Name,
		"namespace": created.Namespace,
		"profile":   created.Spec.Profile,
		"hostname":  created.Spec.Hostname,
		"realm":     created.Spec.Bootstrap.FirstRealm,
	})
}

func (s *Server) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) KeycloakStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.kc().Status(r.Context())
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) ListRealms(w http.ResponseWriter, r *http.Request) {
	realms, err := s.kc().ListRealms(r.Context())
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, realms)
}

func (s *Server) GetRealm(w http.ResponseWriter, r *http.Request, realm string) {
	rl, err := s.kc().GetRealm(r.Context(), realm)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, rl)
}

func (s *Server) CreateRealm(w http.ResponseWriter, r *http.Request) {
	var body keycloak.Realm
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().CreateRealm(r.Context(), body)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) UpdateRealm(w http.ResponseWriter, r *http.Request, realm string) {
	var body keycloak.Realm
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().UpdateRealm(r.Context(), realm, body)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) DeleteRealm(w http.ResponseWriter, r *http.Request, realm string) {
	code, raw, err := s.kc().DeleteRealm(r.Context(), realm)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ListClients(w http.ResponseWriter, r *http.Request, realm string) {
	clients, err := s.kc().ListClients(r.Context(), realm)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (s *Server) GetClient(w http.ResponseWriter, r *http.Request, realm, id string) {
	cl, err := s.kc().GetClient(r.Context(), realm, id)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, cl)
}

func (s *Server) CreateClient(w http.ResponseWriter, r *http.Request, realm string) {
	var body keycloak.Client
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().CreateClient(r.Context(), realm, body)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) UpdateClient(w http.ResponseWriter, r *http.Request, realm, id string) {
	var body keycloak.Client
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().UpdateClient(r.Context(), realm, id, body)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) DeleteClient(w http.ResponseWriter, r *http.Request, realm, id string) {
	code, raw, err := s.kc().DeleteClient(r.Context(), realm, id)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) GetClientSecret(w http.ResponseWriter, r *http.Request, realm, id string) {
	sec, err := s.kc().GetClientSecret(r.Context(), realm, id)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, sec)
}

func (s *Server) RegenerateClientSecret(w http.ResponseWriter, r *http.Request, realm, id string) {
	sec, err := s.kc().RegenerateClientSecret(r.Context(), realm, id)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, sec)
}

func (s *Server) ListUsers(w http.ResponseWriter, r *http.Request, realm string) {
	search := r.URL.Query().Get("search")
	users, err := s.kc().ListUsers(r.Context(), realm, search)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) CreateUser(w http.ResponseWriter, r *http.Request, realm string) {
	var body keycloak.User
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().CreateUser(r.Context(), realm, body)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) UpdateUser(w http.ResponseWriter, r *http.Request, realm, id string) {
	var body keycloak.User
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().UpdateUser(r.Context(), realm, id, body)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) DeleteUser(w http.ResponseWriter, r *http.Request, realm, id string) {
	code, raw, err := s.kc().DeleteUser(r.Context(), realm, id)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ResetPassword(w http.ResponseWriter, r *http.Request, realm, id string) {
	var body keycloak.PasswordReset
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().ResetPassword(r.Context(), realm, id, body)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ListRoles(w http.ResponseWriter, r *http.Request, realm string) {
	roles, err := s.kc().ListRoles(r.Context(), realm)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, roles)
}

func (s *Server) CreateRole(w http.ResponseWriter, r *http.Request, realm string) {
	var body keycloak.Role
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().CreateRole(r.Context(), realm, body)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) GetUserRoleMappings(w http.ResponseWriter, r *http.Request, realm, userID string) {
	m, err := s.kc().GetUserRoleMappings(r.Context(), realm, userID)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) AddRealmRoleMappings(w http.ResponseWriter, r *http.Request, realm, userID string) {
	var roles []keycloak.Role
	if err := json.NewDecoder(r.Body).Decode(&roles); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().AddRealmRoleMappings(r.Context(), realm, userID, roles)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ListGroups(w http.ResponseWriter, r *http.Request, realm string) {
	groups, err := s.kc().ListGroups(r.Context(), realm)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

func (s *Server) ListIdentityProviders(w http.ResponseWriter, r *http.Request, realm string) {
	idps, err := s.kc().ListIdentityProviders(r.Context(), realm)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, idps)
}

func (s *Server) CreateIdentityProvider(w http.ResponseWriter, r *http.Request, realm string) {
	var body keycloak.IdentityProvider
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeKCError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	code, raw, err := s.kc().CreateIdentityProvider(r.Context(), realm, body)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if code >= 300 {
		writeKCError(w, code, "keycloak error", raw)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) ListClientScopes(w http.ResponseWriter, r *http.Request, realm string) {
	scopes, err := s.kc().ListClientScopes(r.Context(), realm)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, scopes)
}

func (s *Server) ListEvents(w http.ResponseWriter, r *http.Request, realm string) {
	events, err := s.kc().ListAdminEvents(r.Context(), realm)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) ListKeys(w http.ResponseWriter, r *http.Request, realm string) {
	keys, err := s.kc().ListKeys(r.Context(), realm)
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) ListAllClients(w http.ResponseWriter, r *http.Request) {
	realms, err := s.kc().ListRealms(r.Context())
	if err != nil {
		writeKCError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	type clientWithRealm struct {
		keycloak.Client
		Realm string `json:"realm"`
	}
	var all []clientWithRealm
	for _, rl := range realms {
		if rl.Realm == "master" {
			continue
		}
		clients, err := s.kc().ListClients(r.Context(), rl.Realm)
		if err != nil {
			continue
		}
		for _, c := range clients {
			all = append(all, clientWithRealm{Client: c, Realm: rl.Realm})
		}
	}
	writeJSON(w, http.StatusOK, all)
}
