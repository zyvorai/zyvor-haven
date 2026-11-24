// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/zyvorai/haven/internal/auth"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/plane"
)

type Server struct {
	Backend idp.Backend
	Plane   *plane.Reader
	Auth    *auth.Store
}

// backendClient is nil-safe for both a nil Backend and an unconnected one.
func (s *Server) backendClient() idp.Provider {
	if s.Backend == nil {
		return nil
	}
	return s.Backend.Client()
}

func (s *Server) provider() idp.Provider {
	return s.Backend.Client()
}

func (s *Server) IdentityServerConfig(w http.ResponseWriter, r *http.Request) {
	url, user := s.Backend.Config()
	writeJSON(w, http.StatusOK, map[string]string{
		"identityServerUrl": url,
		"adminUser":         user,
	})
}

func (s *Server) ConnectIdentityServer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IdentityServerURL string `json:"identityServerUrl"`
		AdminUser         string `json:"adminUser"`
		Password          string `json:"password"`
		ConsoleURL        string `json:"consoleUrl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.Backend.Reconfigure(r.Context(), body.IdentityServerURL, body.AdminUser, body.Password); err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	if s.Auth != nil && body.AdminUser != "" && body.Password != "" {
		s.Auth.SetLocalCreds(body.AdminUser, body.Password)
	}

	consoleBase := strings.TrimRight(strings.TrimSpace(body.ConsoleURL), "/")
	if consoleBase == "" {
		consoleBase = s.publicBase(r)
	}
	realm := idp.BootstrapRealm()
	if err := s.provider().EnsureHavenConsoleClient(r.Context(), realm, consoleBase); err != nil {
		writeError(w, http.StatusBadGateway, "connected, but OIDC client setup failed: "+err.Error(), nil)
		return
	}
	if auth.LabDemoEnabled() {
		_ = s.provider().EnsureUserPassword(r.Context(), realm, "demo", "demo")
	}

	st, err := s.provider().Status(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// ChangeIdentityServerAdminPassword resets the master-realm admin password
// and updates Haven's live connection credentials.
func (s *Server) ChangeIdentityServerAdminPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if len(body.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "new password must be at least 8 characters", nil)
		return
	}
	baseURL, adminUser := s.Backend.Config()
	if baseURL == "" || adminUser == "" {
		writeError(w, http.StatusBadRequest, "identity server is not connected", nil)
		return
	}
	if err := s.Backend.Reconfigure(r.Context(), baseURL, adminUser, body.CurrentPassword); err != nil {
		if errors.Is(err, idp.ErrBackendFixed) {
			// The native backend authenticates with a service client whose secret
			// is set by the environment, so there is no admin password to change.
			writeError(w, http.StatusNotImplemented, "this identity backend is configured by the environment; rotate its admin client secret there instead", nil)
			return
		}
		writeError(w, http.StatusUnauthorized, "current password is incorrect", nil)
		return
	}
	users, err := s.provider().ListUsers(r.Context(), "master", adminUser)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
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
		writeError(w, http.StatusNotFound, "admin user not found in master realm", nil)
		return
	}
	if err := s.provider().ResetPassword(r.Context(), "master", adminID, idp.PasswordReset{
		Type:      "password",
		Value:     body.NewPassword,
		Temporary: false,
	}); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	if err := s.Backend.Reconfigure(r.Context(), baseURL, adminUser, body.NewPassword); err != nil {
		writeError(w, http.StatusBadGateway, "password changed but reconnect failed: "+err.Error(), nil)
		return
	}
	if s.Auth != nil {
		s.Auth.SetLocalCreds(adminUser, body.NewPassword)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"user": adminUser,
		"note": "Admin password updated. Also update the secret that holds it for restarts.",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeProviderError relays a backend rejection with its status and body, and
// reports transport failures as 502.
func writeProviderError(w http.ResponseWriter, err error, msg string) {
	if se := idp.AsStatus(err); se != nil {
		writeError(w, se.Code, msg, se.Body)
		return
	}
	writeError(w, http.StatusBadGateway, err.Error(), nil)
}

func writeError(w http.ResponseWriter, status int, msg string, raw []byte) {
	var body json.RawMessage
	if len(raw) > 0 {
		body = json.RawMessage(raw)
	}
	writeJSON(w, status, idp.APIError{Error: msg, IdentityServer: body, Status: status})
}

func (s *Server) PlaneStatus(w http.ResponseWriter, r *http.Request) {
	if s.Plane == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "message": "plane reader not configured"})
		return
	}
	var hint *plane.IdentityServerHint
	if st, err := s.provider().Status(r.Context()); err == nil && st.Connected {
		hint = &plane.IdentityServerHint{
			Connected:  true,
			Version:    st.Version,
			RealmCount: st.RealmCount,
			URL:        st.IdentityServerURL,
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

func (s *Server) IdentityServerStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.provider().Status(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) ListRealms(w http.ResponseWriter, r *http.Request) {
	realms, err := s.provider().ListRealms(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, realms)
}

func (s *Server) GetRealm(w http.ResponseWriter, r *http.Request, realm string) {
	rl, err := s.provider().GetRealm(r.Context(), realm)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, rl)
}

func (s *Server) CreateRealm(w http.ResponseWriter, r *http.Request) {
	var body idp.Realm
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.provider().CreateRealm(r.Context(), body); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) UpdateRealm(w http.ResponseWriter, r *http.Request, realm string) {
	var body idp.Realm
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.provider().UpdateRealm(r.Context(), realm, body); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) DeleteRealm(w http.ResponseWriter, r *http.Request, realm string) {
	if err := s.provider().DeleteRealm(r.Context(), realm); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ListClients(w http.ResponseWriter, r *http.Request, realm string) {
	clients, err := s.provider().ListClients(r.Context(), realm)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (s *Server) GetClient(w http.ResponseWriter, r *http.Request, realm, id string) {
	cl, err := s.provider().GetClient(r.Context(), realm, id)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, cl)
}

func (s *Server) CreateClient(w http.ResponseWriter, r *http.Request, realm string) {
	var body idp.Client
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	// Providers that cannot read a secret back (the native IdP stores only a
	// hash) reveal it once here; the caller must copy it now.
	if sc, ok := s.provider().(idp.SecretCreator); ok && !body.PublicClient {
		id, secret, err := sc.CreateClientWithSecret(r.Context(), realm, body)
		if err != nil {
			writeProviderError(w, err, "identity server error")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, map[string]string{"id": id, "secret": secret})
		return
	}
	if err := s.provider().CreateClient(r.Context(), realm, body); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) UpdateClient(w http.ResponseWriter, r *http.Request, realm, id string) {
	var body idp.Client
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.provider().UpdateClient(r.Context(), realm, id, body); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) DeleteClient(w http.ResponseWriter, r *http.Request, realm, id string) {
	if err := s.provider().DeleteClient(r.Context(), realm, id); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) GetClientSecret(w http.ResponseWriter, r *http.Request, realm, id string) {
	sec, err := s.provider().GetClientSecret(r.Context(), realm, id)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, sec)
}

func (s *Server) RegenerateClientSecret(w http.ResponseWriter, r *http.Request, realm, id string) {
	sec, err := s.provider().RegenerateClientSecret(r.Context(), realm, id)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, sec)
}

func (s *Server) ListUsers(w http.ResponseWriter, r *http.Request, realm string) {
	search := r.URL.Query().Get("search")
	users, err := s.provider().ListUsers(r.Context(), realm, search)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) CreateUser(w http.ResponseWriter, r *http.Request, realm string) {
	var body idp.User
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.provider().CreateUser(r.Context(), realm, body); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) UpdateUser(w http.ResponseWriter, r *http.Request, realm, id string) {
	var body idp.User
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.provider().UpdateUser(r.Context(), realm, id, body); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) DeleteUser(w http.ResponseWriter, r *http.Request, realm, id string) {
	if err := s.provider().DeleteUser(r.Context(), realm, id); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ResetPassword(w http.ResponseWriter, r *http.Request, realm, id string) {
	var body idp.PasswordReset
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.provider().ResetPassword(r.Context(), realm, id, body); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ListRoles(w http.ResponseWriter, r *http.Request, realm string) {
	roles, err := s.provider().ListRoles(r.Context(), realm)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, roles)
}

func (s *Server) CreateRole(w http.ResponseWriter, r *http.Request, realm string) {
	var body idp.Role
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.provider().CreateRole(r.Context(), realm, body); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) GetUserRoleMappings(w http.ResponseWriter, r *http.Request, realm, userID string) {
	m, err := s.provider().GetUserRoleMappings(r.Context(), realm, userID)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) AddRealmRoleMappings(w http.ResponseWriter, r *http.Request, realm, userID string) {
	var roles []idp.Role
	if err := json.NewDecoder(r.Body).Decode(&roles); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.provider().AddRealmRoleMappings(r.Context(), realm, userID, roles); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ListGroups(w http.ResponseWriter, r *http.Request, realm string) {
	groups, err := s.provider().ListGroups(r.Context(), realm)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

func (s *Server) ListIdentityProviders(w http.ResponseWriter, r *http.Request, realm string) {
	idps, err := s.provider().ListIdentityProviders(r.Context(), realm)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, idps)
}

func (s *Server) CreateIdentityProvider(w http.ResponseWriter, r *http.Request, realm string) {
	var body idp.IdentityProvider
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON", nil)
		return
	}
	if err := s.provider().CreateIdentityProvider(r.Context(), realm, body); err != nil {
		writeProviderError(w, err, "identity server error")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) ListClientScopes(w http.ResponseWriter, r *http.Request, realm string) {
	scopes, err := s.provider().ListClientScopes(r.Context(), realm)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, scopes)
}

func (s *Server) ListEvents(w http.ResponseWriter, r *http.Request, realm string) {
	events, err := s.provider().ListAdminEvents(r.Context(), realm)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) ListKeys(w http.ResponseWriter, r *http.Request, realm string) {
	keys, err := s.provider().ListKeys(r.Context(), realm)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) ListAllClients(w http.ResponseWriter, r *http.Request) {
	realms, err := s.provider().ListRealms(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error(), nil)
		return
	}
	type clientWithRealm struct {
		idp.Client
		Realm string `json:"realm"`
	}
	var all []clientWithRealm
	for _, rl := range realms {
		if rl.Realm == "master" {
			continue
		}
		clients, err := s.provider().ListClients(r.Context(), rl.Realm)
		if err != nil {
			continue
		}
		for _, c := range clients {
			all = append(all, clientWithRealm{Client: c, Realm: rl.Realm})
		}
	}
	writeJSON(w, http.StatusOK, all)
}
