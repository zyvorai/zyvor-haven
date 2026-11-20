// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"net/http"
	"strings"

	"github.com/zyvorai/haven/internal/auth"
	"github.com/zyvorai/haven/internal/keycloak"
	"github.com/zyvorai/haven/internal/plane"
)

func NewRouter(kc *keycloak.Manager, pr *plane.Reader, sessions *auth.Store) http.Handler {
	s := &Server{KC: kc, Plane: pr, Auth: sessions}
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /api/v1/health", s.Health)
	mux.HandleFunc("GET /api/v1/auth/providers", s.AuthProviders)
	mux.HandleFunc("POST /api/v1/auth/login", s.AuthLogin)
	mux.HandleFunc("GET /api/v1/auth/session", s.AuthSession)
	mux.HandleFunc("POST /api/v1/auth/logout", s.AuthLogout)
	mux.HandleFunc("GET /api/v1/auth/oidc/login", s.OIDCLogin)
	mux.HandleFunc("GET /api/v1/auth/oidc/callback", s.OIDCCallback)
	mux.HandleFunc("POST /api/v1/auth/password", requireAuth(s, s.ChangeConsolePassword))

	// Protected
	mux.HandleFunc("GET /api/v1/plane/status", requireAuth(s, s.PlaneStatus))
	mux.HandleFunc("GET /api/v1/plane/capabilities", requireAuth(s, s.PlaneCapabilities))
	mux.HandleFunc("POST /api/v1/planes", requireAuth(s, s.CreatePlane))
	mux.HandleFunc("GET /api/v1/keycloak/status", requireAuth(s, s.KeycloakStatus))
	mux.HandleFunc("GET /api/v1/keycloak/config", requireAuth(s, s.KeycloakConfig))
	mux.HandleFunc("POST /api/v1/keycloak/connect", requireAuth(s, s.ConnectKeycloak))
	mux.HandleFunc("POST /api/v1/keycloak/admin-password", requireAuth(s, s.ChangeKeycloakAdminPassword))
	mux.HandleFunc("GET /api/v1/realms", requireAuth(s, s.ListRealms))
	mux.HandleFunc("POST /api/v1/realms", requireAuth(s, s.CreateRealm))
	mux.HandleFunc("GET /api/v1/clients", requireAuth(s, s.ListAllClients))
	mux.HandleFunc("GET /api/v1/security/posture", requireAuth(s, s.SecurityPosture))
	mux.HandleFunc("GET /api/v1/security/posture/sarif", requireAuth(s, s.SecurityPostureSARIF))
	mux.HandleFunc("GET /api/v1/time-machine/snapshots", requireAuth(s, s.ListTimeMachineSnapshots))
	mux.HandleFunc("POST /api/v1/time-machine/snapshots", requireAuth(s, s.CreateTimeMachineSnapshot))
	mux.Handle("/api/v1/time-machine/snapshots/", requireAuth(s, timeMachineSubroutes(s)))
	mux.HandleFunc("GET /api/v1/credentials", requireAuth(s, s.ListCredentials))
	mux.Handle("/api/v1/credentials/", requireAuth(s, credentialSubroutes(s)))
	mux.HandleFunc("GET /api/v1/federation/catalog", requireAuth(s, s.FederationCatalog))
	mux.HandleFunc("GET /api/v1/federation/connections", requireAuth(s, s.ListFederationConnections))
	mux.HandleFunc("POST /api/v1/federation/connections", requireAuth(s, s.CreateFederationConnection))
	mux.Handle("/api/v1/federation/connections/", requireAuth(s, federationSubroutes(s)))

	mux.Handle("/api/v1/realms/", requireAuth(s, realmSubroutes(s)))

	return mux
}

func realmSubroutes(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/realms/")
		parts := strings.Split(path, "/")
		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		realm := parts[0]
		rest := parts[1:]

		if len(rest) == 0 {
			switch r.Method {
			case http.MethodGet:
				s.GetRealm(w, r, realm)
			case http.MethodPut:
				s.UpdateRealm(w, r, realm)
			case http.MethodDelete:
				s.DeleteRealm(w, r, realm)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}

		switch rest[0] {
		case "clients":
			handleClients(s, w, r, realm, rest[1:])
		case "users":
			handleUsers(s, w, r, realm, rest[1:])
		case "roles":
			handleRoles(s, w, r, realm, rest[1:])
		case "groups":
			if r.Method == http.MethodGet && len(rest) == 1 {
				s.ListGroups(w, r, realm)
				return
			}
			http.NotFound(w, r)
		case "identity-providers":
			if r.Method == http.MethodGet && len(rest) == 1 {
				s.ListIdentityProviders(w, r, realm)
				return
			}
			if r.Method == http.MethodPost && len(rest) == 1 {
				s.CreateIdentityProvider(w, r, realm)
				return
			}
			http.NotFound(w, r)
		case "client-scopes":
			if r.Method == http.MethodGet && len(rest) == 1 {
				s.ListClientScopes(w, r, realm)
				return
			}
			http.NotFound(w, r)
		case "events":
			if r.Method == http.MethodGet && len(rest) == 1 {
				s.ListEvents(w, r, realm)
				return
			}
			http.NotFound(w, r)
		case "keys":
			if r.Method == http.MethodGet && len(rest) == 1 {
				s.ListKeys(w, r, realm)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}

func handleClients(s *Server, w http.ResponseWriter, r *http.Request, realm string, rest []string) {
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			s.ListClients(w, r, realm)
		case http.MethodPost:
			s.CreateClient(w, r, realm)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	id := rest[0]
	if len(rest) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.GetClient(w, r, realm, id)
		case http.MethodPut:
			s.UpdateClient(w, r, realm, id)
		case http.MethodDelete:
			s.DeleteClient(w, r, realm, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if rest[1] == "secret" {
		switch r.Method {
		case http.MethodGet:
			s.GetClientSecret(w, r, realm, id)
		case http.MethodPost:
			s.RegenerateClientSecret(w, r, realm, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	http.NotFound(w, r)
}

func handleUsers(s *Server, w http.ResponseWriter, r *http.Request, realm string, rest []string) {
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			s.ListUsers(w, r, realm)
		case http.MethodPost:
			s.CreateUser(w, r, realm)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	id := rest[0]
	if len(rest) == 1 {
		switch r.Method {
		case http.MethodPut:
			s.UpdateUser(w, r, realm, id)
		case http.MethodDelete:
			s.DeleteUser(w, r, realm, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if rest[1] == "password" && r.Method == http.MethodPut {
		s.ResetPassword(w, r, realm, id)
		return
	}
	if rest[1] == "role-mappings" {
		if len(rest) == 2 && r.Method == http.MethodGet {
			s.GetUserRoleMappings(w, r, realm, id)
			return
		}
		if len(rest) == 3 && rest[2] == "realm" && r.Method == http.MethodPost {
			s.AddRealmRoleMappings(w, r, realm, id)
			return
		}
	}
	http.NotFound(w, r)
}

func handleRoles(s *Server, w http.ResponseWriter, r *http.Request, realm string, rest []string) {
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			s.ListRoles(w, r, realm)
		case http.MethodPost:
			s.CreateRole(w, r, realm)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	http.NotFound(w, r)
}
