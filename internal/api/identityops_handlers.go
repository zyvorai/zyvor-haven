// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/federation"
	"github.com/zyvorai/haven/internal/identityops"
	"github.com/zyvorai/haven/internal/keycloak"
)

func (s *Server) ListTimeMachineSnapshots(w http.ResponseWriter, r *http.Request) {
	items, err := identityops.DefaultStore().ListSnapshots(strings.TrimSpace(r.URL.Query().Get("realm")))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) CreateTimeMachineSnapshot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Realm  string `json:"realm"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(body.Realm) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "realm is required"})
		return
	}
	snap, err := s.captureRealmSnapshot(r, body.Realm, body.Reason)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	saved, err := identityops.DefaultStore().SaveSnapshot(snap)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func timeMachineSubroutes(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/time-machine/snapshots/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		if len(parts) == 1 {
			switch r.Method {
			case http.MethodGet:
				s.GetTimeMachineSnapshot(w, r, id)
			case http.MethodDelete:
				s.DeleteTimeMachineSnapshot(w, r, id)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
		switch parts[1] {
		case "diff":
			if r.Method == http.MethodGet {
				s.DiffTimeMachineSnapshot(w, r, id)
				return
			}
		case "restore":
			if r.Method == http.MethodPost {
				s.RestoreTimeMachineSnapshot(w, r, id)
				return
			}
		}
		http.NotFound(w, r)
	}
}

func (s *Server) GetTimeMachineSnapshot(w http.ResponseWriter, _ *http.Request, id string) {
	snap, err := identityops.DefaultStore().GetSnapshot(id)
	if err != nil {
		status := http.StatusInternalServerError
		if os.IsNotExist(err) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) DeleteTimeMachineSnapshot(w http.ResponseWriter, _ *http.Request, id string) {
	if err := identityops.DefaultStore().DeleteSnapshot(id); err != nil {
		status := http.StatusInternalServerError
		if os.IsNotExist(err) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) DiffTimeMachineSnapshot(w http.ResponseWriter, r *http.Request, id string) {
	snap, err := identityops.DefaultStore().GetSnapshot(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	live, err := s.captureRealmSnapshot(r, snap.Realm, "live")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	diff, err := identityops.Diff(snap, live)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, diff)
}

func (s *Server) RestoreTimeMachineSnapshot(w http.ResponseWriter, r *http.Request, id string) {
	snap, err := identityops.DefaultStore().GetSnapshot(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	var body struct {
		TargetRealm string `json:"targetRealm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	target := strings.TrimSpace(body.TargetRealm)
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "targetRealm is required"})
		return
	}
	if target == snap.Realm {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "in-place restore is intentionally disabled; restore into a new realm and promote after validation"})
		return
	}
	if strings.ContainsAny(target, "/?# ") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "targetRealm contains invalid characters"})
		return
	}

	kc := s.kc()
	exists, err := kc.RealmExists(r.Context(), target)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if exists {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "target realm already exists"})
		return
	}

	result, err := restoreSnapshot(r, kc, snap, target)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "result": result})
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

type restoreResult struct {
	TargetRealm    string   `json:"targetRealm"`
	Clients        int      `json:"clients"`
	Users          int      `json:"users"`
	Roles          int      `json:"roles"`
	Groups         int      `json:"groups"`
	Providers      int      `json:"providers"`
	AccessBindings int      `json:"accessBindings"`
	NativeImport   bool     `json:"nativeImport"`
	Warnings       []string `json:"warnings,omitempty"`
}

func restoreSnapshot(r *http.Request, kc *keycloak.AdminClient, snap identityops.RealmSnapshot, target string) (restoreResult, error) {
	out := restoreResult{TargetRealm: target}
	realm := snap.RealmConfig
	realm.ID = ""
	realm.Realm = target
	code, raw, err := kc.CreateRealm(r.Context(), realm)
	if err != nil {
		return out, err
	}
	if code >= 300 {
		return out, fmt.Errorf("create realm: %s", string(raw))
	}

	usedNative := false
	if len(snap.PartialExport) > 0 {
		code, raw, err := kc.PartialImport(r.Context(), target, snap.PartialExport)
		if err == nil && code < 300 {
			usedNative = true
			out.NativeImport = true
			out.Roles = len(snap.Roles)
			out.Groups = len(snap.Groups)
			out.Clients = len(snap.Clients)
		} else if err != nil {
			out.Warnings = append(out.Warnings, "native partial import: "+err.Error())
		} else {
			out.Warnings = append(out.Warnings, "native partial import: "+string(raw))
		}
	}
	if !usedNative {
		for _, role := range snap.Roles {
			role.ID = ""
			code, raw, err := kc.CreateRole(r.Context(), target, role)
			if err != nil {
				out.Warnings = append(out.Warnings, "role "+role.Name+": "+err.Error())
				continue
			}
			if code >= 300 && code != http.StatusConflict {
				out.Warnings = append(out.Warnings, "role "+role.Name+": "+string(raw))
				continue
			}
			if code < 300 {
				out.Roles++
			}
		}
		for _, group := range snap.Groups {
			group.ID = ""
			code, raw, err := kc.CreateGroup(r.Context(), target, group)
			if err != nil {
				out.Warnings = append(out.Warnings, "group "+group.Name+": "+err.Error())
				continue
			}
			if code >= 300 && code != http.StatusConflict {
				out.Warnings = append(out.Warnings, "group "+group.Name+": "+string(raw))
				continue
			}
			if code < 300 {
				out.Groups++
			}
		}
	}
	for _, idp := range snap.IdentityProviders {
		code, raw, err := kc.CreateIdentityProvider(r.Context(), target, idp)
		if err != nil {
			out.Warnings = append(out.Warnings, "provider "+idp.Alias+": "+err.Error())
			continue
		}
		if code >= 300 && code != http.StatusConflict {
			out.Warnings = append(out.Warnings, "provider "+idp.Alias+": "+string(raw))
			continue
		}
		if code < 300 {
			out.Providers++
		}
	}
	if !usedNative {
		for _, client := range snap.Clients {
			client.ID = ""
			client.Secret = ""
			code, raw, err := kc.CreateClient(r.Context(), target, client)
			if err != nil {
				out.Warnings = append(out.Warnings, "client "+client.ClientID+": "+err.Error())
				continue
			}
			if code >= 300 && code != http.StatusConflict {
				out.Warnings = append(out.Warnings, "client "+client.ClientID+": "+string(raw))
				continue
			}
			if code < 300 {
				out.Clients++
			}
		}
	}
	for _, user := range snap.Users {
		if strings.HasPrefix(user.Username, "service-account-") {
			continue
		}
		user.ID = ""
		code, raw, err := kc.CreateUser(r.Context(), target, user)
		if err != nil {
			out.Warnings = append(out.Warnings, "user "+user.Username+": "+err.Error())
			continue
		}
		if code >= 300 && code != http.StatusConflict {
			out.Warnings = append(out.Warnings, "user "+user.Username+": "+string(raw))
			continue
		}
		if code < 300 {
			out.Users++
		}
	}
	if len(snap.UserAccess) > 0 {
		restoreUserAccess(r, kc, target, snap.UserAccess, &out)
	}
	return out, nil
}

func restoreUserAccess(r *http.Request, kc *keycloak.AdminClient, realm string, access []identityops.UserAccess, out *restoreResult) {
	roles, _ := kc.ListRoles(r.Context(), realm)
	roleByName := make(map[string]keycloak.Role, len(roles))
	for _, role := range roles {
		roleByName[role.Name] = role
	}
	groups, _ := kc.ListGroups(r.Context(), realm)
	groupByKey := make(map[string]keycloak.Group, len(groups)*2)
	for _, group := range groups {
		groupByKey[group.Name] = group
		if group.Path != "" {
			groupByKey[group.Path] = group
		}
	}
	for _, grant := range access {
		users, err := kc.ListUsers(r.Context(), realm, grant.Username)
		if err != nil {
			out.Warnings = append(out.Warnings, "access "+grant.Username+": "+err.Error())
			continue
		}
		var userID string
		for _, user := range users {
			if user.Username == grant.Username {
				userID = user.ID
				break
			}
		}
		if userID == "" {
			continue
		}
		mapped := make([]keycloak.Role, 0, len(grant.RealmRoles))
		for _, name := range grant.RealmRoles {
			if role, ok := roleByName[name]; ok {
				mapped = append(mapped, role)
			}
		}
		if len(mapped) > 0 {
			code, raw, err := kc.AddRealmRoleMappings(r.Context(), realm, userID, mapped)
			if err != nil || code >= 300 {
				out.Warnings = append(out.Warnings, "role mappings "+grant.Username+": "+string(raw))
			} else {
				out.AccessBindings += len(mapped)
			}
		}
		for _, groupKey := range grant.Groups {
			group, ok := groupByKey[groupKey]
			if !ok || group.ID == "" {
				continue
			}
			code, raw, err := kc.JoinGroup(r.Context(), realm, userID, group.ID)
			if err != nil || code >= 300 {
				out.Warnings = append(out.Warnings, "group mapping "+grant.Username+": "+string(raw))
			} else {
				out.AccessBindings++
			}
		}
	}
}

func (s *Server) captureRealmSnapshot(r *http.Request, realm, reason string) (identityops.RealmSnapshot, error) {
	kc := s.kc()
	rc, err := kc.GetRealm(r.Context(), realm)
	if err != nil {
		return identityops.RealmSnapshot{}, err
	}
	clients, err := kc.ListClients(r.Context(), realm)
	if err != nil {
		return identityops.RealmSnapshot{}, err
	}
	users, err := kc.ListAllUsers(r.Context(), realm)
	if err != nil {
		return identityops.RealmSnapshot{}, err
	}
	roles, err := kc.ListRoles(r.Context(), realm)
	if err != nil {
		return identityops.RealmSnapshot{}, err
	}
	groups, err := kc.ListGroups(r.Context(), realm)
	if err != nil {
		return identityops.RealmSnapshot{}, err
	}
	idps, err := kc.ListIdentityProviders(r.Context(), realm)
	if err != nil {
		return identityops.RealmSnapshot{}, err
	}

	access := make([]identityops.UserAccess, 0, len(users))
	for _, user := range users {
		if user.ID == "" || strings.HasPrefix(user.Username, "service-account-") {
			continue
		}
		grant := identityops.UserAccess{Username: user.Username}
		if mappings, err := kc.GetUserRoleMappings(r.Context(), realm, user.ID); err == nil {
			for _, role := range mappings.RealmMappings {
				grant.RealmRoles = append(grant.RealmRoles, role.Name)
			}
		}
		if memberships, err := kc.ListUserGroups(r.Context(), realm, user.ID); err == nil {
			for _, group := range memberships {
				if group.Path != "" {
					grant.Groups = append(grant.Groups, group.Path)
				} else {
					grant.Groups = append(grant.Groups, group.Name)
				}
			}
		}
		if len(grant.RealmRoles) > 0 || len(grant.Groups) > 0 {
			access = append(access, grant)
		}
	}
	partial, _ := kc.PartialExport(r.Context(), realm)

	return identityops.RealmSnapshot{
		Realm: realm, CreatedAt: time.Now().UTC(), Reason: reason, RealmConfig: *rc,
		Clients: clients, Users: users, Roles: roles, Groups: groups, IdentityProviders: idps,
		UserAccess: access, PartialExport: identityops.SanitizePartialExport(partial),
	}, nil
}

type credentialInventoryItem struct {
	Realm            string     `json:"realm"`
	ClientID         string     `json:"clientId"`
	ClientUUID       string     `json:"clientUuid"`
	Enabled          bool       `json:"enabled"`
	ServiceAccount   bool       `json:"serviceAccount"`
	LastRotatedAt    *time.Time `json:"lastRotatedAt,omitempty"`
	AgeDays          *int       `json:"ageDays,omitempty"`
	RotationDue      bool       `json:"rotationDue"`
	OverlapAvailable bool       `json:"overlapAvailable"`
	RotationTracked  bool       `json:"rotationTracked"`
}

func (s *Server) ListCredentials(w http.ResponseWriter, r *http.Request) {
	kc := s.kc()
	realms, err := kc.ListRealms(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	includeMaster := r.URL.Query().Get("includeMaster") == "1"
	days := rotationDays()
	items := []credentialInventoryItem{}

	for _, realm := range realms {
		if realm.Realm == "master" && !includeMaster {
			continue
		}
		clients, err := kc.ListClients(r.Context(), realm.Realm)
		if err != nil {
			continue
		}
		for _, cl := range clients {
			if cl.ID == "" || cl.PublicClient || cl.BearerOnly {
				continue
			}
			item := credentialInventoryItem{Realm: realm.Realm, ClientID: cl.ClientID, ClientUUID: cl.ID, Enabled: cl.Enabled, ServiceAccount: cl.ServiceAccountsEnabled}
			if rec, ok := identityops.DefaultStore().Rotation(realm.Realm, cl.ID); ok {
				item.RotationTracked = true
				t := rec.LastRotatedAt
				item.LastRotatedAt = &t
				age := int(time.Since(rec.LastRotatedAt).Hours() / 24)
				if age < 0 {
					age = 0
				}
				item.AgeDays = &age
				item.RotationDue = age >= days
			}
			_, code, _ := kc.GetRotatedClientSecret(r.Context(), realm.Realm, cl.ID)
			item.OverlapAvailable = code == http.StatusOK
			items = append(items, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rotationDays": days, "items": items})
}

func credentialSubroutes(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/credentials/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) != 3 {
			http.NotFound(w, r)
			return
		}
		realm, id, action := parts[0], parts[1], parts[2]
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch action {
		case "rotate":
			s.RotateCredential(w, r, realm, id)
		case "retire":
			s.RetireRotatedCredential(w, r, realm, id)
		default:
			http.NotFound(w, r)
		}
	}
}

func (s *Server) RotateCredential(w http.ResponseWriter, r *http.Request, realm, id string) {
	kc := s.kc()
	cl, err := kc.GetClient(r.Context(), realm, id)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if cl.PublicClient || cl.BearerOnly {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "client does not use a confidential client secret"})
		return
	}
	sec, err := kc.RegenerateClientSecret(r.Context(), realm, id)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if sec.Value == "" {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "Keycloak returned an empty client secret"})
		return
	}
	_, code, _ := kc.GetRotatedClientSecret(r.Context(), realm, id)
	overlap := code == http.StatusOK
	rec := identityops.RotationRecord{Realm: realm, ClientID: cl.ClientID, ClientUUID: id, LastRotatedAt: time.Now().UTC(), OverlapAvailable: overlap}
	if err := identityops.DefaultStore().RecordRotation(rec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "secret rotated but rotation metadata could not be saved: " + err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"realm": realm, "clientId": cl.ClientID, "clientUuid": id, "secret": sec.Value,
		"overlapAvailable": overlap,
		"note":             rotationNote(overlap),
	})
}

func (s *Server) RetireRotatedCredential(w http.ResponseWriter, r *http.Request, realm, id string) {
	code, raw, err := s.kc().InvalidateRotatedClientSecret(r.Context(), realm, id)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if code >= 300 && code != http.StatusNotFound {
		writeJSON(w, code, map[string]any{"error": "Keycloak could not invalidate the rotated secret", "keycloak": redactKeycloakError(raw)})
		return
	}
	_ = identityops.DefaultStore().ClearOverlap(realm, id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "overlapAvailable": false})
}

func rotationDays() int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("HAVEN_CLIENT_SECRET_ROTATION_DAYS")))
	if err == nil && v >= 1 && v <= 3650 {
		return v
	}
	return 90
}

func rotationNote(overlap bool) string {
	if overlap {
		return "New secret generated. The previous secret remains available during Keycloak's rotation overlap; update consumers, verify them, then retire the previous secret."
	}
	return "New secret generated. Keycloak did not expose a rotated-secret overlap; update consumers immediately. Enable Keycloak client-secret-rotation policy for staged overlap."
}

func (s *Server) FederationCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, federation.Catalog())
}

func (s *Server) ListFederationConnections(w http.ResponseWriter, r *http.Request) {
	realm := strings.TrimSpace(r.URL.Query().Get("realm"))
	if realm == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "realm is required"})
		return
	}
	items, err := s.kc().ListIdentityProviders(r.Context(), realm)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	for i := range items {
		redactIDP(&items[i])
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) CreateFederationConnection(w http.ResponseWriter, r *http.Request) {
	var req federation.ConnectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	idp, err := federation.BuildIdentityProvider(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	code, raw, err := s.kc().CreateIdentityProvider(r.Context(), req.Realm, idp)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if code >= 300 {
		writeJSON(w, code, map[string]any{"error": "Keycloak rejected the identity provider", "keycloak": redactKeycloakError(raw)})
		return
	}
	redactIDP(&idp)
	writeJSON(w, http.StatusCreated, idp)
}

func federationSubroutes(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/federation/connections/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		realm, alias := parts[0], parts[1]
		switch r.Method {
		case http.MethodDelete:
			s.DeleteFederationConnection(w, r, realm, alias)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *Server) DeleteFederationConnection(w http.ResponseWriter, r *http.Request, realm, alias string) {
	code, raw, err := s.kc().DeleteIdentityProvider(r.Context(), realm, alias)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	if code >= 300 && code != http.StatusNotFound {
		writeJSON(w, code, map[string]any{"error": "Keycloak rejected the delete", "keycloak": redactKeycloakError(raw)})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// redactKeycloakError returns a Keycloak admin-API error body with any
// secret/password/credential/certificate-shaped field scrubbed, so a
// validation-rejection body that happens to echo back submitted config
// can't leak a client secret or IdP credential to the Haven client.
func redactKeycloakError(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "Keycloak rejected the request"
	}
	redactRawValue(v)
	b, err := json.Marshal(v)
	if err != nil {
		return "Keycloak rejected the request"
	}
	return string(b)
}

func redactRawValue(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			lower := strings.ToLower(k)
			if strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "credential") || strings.Contains(lower, "certificate") {
				x[k] = "••••••••"
				continue
			}
			redactRawValue(val)
		}
	case []any:
		for _, item := range x {
			redactRawValue(item)
		}
	}
}

func redactIDP(idp *keycloak.IdentityProvider) {
	if idp.Config == nil {
		return
	}
	for k := range idp.Config {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "certificate") {
			if idp.Config[k] != "" {
				idp.Config[k] = "••••••••"
			}
		}
	}
}
