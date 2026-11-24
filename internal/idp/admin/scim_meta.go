// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func groupIn(name string) idp.Group { return idp.Group{Name: name} }

// ---- discovery: ServiceProviderConfig, ResourceTypes, Schemas ----

func (s *scimAPI) spConfig(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	s.writeJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{scimSchemaSPC},
		"patch":          map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": scimMaxPage},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": true},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "SCIM bearer token", "primary": true,
			"description": "A per-realm SCIM token issued through the Admin API; not an Admin API token.",
			"specUri":     "https://www.rfc-editor.org/rfc/rfc6750",
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": s.loc(rl, "ServiceProviderConfig", "")[:len(s.loc(rl, "ServiceProviderConfig", ""))-1]},
	})
}

func (s *scimAPI) resourceTypeList(rl core.Realm) []map[string]any {
	mk := func(id, name, endpoint, desc, schema string) map[string]any {
		return map[string]any{
			"schemas": []string{scimSchemaRT}, "id": id, "name": name, "endpoint": endpoint, "description": desc,
			"schema": schema,
			"meta":   map[string]any{"resourceType": "ResourceType", "location": s.loc(rl, "ResourceTypes", id)},
		}
	}
	return []map[string]any{
		mk("User", "User", "/Users", "User account", scimSchemaUser),
		mk("Group", "Group", "/Groups", "Group (membership only; name is immutable, no deletion)", scimSchemaGrp),
	}
}

func (s *scimAPI) resourceTypes(w http.ResponseWriter, r *http.Request) {
	list := s.resourceTypeList(scimOf(r).rl)
	if id := r.PathValue("id"); id != "" {
		for _, x := range list {
			if x["id"] == id {
				s.writeJSON(w, http.StatusOK, x)
				return
			}
		}
		s.writeErr(w, errScimNotFound)
		return
	}
	s.writeJSON(w, http.StatusOK, s.listBody(len(list), 1, list))
}

func attr(name, typ, mut, returned, uniq, desc string, multi, required bool, sub ...map[string]any) map[string]any {
	m := map[string]any{"name": name, "type": typ, "multiValued": multi, "required": required, "caseExact": false,
		"mutability": mut, "returned": returned, "uniqueness": uniq, "description": desc}
	if len(sub) > 0 {
		m["subAttributes"] = sub
	}
	return m
}

func (s *scimAPI) schemaList(rl core.Realm) []map[string]any {
	loc := func(id string) map[string]any {
		return map[string]any{"resourceType": "Schema", "location": s.loc(rl, "Schemas", id)}
	}
	user := map[string]any{
		"schemas": []string{scimSchemaSch}, "id": scimSchemaUser, "name": "User",
		"description": "User account. Supported attributes only; other attributes in a request are ignored (POST, PUT) or rejected (PATCH).",
		"attributes": []map[string]any{
			attr("userName", "string", "readWrite", "default", "server", "Unique login name", false, true),
			attr("externalId", "string", "readWrite", "default", "server", "Identifier of the provisioning client", false, false),
			attr("name", "complex", "readWrite", "default", "none", "Name", false, false,
				attr("givenName", "string", "readWrite", "default", "none", "Given name", false, false),
				attr("familyName", "string", "readWrite", "default", "none", "Family name", false, false),
				attr("formatted", "string", "readOnly", "default", "none", "Derived full name", false, false)),
			attr("displayName", "string", "readOnly", "default", "none", "Derived full name", false, false),
			attr("emails", "complex", "readWrite", "default", "none", "At most one address is stored; it is returned as the primary work address", true, false,
				attr("value", "string", "readWrite", "default", "none", "Email address; an address change is unverified until the user confirms it", false, false),
				attr("type", "string", "readOnly", "default", "none", "Always work", false, false),
				attr("primary", "boolean", "readOnly", "default", "none", "Always true", false, false)),
			attr("active", "boolean", "readWrite", "default", "none", "false disables the account and ends its sessions", false, false),
			attr("groups", "complex", "readOnly", "default", "none", "Groups of the user; change membership through /Groups", true, false),
		},
		"meta": loc(scimSchemaUser),
	}
	group := map[string]any{
		"schemas": []string{scimSchemaSch}, "id": scimSchemaGrp, "name": "Group",
		"description": "Group. displayName is immutable after creation and groups cannot be deleted.",
		"attributes": []map[string]any{
			attr("displayName", "string", "immutable", "default", "server", "Group name (no slash)", false, true),
			attr("members", "complex", "readWrite", "default", "none", "Member users (nested groups are not supported)", true, false,
				attr("value", "string", "immutable", "default", "none", "User id", false, true),
				attr("display", "string", "readOnly", "default", "none", "userName", false, false),
				attr("type", "string", "readOnly", "default", "none", "Always User", false, false)),
		},
		"meta": loc(scimSchemaGrp),
	}
	return []map[string]any{user, group}
}

func (s *scimAPI) schemas(w http.ResponseWriter, r *http.Request) {
	list := s.schemaList(scimOf(r).rl)
	if id := r.PathValue("id"); id != "" {
		for _, x := range list {
			if x["id"] == id {
				s.writeJSON(w, http.StatusOK, x)
				return
			}
		}
		s.writeErr(w, errScimNotFound)
		return
	}
	s.writeJSON(w, http.StatusOK, s.listBody(len(list), 1, list))
}

// ---- Admin API: the realm's SCIM token ----

func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}/scim/token"
		m.HandleFunc("GET "+p, a.scimTokenStatus)
		m.HandleFunc("POST "+p, a.op("secret", "create", a.scimTokenIssue))
		m.HandleFunc("DELETE "+p, a.op("secret", "delete", a.scimTokenRevoke))
	})
}

func (a *api) scimStore(w http.ResponseWriter) (core.SCIMStore, bool) {
	ss, ok := core.StoreAs[core.SCIMStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "SCIM is not available on this store")
	}
	return ss, ok
}

func (a *api) scimEndpoint(realm string) string { return a.base + "/realms/" + realm + "/scim/v2" }

func (a *api) scimTokenStatus(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	ss, ok := a.scimStore(w)
	if !ok {
		return
	}
	out := map[string]any{"configured": false, "endpoint": a.scimEndpoint(rl.Name)}
	t, err := ss.GetSCIMToken(r.Context(), rl.Name)
	switch {
	case err == nil && t.RealmID == rl.ID:
		out["configured"], out["readOnly"], out["createdBy"] = true, t.ReadOnly, t.CreatedBy
		out["createdAt"] = t.CreatedAt.UTC().Format(time.RFC3339)
	case err != nil && !errors.Is(err, idp.ErrNotFound):
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// scimTokenIssue creates the realm's SCIM token or rotates it: the old token
// stops working at once. The token is returned this one time; only its hash
// is stored.
func (a *api) scimTokenIssue(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	ss, ok := a.scimStore(w)
	if !ok {
		return
	}
	var in struct {
		ReadOnly bool `json:"readOnly"`
	}
	if r.ContentLength != 0 {
		if _, err := decode(r, &in); err != nil && !errors.Is(err, io.EOF) {
			a.fail(w, r, err)
			return
		}
	}
	sec, err := newSecret()
	if err != nil {
		a.fail(w, r, err)
		return
	}
	tok := "scim_" + sec
	now := a.cfg.Clock().UTC()
	if err := ss.PutSCIMToken(r.Context(), core.SCIMToken{Realm: rl.Name, RealmID: rl.ID, TokenHash: sha256Hex(tok),
		ReadOnly: in.ReadOnly, CreatedBy: actorOf(r), CreatedAt: now}); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "ACTION", "scim-token", "issued")
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "endpoint": a.scimEndpoint(rl.Name),
		"readOnly": in.ReadOnly, "createdAt": now.Format(time.RFC3339)})
}

func (a *api) scimTokenRevoke(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	ss, ok := a.scimStore(w)
	if !ok {
		return
	}
	if err := ss.DeleteSCIMToken(r.Context(), rl.Name); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "ACTION", "scim-token", "revoked")
	noContent(w)
}
