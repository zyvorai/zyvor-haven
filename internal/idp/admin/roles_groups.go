// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/http"
	"slices"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func (a *api) roleGroupRoutes(m *http.ServeMux) {
	p := pathPrefix + "/realms/{r}"
	m.HandleFunc("GET "+p+"/roles", a.listRoles)
	m.HandleFunc("POST "+p+"/roles", a.op("role", "create", a.createRole))
	m.HandleFunc("GET "+p+"/groups", a.listGroups)
	m.HandleFunc("POST "+p+"/groups", a.op("group", "create", a.createGroup))
	m.HandleFunc("GET "+p+"/users/{id}/roles", a.userRoles)
	m.HandleFunc("POST "+p+"/users/{id}/roles", a.op("role", "action", a.addUserRoles))
	m.HandleFunc("GET "+p+"/users/{id}/groups", a.userGroups)
	m.HandleFunc("PUT "+p+"/users/{id}/groups/{gid}", a.op("group", "action", a.joinGroup))
}

func (a *api) listRoles(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	rs, err := a.cfg.Store.ListRoles(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]idp.Role, 0, len(rs))
	for _, x := range rs {
		out = append(out, roleToWire(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func validRole(in idp.Role) error {
	if !roleNameRE.MatchString(in.Name) || !validText(in.Description, 1024) {
		return bad("invalid role name or description")
	}
	return nil
}

func (a *api) createRole(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	var in idp.Role
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := validRole(in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.cfg.Store.CreateRole(r.Context(), core.Role{Realm: rl.Name, Name: in.Name, Description: in.Description}); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "CREATE", "role", in.Name)
	id := ""
	if rs, err := a.cfg.Store.ListRoles(r.Context(), rl.Name); err == nil {
		for _, x := range rs {
			if x.Name == in.Name {
				id = x.ID
			}
		}
	}
	if id == "" {
		id = in.Name
	}
	created(w, pathPrefix+"/realms/"+rl.Name+"/roles", map[string]string{"id": id})
}

func (a *api) listGroups(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	gs, err := a.cfg.Store.ListGroups(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]idp.Group, 0, len(gs))
	for _, x := range gs {
		out = append(out, groupToWire(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func validGroup(in idp.Group) error {
	if in.Name == "" || !validText(in.Name, 255) || strings.Contains(in.Name, "/") || strings.TrimSpace(in.Name) != in.Name {
		return bad("invalid group name")
	}
	return nil
}

func (a *api) createGroup(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	var in idp.Group
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := validGroup(in); err != nil {
		a.fail(w, r, err)
		return
	}
	path := "/" + in.Name
	if in.Path != "" && in.Path != path {
		a.fail(w, r, bad("group path must be /name"))
		return
	}
	if err := a.cfg.Store.CreateGroup(r.Context(), core.Group{Realm: rl.Name, Name: in.Name, Path: path}); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "CREATE", "group", in.Name)
	id := ""
	if gs, err := a.cfg.Store.ListGroups(r.Context(), rl.Name); err == nil {
		for _, x := range gs {
			if x.Path == path {
				id = x.ID
			}
		}
	}
	if id == "" {
		id = path
	}
	created(w, pathPrefix+"/realms/"+rl.Name+"/groups", map[string]string{"id": id})
}

// ---- user membership ----

func (a *api) userRoles(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	known, err := a.cfg.Store.ListRoles(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := idp.RoleMappings{RealmMappings: []idp.Role{}}
	for _, name := range u.Roles {
		role := idp.Role{Name: name}
		for _, k := range known {
			if k.Name == name {
				role = roleToWire(k)
			}
		}
		out.RealmMappings = append(out.RealmMappings, role)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) addUserRoles(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in []idp.Role
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if len(in) > 100 {
		a.fail(w, r, bad("too many roles"))
		return
	}
	known, err := a.cfg.Store.ListRoles(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	roles := slices.Clone(u.Roles)
	for _, want := range in {
		if !slices.ContainsFunc(known, func(k core.Role) bool { return k.Name == want.Name }) {
			a.fail(w, r, bad("unknown role"))
			return
		}
		if !slices.Contains(roles, want.Name) {
			roles = append(roles, want.Name)
		}
	}
	u.Roles = roles
	if err := a.cfg.Store.UpdateUser(r.Context(), u); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "ACTION", "user-roles", u.Username)
	noContent(w)
}

func (a *api) userGroups(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	known, err := a.cfg.Store.ListGroups(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := []idp.Group{}
	for _, path := range u.Groups {
		g := idp.Group{Name: strings.TrimPrefix(path, "/"), Path: path}
		for _, k := range known {
			if k.Path == path {
				g = groupToWire(k)
			}
		}
		out = append(out, g)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) joinGroup(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	known, err := a.cfg.Store.ListGroups(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	gid := r.PathValue("gid")
	i := slices.IndexFunc(known, func(g core.Group) bool { return g.ID == gid })
	if i < 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !slices.Contains(u.Groups, known[i].Path) {
		u.Groups = append(slices.Clone(u.Groups), known[i].Path)
		if err := a.cfg.Store.UpdateUser(r.Context(), u); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	a.audit(r, rl, "ACTION", "user-group", u.Username)
	noContent(w)
}
