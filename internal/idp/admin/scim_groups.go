// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/zyvorai/haven/internal/idp/core"
)

var (
	scimGroupAttrs = map[string]bool{"id": true, "displayname": true, "members.value": true, "members": true}
	memberSelRE    = regexp.MustCompile(`(?i)^members\[value eq "([^"]{1,128})"\]$`)
)

// groupMembers maps a group path to its visible member users in one scan.
func (s *scimAPI) groupMembers(ctx context.Context, realm string) (map[string][]core.User, error) {
	m := map[string][]core.User{}
	err := s.scanUsers(ctx, realm, func(u core.User) {
		for _, p := range u.Groups {
			m[p] = append(m[p], u)
		}
	})
	return m, err
}

func memberIDs(us []core.User) []string {
	ids := make([]string, 0, len(us))
	for _, u := range us {
		ids = append(ids, u.ID)
	}
	sort.Strings(ids)
	return ids
}

func groupVersion(g core.Group, members []core.User) string {
	return scimVersion("group", g.ID, g.Name, strings.Join(memberIDs(members), ","))
}

func (s *scimAPI) groupResource(rl core.Realm, g core.Group, members []core.User, withMembers bool) (map[string]any, string) {
	v := groupVersion(g, members)
	res := map[string]any{
		"schemas":     []string{scimSchemaGrp},
		"id":          g.ID,
		"displayName": g.Name,
		"meta":        map[string]any{"resourceType": "Group", "location": s.loc(rl, "Groups", g.ID), "version": v},
	}
	if withMembers {
		ms := make([]map[string]any, 0, len(members))
		for _, u := range members {
			ms = append(ms, map[string]any{"value": u.ID, "display": u.Username, "type": "User", "$ref": s.loc(rl, "Users", u.ID)})
		}
		res["members"] = ms
	}
	return res, v
}

func (s *scimAPI) findGroup(ctx context.Context, realm, id string) (core.Group, error) {
	gs, err := s.cfg.Store.ListGroups(ctx, realm)
	if err != nil {
		return core.Group{}, err
	}
	for _, g := range gs {
		if g.ID == id {
			return g, nil
		}
	}
	return core.Group{}, errScimNotFound
}

func excluded(r *http.Request, attr string) bool {
	for _, p := range strings.Split(r.URL.Query().Get("excludedAttributes"), ",") {
		if strings.EqualFold(strings.TrimSpace(p), attr) {
			return true
		}
	}
	return false
}

func (s *scimAPI) listGroups(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	ctx := r.Context()
	f, err := parseFilterParam(r, scimGroupAttrs)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	start, count, err := paging(r)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	withMembers := !excluded(r, "members")
	var members map[string][]core.User
	if withMembers || filterUses(f, "members.value") || filterUses(f, "members") {
		if members, err = s.groupMembers(ctx, rl.Name); err != nil {
			s.ferr(w, r, err)
			return
		}
	}
	gs, err := s.cfg.Store.ListGroups(ctx, rl.Name)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].Path < gs[j].Path })
	var match []core.Group
	for _, g := range gs {
		if f == nil || f.eval(groupGetter(g, members[g.Path]), scimExactAttrs) {
			match = append(match, g)
		}
	}
	page := window(match, start, count)
	res := make([]map[string]any, 0, len(page))
	for _, g := range page {
		m, _ := s.groupResource(rl, g, members[g.Path], withMembers)
		res = append(res, m)
	}
	s.writeJSON(w, http.StatusOK, s.listBody(len(match), start, res))
}

func groupGetter(g core.Group, members []core.User) scimGet {
	return func(a string) []any {
		switch a {
		case "id":
			return []any{g.ID}
		case "displayname":
			return []any{g.Name}
		case "members", "members.value":
			out := make([]any, 0, len(members))
			for _, u := range members {
				out = append(out, u.ID)
			}
			return out
		}
		return nil
	}
}

func (s *scimAPI) getGroup(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	g, err := s.findGroup(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	s.sendGroup(w, r, http.StatusOK, rl, g)
}

func (s *scimAPI) sendGroup(w http.ResponseWriter, r *http.Request, code int, rl core.Realm, g core.Group) {
	members, err := s.groupMembers(r.Context(), rl.Name)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	res, v := s.groupResource(rl, g, members[g.Path], true)
	if code == http.StatusOK && r.Method == http.MethodGet && ifNoneMatch(r, v) {
		w.Header().Set("ETag", v)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	loc := ""
	if code == http.StatusCreated {
		loc = s.loc(rl, "Groups", g.ID)
	}
	s.respond(w, code, v, loc, res)
}

// resolveMembers turns a SCIM members value into existing, visible users.
func (s *scimAPI) resolveMembers(ctx context.Context, realm string, v any) ([]core.User, error) {
	var list []any
	switch x := v.(type) {
	case nil:
		return nil, nil
	case []any:
		list = x
	case map[string]any:
		list = []any{x}
	default:
		return nil, valErr("members must be a list")
	}
	if len(list) > scimMaxMembers {
		return nil, valErr("too many members in one request")
	}
	out := make([]core.User, 0, len(list))
	for _, e := range list {
		m, ok := e.(map[string]any)
		id, isStr := "", false
		if ok {
			id, isStr = strOf(m["value"])
		}
		if !isStr || id == "" {
			return nil, valErr("each member needs a value")
		}
		u, err := s.visibleUser(ctx, realm, id)
		if err != nil {
			return nil, valErr("unknown member " + trunc(id, 64))
		}
		out = append(out, u)
	}
	return out, nil
}

// setMembers makes the group's membership equal to want, changing only the
// users that differ. Each change is audited like the Admin API's join.
func (s *scimAPI) setMembers(r *http.Request, rl core.Realm, g core.Group, have []core.User, want map[string]core.User) error {
	ctx := r.Context()
	cur := map[string]bool{}
	for _, u := range have {
		cur[u.ID] = true
		if _, keep := want[u.ID]; !keep {
			u.Groups = slices.DeleteFunc(slices.Clone(u.Groups), func(p string) bool { return p == g.Path })
			if err := s.cfg.Store.UpdateUser(ctx, u); err != nil {
				return err
			}
			s.audit(r, rl, "ACTION", "user-group", u.Username)
		}
	}
	for id, u := range want {
		if cur[id] || slices.Contains(u.Groups, g.Path) {
			continue
		}
		fresh, err := s.visibleUser(ctx, rl.Name, id)
		if err != nil {
			return err
		}
		fresh.Groups = append(slices.Clone(fresh.Groups), g.Path)
		if err := s.cfg.Store.UpdateUser(ctx, fresh); err != nil {
			return err
		}
		s.audit(r, rl, "ACTION", "user-group", fresh.Username)
	}
	return nil
}

func (s *scimAPI) createGroup(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	ctx := r.Context()
	body, err := s.readJSON(r)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	name, _ := body["displayName"].(string)
	if err := validGroup(groupIn(name)); err != nil {
		s.ferr(w, r, err)
		return
	}
	members, err := s.resolveMembers(ctx, rl.Name, body["members"])
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	path := "/" + name
	if err := s.cfg.Store.CreateGroup(ctx, core.Group{Realm: rl.Name, Name: name, Path: path}); err != nil {
		s.ferr(w, r, err)
		return
	}
	s.audit(r, rl, "CREATE", "group", name)
	g, err := s.groupByPath(ctx, rl.Name, path)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	want := map[string]core.User{}
	for _, u := range members {
		want[u.ID] = u
	}
	if err := s.setMembers(r, rl, g, nil, want); err != nil {
		s.ferr(w, r, err)
		return
	}
	s.sendGroup(w, r, http.StatusCreated, rl, g)
}

func (s *scimAPI) groupByPath(ctx context.Context, realm, path string) (core.Group, error) {
	gs, err := s.cfg.Store.ListGroups(ctx, realm)
	if err != nil {
		return core.Group{}, err
	}
	for _, g := range gs {
		if g.Path == path {
			return g, nil
		}
	}
	return core.Group{}, errScimNotFound
}

// loadGroupForWrite loads the group and its members and checks If-Match.
func (s *scimAPI) loadGroupForWrite(w http.ResponseWriter, r *http.Request, rl core.Realm) (core.Group, []core.User, bool) {
	ctx := r.Context()
	g, err := s.findGroup(ctx, rl.Name, r.PathValue("id"))
	var all map[string][]core.User
	if err == nil {
		all, err = s.groupMembers(ctx, rl.Name)
	}
	if err != nil {
		s.ferr(w, r, err)
		return g, nil, false
	}
	if !ifMatchOK(r, groupVersion(g, all[g.Path])) {
		s.ferr(w, r, serr(http.StatusPreconditionFailed, "", "the resource changed; re-read it and retry"))
		return g, nil, false
	}
	return g, all[g.Path], true
}

func (s *scimAPI) putGroup(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	g, have, ok := s.loadGroupForWrite(w, r, rl)
	if !ok {
		return
	}
	body, err := s.readJSON(r)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	if name, _ := body["displayName"].(string); name != g.Name {
		s.ferr(w, r, mutErr("displayName cannot be changed"))
		return
	}
	members, err := s.resolveMembers(r.Context(), rl.Name, body["members"])
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	want := map[string]core.User{}
	for _, u := range members {
		want[u.ID] = u
	}
	if err := s.setMembers(r, rl, g, have, want); err != nil {
		s.ferr(w, r, err)
		return
	}
	s.audit(r, rl, "UPDATE", "group", g.Name)
	s.sendGroup(w, r, http.StatusOK, rl, g)
}

func (s *scimAPI) patchGroup(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	ctx := r.Context()
	g, have, ok := s.loadGroupForWrite(w, r, rl)
	if !ok {
		return
	}
	body, err := s.readJSON(r)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	ops, err := parsePatch(body)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	want := map[string]core.User{}
	for _, u := range have {
		want[u.ID] = u
	}
	for _, o := range ops {
		if err := s.patchGroupOp(ctx, rl.Name, g, want, o); err != nil {
			s.ferr(w, r, err)
			return
		}
	}
	if err := s.setMembers(r, rl, g, have, want); err != nil {
		s.ferr(w, r, err)
		return
	}
	s.audit(r, rl, "UPDATE", "group", g.Name)
	s.sendGroup(w, r, http.StatusOK, rl, g)
}

func (s *scimAPI) patchGroupOp(ctx context.Context, realm string, g core.Group, want map[string]core.User, o patchOp) error {
	path := strings.TrimSpace(o.Path)
	lp := strings.ToLower(strings.TrimPrefix(path, scimSchemaGrp+":"))
	if lp == "" {
		m, ok := o.Value.(map[string]any)
		if !ok || o.Op == "remove" {
			return serr(http.StatusBadRequest, "noTarget", "a path is required")
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := s.patchGroupOp(ctx, realm, g, want, patchOp{o.Op, k, m[k]}); err != nil {
				return err
			}
		}
		return nil
	}
	switch {
	case lp == "displayname":
		if n, _ := o.Value.(string); o.Op == "remove" || n != g.Name {
			return mutErr("displayName cannot be changed")
		}
	case lp == "members":
		switch o.Op {
		case "remove":
			if o.Value == nil {
				clear(want)
				return nil
			}
			us, err := s.resolveMembers(ctx, realm, o.Value)
			if err != nil {
				return err
			}
			for _, u := range us {
				delete(want, u.ID)
			}
		default:
			us, err := s.resolveMembers(ctx, realm, o.Value)
			if err != nil {
				return err
			}
			if o.Op == "replace" {
				clear(want)
			}
			for _, u := range us {
				want[u.ID] = u
			}
			if len(want) > scimMaxMembers*10 {
				return valErr("too many members")
			}
		}
	case memberSelRE.MatchString(path):
		if o.Op != "remove" {
			return serr(http.StatusBadRequest, "invalidPath", "a members filter path is only valid with remove")
		}
		delete(want, memberSelRE.FindStringSubmatch(path)[1])
	case lp == "id" || lp == "meta" || lp == "schemas":
		return nil
	default:
		return serr(http.StatusBadRequest, "noTarget", "attribute is not supported: "+trunc(path, 64))
	}
	return nil
}

// deleteGroup: the store has no group deletion, so SCIM cannot offer it.
func (s *scimAPI) deleteGroup(w http.ResponseWriter, r *http.Request) {
	s.writeErr(w, serr(http.StatusNotImplemented, "", "deleting a group is not supported; remove its members instead"))
}
