// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var (
	scimUserAttrs = map[string]bool{
		"id": true, "externalid": true, "username": true, "active": true, "displayname": true,
		"name.givenname": true, "name.familyname": true, "emails": true, "emails.value": true,
	}
	scimExactAttrs = map[string]bool{"id": true, "externalid": true, "members.value": true}
	emailSelRE     = regexp.MustCompile(`(?i)^emails\[(type|primary) eq ("[^"]{0,32}"|true|false)\](\.value)?$`)
)

// userDraft is the SCIM-writable part of a user.
type userDraft struct {
	userName, given, family, email, ext string
	active                              bool
}

func draftOf(u core.User, ext string) userDraft {
	return userDraft{userName: u.Username, given: u.FirstName, family: u.LastName, email: u.Email, ext: ext, active: u.Enabled}
}

func mutErr(detail string) *scimErr { return serr(http.StatusBadRequest, "mutability", detail) }
func valErr(detail string) *scimErr { return serr(http.StatusBadRequest, "invalidValue", detail) }

func strOf(v any) (string, bool) { s, ok := v.(string); return s, ok }

func boolOf(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string: // some provisioning clients send "True" / "False"
		switch strings.ToLower(x) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// pickEmail chooses the primary (else first) address of an emails value.
func pickEmail(v any) (string, error) {
	var list []any
	switch x := v.(type) {
	case []any:
		list = x
	case map[string]any:
		list = []any{x}
	case nil:
		return "", nil
	default:
		return "", valErr("emails must be a list")
	}
	if len(list) > scimMaxEmails {
		return "", valErr("too many emails")
	}
	first, primary := "", ""
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return "", valErr("invalid emails entry")
		}
		val, ok := strOf(m["value"])
		if !ok {
			return "", valErr("emails entries need a string value")
		}
		if i == 0 {
			first = val
		}
		if p, _ := boolOf(m["primary"]); p && primary == "" {
			primary = val
		}
	}
	if primary != "" {
		return primary, nil
	}
	return first, nil
}

// ignoredAttrs are accepted and dropped: the server derives or does not store them.
var ignoredAttrs = map[string]bool{
	"schemas": true, "id": true, "meta": true, "displayname": true, "name.formatted": true,
	"name.middlename": true, "name.honorificprefix": true, "name.honorificsuffix": true,
	"nickname": true, "profileurl": true, "title": true, "usertype": true, "preferredlanguage": true,
	"locale": true, "timezone": true, "phonenumbers": true, "addresses": true, "photos": true,
	"ims": true, "x509certificates": true, "entitlements": true,
	"urn:ietf:params:scim:schemas:extension:enterprise:2.0:user": true,
}

// apply performs one add / replace / remove on the draft. whole is true for
// POST and PUT bodies: unknown attributes are then ignored, as RFC 7644
// requires, where PATCH rejects them with noTarget.
func (d *userDraft) apply(op, path string, val any, whole bool) error {
	path = strings.TrimSpace(path)
	lp := strings.ToLower(path)
	lp = strings.TrimPrefix(lp, strings.ToLower(scimSchemaUser)+":")
	remove := op == "remove"
	if !remove && val == nil && lp != "" {
		return valErr("missing value for " + trunc(path, 64))
	}
	switch {
	case lp == "":
		m, ok := val.(map[string]any)
		if !ok || remove {
			return serr(http.StatusBadRequest, "noTarget", "a path is required")
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if whole && m[k] == nil {
				continue // null = absent in a full body
			}
			if err := d.apply(op, k, m[k], whole); err != nil {
				return err
			}
		}
		return nil
	case lp == "username":
		if remove {
			return mutErr("userName cannot be removed")
		}
		s, ok := strOf(val)
		if !ok || s == "" {
			return valErr("userName must be a non-empty string")
		}
		d.userName = s
	case lp == "active":
		if remove {
			return mutErr("active cannot be removed")
		}
		b, ok := boolOf(val)
		if !ok {
			return valErr("active must be a boolean")
		}
		d.active = b
	case lp == "externalid":
		if remove {
			d.ext = ""
			return nil
		}
		s, ok := strOf(val)
		if !ok || !validText(s, 255) {
			return valErr("externalId must be a string of at most 255 characters")
		}
		d.ext = s
	case lp == "name.givenname" || lp == "name.familyname":
		s := ""
		if !remove {
			var ok bool
			if s, ok = strOf(val); !ok {
				return valErr("name values must be strings")
			}
		}
		if lp == "name.givenname" {
			d.given = s
		} else {
			d.family = s
		}
	case lp == "name":
		if remove {
			d.given, d.family = "", ""
			return nil
		}
		m, ok := val.(map[string]any)
		if !ok {
			return valErr("name must be an object")
		}
		for k, v := range m {
			switch strings.ToLower(k) {
			case "givenname", "familyname":
				s, ok := strOf(v)
				if !ok {
					return valErr("name values must be strings")
				}
				if strings.ToLower(k) == "givenname" {
					d.given = s
				} else {
					d.family = s
				}
			}
		}
		if op == "replace" || whole {
			if _, ok := m["givenName"]; !ok {
				if _, ok := m["givenname"]; !ok {
					d.given = ""
				}
			}
			if _, ok := m["familyName"]; !ok {
				if _, ok := m["familyname"]; !ok {
					d.family = ""
				}
			}
		}
	case lp == "emails":
		if remove {
			d.email = ""
			return nil
		}
		e, err := pickEmail(val)
		if err != nil {
			return err
		}
		d.email = e
	case emailSelRE.MatchString(lp):
		if remove {
			d.email = ""
			return nil
		}
		s, ok := strOf(val)
		if !ok {
			if m, isMap := val.(map[string]any); isMap { // {"value": "..."}
				s, ok = strOf(m["value"])
			}
		}
		if !ok {
			return valErr("emails value must be a string")
		}
		d.email = s
	case lp == "password":
		return mutErr("password synchronization is not supported")
	case lp == "roles" || lp == "groups":
		if whole && lp == "groups" {
			return nil // readOnly on users; membership is managed through /Groups
		}
		return mutErr(lp + " cannot be changed through the Users resource")
	case ignoredAttrs[lp]:
		return nil
	default:
		if whole {
			return nil
		}
		return serr(http.StatusBadRequest, "noTarget", "attribute is not supported: "+trunc(path, 64))
	}
	return nil
}

func (s *scimAPI) groupIndex(ctx context.Context, realm string) (map[string]core.Group, error) {
	gs, err := s.cfg.Store.ListGroups(ctx, realm)
	if err != nil {
		return nil, err
	}
	m := make(map[string]core.Group, len(gs))
	for _, g := range gs {
		m[g.Path] = g
	}
	return m, nil
}

func fullName(u core.User) string { return strings.TrimSpace(u.FirstName + " " + u.LastName) }

func userVersion(u core.User, ext string) string {
	gs := slices.Clone(u.Groups)
	sort.Strings(gs)
	return scimVersion("user", u.ID, u.Username, u.Email, u.FirstName, u.LastName, strconvBool(u.Enabled), ext, strings.Join(gs, "\x01"))
}

func strconvBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (s *scimAPI) userResource(rl core.Realm, u core.User, ext string, gi map[string]core.Group) (map[string]any, string) {
	v := userVersion(u, ext)
	res := map[string]any{
		"schemas":  []string{scimSchemaUser},
		"id":       u.ID,
		"userName": u.Username,
		"active":   u.Enabled,
		"name":     map[string]any{"givenName": u.FirstName, "familyName": u.LastName, "formatted": fullName(u)},
		"meta": map[string]any{"resourceType": "User", "created": u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			"location": s.loc(rl, "Users", u.ID), "version": v},
	}
	if fn := fullName(u); fn != "" {
		res["displayName"] = fn
	}
	if ext != "" {
		res["externalId"] = ext
	}
	if u.Email != "" {
		res["emails"] = []map[string]any{{"value": u.Email, "type": "work", "primary": true}}
	}
	groups := []map[string]any{}
	for _, p := range u.Groups {
		if g, ok := gi[p]; ok {
			groups = append(groups, map[string]any{"value": g.ID, "display": g.Name, "type": "direct", "$ref": s.loc(rl, "Groups", g.ID)})
		}
	}
	res["groups"] = groups
	return res, v
}

func userGetter(u core.User, ext map[string]string) scimGet {
	return func(a string) []any {
		switch a {
		case "id":
			return []any{u.ID}
		case "username":
			return []any{u.Username}
		case "externalid":
			if e := ext[u.ID]; e != "" {
				return []any{e}
			}
		case "active":
			return []any{u.Enabled}
		case "name.givenname":
			return []any{u.FirstName}
		case "name.familyname":
			return []any{u.LastName}
		case "displayname":
			return []any{fullName(u)}
		case "emails", "emails.value":
			if u.Email != "" {
				return []any{u.Email}
			}
		}
		return nil
	}
}

func (s *scimAPI) listUsers(w http.ResponseWriter, r *http.Request) {
	rq := scimOf(r)
	rl := rq.rl
	ctx := r.Context()
	f, err := parseFilterParam(r, scimUserAttrs)
	if err == nil {
		var start, count int
		if start, count, err = paging(r); err == nil {
			var all []core.User
			all, err = s.matchUsers(ctx, rl.Name, f)
			if err == nil {
				page := window(all, start, count)
				var gi map[string]core.Group
				if gi, err = s.groupIndex(ctx, rl.Name); err == nil {
					ids := make([]string, 0, len(page))
					for _, u := range page {
						ids = append(ids, u.ID)
					}
					var ext map[string]string
					if len(ids) > 0 {
						ext, err = s.ss.SCIMExternalIDs(ctx, rl.Name, ids)
					}
					if err == nil {
						res := make([]map[string]any, 0, len(page))
						for _, u := range page {
							m, _ := s.userResource(rl, u, ext[u.ID], gi)
							res = append(res, m)
						}
						s.writeJSON(w, http.StatusOK, s.listBody(len(all), start, res))
						return
					}
				}
			}
		}
	}
	s.ferr(w, r, err)
}

// matchUsers returns the visible users matching f, in store order. A lone
// userName / id / externalId equality uses an index instead of a scan.
func (s *scimAPI) matchUsers(ctx context.Context, realm string, f *fnode) ([]core.User, error) {
	if attr, val, ok := f.eqAttr(); ok {
		var u core.User
		var err error
		switch attr {
		case "username":
			u, err = s.cfg.Store.GetUserByUsername(ctx, realm, val)
		case "id":
			u, err = s.cfg.Store.GetUser(ctx, realm, val)
		case "externalid":
			var id string
			if id, err = s.ss.FindSCIMExternalID(ctx, realm, val); err == nil {
				u, err = s.cfg.Store.GetUser(ctx, realm, id)
			}
		default:
			goto scan
		}
		if errors.Is(err, idp.ErrNotFound) || (err == nil && hidden(u)) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return []core.User{u}, nil
	}
scan:
	var ext map[string]string
	if filterUses(f, "externalid") {
		var err error
		if ext, err = s.ss.SCIMExternalIDs(ctx, realm, nil); err != nil {
			return nil, err
		}
	}
	var out []core.User
	err := s.scanUsers(ctx, realm, func(u core.User) {
		if f == nil || f.eval(userGetter(u, ext), scimExactAttrs) {
			out = append(out, u)
		}
	})
	return out, err
}

func (s *scimAPI) getUser(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	u, err := s.visibleUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	s.sendUser(w, r, http.StatusOK, rl, u)
}

// sendUser writes one user as the response (or 304 for a matching If-None-Match).
func (s *scimAPI) sendUser(w http.ResponseWriter, r *http.Request, code int, rl core.Realm, u core.User) {
	ctx := r.Context()
	gi, err := s.groupIndex(ctx, rl.Name)
	var ext map[string]string
	if err == nil {
		ext, err = s.ss.SCIMExternalIDs(ctx, rl.Name, []string{u.ID})
	}
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	res, v := s.userResource(rl, u, ext[u.ID], gi)
	if code == http.StatusOK && r.Method == http.MethodGet && ifNoneMatch(r, v) {
		w.Header().Set("ETag", v)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	loc := ""
	if code == http.StatusCreated {
		loc = s.loc(rl, "Users", u.ID)
	}
	s.respond(w, code, v, loc, res)
}

// buildUser validates a draft with the Admin API's rules and applies it to base.
func buildUser(base core.User, d userDraft) (core.User, error) {
	if strings.HasPrefix(strings.ToLower(d.userName), scimSAPrefix) {
		return base, valErr("userName is reserved")
	}
	if d.email != "" && (!strings.Contains(d.email, "@") || strings.ContainsAny(d.email, " \t")) {
		return base, valErr("invalid email address")
	}
	next, err := applyUser(base, idp.User{Username: d.userName, Email: d.email, FirstName: d.given, LastName: d.family,
		Enabled: d.active, EmailVerified: base.EmailVerified, RequiredActions: base.PendingActions})
	if err != nil {
		return base, err
	}
	// A changed address is unproven until its owner clicks a link; SCIM can
	// never assert that an address is verified.
	if !strings.EqualFold(strings.TrimSpace(base.Email), strings.TrimSpace(next.Email)) {
		next.EmailVerified = false
	}
	return next, nil
}

func newDraft() userDraft { return userDraft{active: true} }

func (s *scimAPI) createUser(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	ctx := r.Context()
	body, err := s.readJSON(r)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	d := newDraft()
	if err := d.apply("replace", "", body, true); err != nil {
		s.ferr(w, r, err)
		return
	}
	if d.userName == "" {
		s.ferr(w, r, serr(http.StatusBadRequest, "invalidValue", "userName is required"))
		return
	}
	u, err := buildUser(core.User{Realm: rl.Name}, d)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	if d.ext != "" {
		if _, err := s.ss.FindSCIMExternalID(ctx, rl.Name, d.ext); err == nil {
			s.ferr(w, r, idp.ErrConflict)
			return
		} else if !errors.Is(err, idp.ErrNotFound) {
			s.ferr(w, r, err)
			return
		}
	}
	if err := s.cfg.Store.CreateUser(ctx, u); err != nil {
		s.ferr(w, r, err)
		return
	}
	stored, err := s.cfg.Store.GetUserByUsername(ctx, rl.Name, u.Username)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	if d.ext != "" {
		if err := s.ss.SetSCIMExternalID(ctx, rl.Name, stored.ID, d.ext); err != nil {
			_ = s.cfg.Store.DeleteUser(ctx, rl.Name, stored.ID) // do not leave a half-made user
			s.ferr(w, r, err)
			return
		}
	}
	s.audit(r, rl, "CREATE", "user", stored.Username)
	s.sendUser(w, r, http.StatusCreated, rl, stored)
}

// commitUser stores the changes of a PUT or PATCH.
func (s *scimAPI) commitUser(w http.ResponseWriter, r *http.Request, rl core.Realm, cur core.User, curExt string, d userDraft) {
	ctx := r.Context()
	next, err := buildUser(cur, d)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	if d.ext != curExt && d.ext != "" {
		if holder, err := s.ss.FindSCIMExternalID(ctx, rl.Name, d.ext); err == nil && holder != cur.ID {
			s.ferr(w, r, idp.ErrConflict)
			return
		} else if err != nil && !errors.Is(err, idp.ErrNotFound) {
			s.ferr(w, r, err)
			return
		}
	}
	if err := s.cfg.Store.UpdateUser(ctx, next); err != nil {
		s.ferr(w, r, err)
		return
	}
	if d.ext != curExt {
		if err := s.ss.SetSCIMExternalID(ctx, rl.Name, cur.ID, d.ext); err != nil {
			s.ferr(w, r, err)
			return
		}
	}
	if !strings.EqualFold(strings.TrimSpace(cur.Email), strings.TrimSpace(next.Email)) {
		s.emailChanged(rl, next)
	}
	if cur.Enabled && !next.Enabled {
		s.dropUserSessions(ctx, rl.Name, next.ID)
	}
	s.audit(r, rl, "UPDATE", "user", next.Username)
	s.sendUser(w, r, http.StatusOK, rl, next)
}

// loadForWrite loads the user, its externalId and checks If-Match.
func (s *scimAPI) loadForWrite(w http.ResponseWriter, r *http.Request, rl core.Realm) (core.User, string, bool) {
	ctx := r.Context()
	cur, err := s.visibleUser(ctx, rl.Name, r.PathValue("id"))
	var ext map[string]string
	if err == nil {
		ext, err = s.ss.SCIMExternalIDs(ctx, rl.Name, []string{cur.ID})
	}
	if err != nil {
		s.ferr(w, r, err)
		return cur, "", false
	}
	if !ifMatchOK(r, userVersion(cur, ext[cur.ID])) {
		s.ferr(w, r, serr(http.StatusPreconditionFailed, "", "the resource changed; re-read it and retry"))
		return cur, "", false
	}
	return cur, ext[cur.ID], true
}

func (s *scimAPI) putUser(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	cur, ext, ok := s.loadForWrite(w, r, rl)
	if !ok {
		return
	}
	body, err := s.readJSON(r)
	if err != nil {
		s.ferr(w, r, err)
		return
	}
	d := newDraft()
	if err := d.apply("replace", "", body, true); err != nil {
		s.ferr(w, r, err)
		return
	}
	if d.userName == "" {
		s.ferr(w, r, valErr("userName is required"))
		return
	}
	s.commitUser(w, r, rl, cur, ext, d)
}

type patchOp struct {
	Op    string
	Path  string
	Value any
}

func parsePatch(body map[string]any) ([]patchOp, error) {
	ok := false
	if sc, _ := body["schemas"].([]any); sc != nil {
		for _, x := range sc {
			if x == scimSchemaPat {
				ok = true
			}
		}
	}
	if !ok {
		return nil, serr(http.StatusBadRequest, "invalidSyntax", "schemas must include "+scimSchemaPat)
	}
	raw, _ := body["Operations"].([]any)
	if raw == nil {
		raw, _ = body["operations"].([]any)
	}
	if len(raw) == 0 || len(raw) > scimMaxOps {
		return nil, serr(http.StatusBadRequest, "invalidSyntax", "Operations must hold 1 to 100 operations")
	}
	ops := make([]patchOp, 0, len(raw))
	for _, x := range raw {
		m, isMap := x.(map[string]any)
		if !isMap {
			return nil, serr(http.StatusBadRequest, "invalidSyntax", "invalid operation")
		}
		op, _ := m["op"].(string)
		op = strings.ToLower(op)
		if op != "add" && op != "remove" && op != "replace" {
			return nil, serr(http.StatusBadRequest, "invalidSyntax", "op must be add, remove or replace")
		}
		path, _ := m["path"].(string)
		ops = append(ops, patchOp{op, path, m["value"]})
	}
	return ops, nil
}

func (s *scimAPI) patchUser(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	cur, ext, ok := s.loadForWrite(w, r, rl)
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
	d := draftOf(cur, ext)
	for _, o := range ops {
		if err := d.apply(o.Op, o.Path, o.Value, false); err != nil {
			s.ferr(w, r, err)
			return
		}
	}
	s.commitUser(w, r, rl, cur, ext, d)
}

func (s *scimAPI) deleteUser(w http.ResponseWriter, r *http.Request) {
	rl := scimOf(r).rl
	ctx := r.Context()
	cur, _, ok := s.loadForWrite(w, r, rl)
	if !ok {
		return
	}
	s.dropUserSessions(ctx, rl.Name, cur.ID)
	if err := s.cfg.Store.DeleteUser(ctx, rl.Name, cur.ID); err != nil {
		s.ferr(w, r, err)
		return
	}
	s.dropFedLinks(ctx, rl.Name, cur.ID)
	_ = s.ss.SetSCIMExternalID(ctx, rl.Name, cur.ID, "")
	s.audit(r, rl, "DELETE", "user", cur.Username)
	noContent(w)
}
