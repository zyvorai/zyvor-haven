// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/password"
)

const (
	defaultMax    = 100
	capMax        = 1000
	maxPasswordLn = 1024
	pwAction      = "UPDATE_PASSWORD"
)

func (a *api) userRoutes(m *http.ServeMux) {
	p := pathPrefix + "/realms/{r}/users"
	m.HandleFunc("GET "+p, a.listUsers)
	m.HandleFunc("POST "+p, a.op("user", "create", a.createUser))
	m.HandleFunc("GET "+p+"/{id}", a.getUser)
	m.HandleFunc("PUT "+p+"/{id}", a.op("user", "update", a.updateUser))
	m.HandleFunc("DELETE "+p+"/{id}", a.op("user", "delete", a.deleteUser))
	m.HandleFunc("PUT "+p+"/{id}/password", a.op("user", "action", a.resetPassword))
}

func intParam(r *http.Request, name string, def, min, max int) (int, error) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < min {
		return 0, bad("invalid " + name)
	}
	return min2(n, max), nil
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (a *api) listUsers(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	first, err := intParam(r, "first", 0, 0, 1<<30)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	max, err := intParam(r, "max", defaultMax, 1, capMax)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	search := r.URL.Query().Get("search")
	if len(search) > 200 {
		a.fail(w, r, bad("search too long"))
		return
	}
	us, err := a.cfg.Store.ListUsers(r.Context(), rl.Name, search, first, max)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]idp.User, 0, len(us))
	for _, u := range us {
		out = append(out, userToWire(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) getUser(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, userToWire(u))
}

func (a *api) createUser(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	var in idp.User
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	u, err := applyUser(core.User{Realm: rl.Name}, in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.cfg.Store.CreateUser(r.Context(), u); err != nil {
		a.fail(w, r, err)
		return
	}
	stored, err := a.cfg.Store.GetUserByUsername(r.Context(), rl.Name, u.Username)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "CREATE", "user", stored.Username)
	created(w, pathPrefix+"/realms/"+rl.Name+"/users/"+stored.ID, map[string]string{"id": stored.ID})
}

func (a *api) updateUser(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	cur, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in idp.User
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	next, err := applyUser(cur, in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.cfg.Store.UpdateUser(r.Context(), next); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "user", next.Username)
	noContent(w)
}

func (a *api) deleteUser(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	cur, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.cfg.Store.DeleteUser(r.Context(), rl.Name, cur.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "user", cur.Username)
	noContent(w)
}

func (a *api) resetPassword(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	cur, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in idp.PasswordReset
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.Type != "" && in.Type != "password" {
		a.fail(w, r, bad("type must be password"))
		return
	}
	if in.Value == "" || len(in.Value) > maxPasswordLn {
		a.fail(w, r, bad("invalid password"))
		return
	}
	if err := password.CheckPolicy(rl.PasswordPolicy, in.Value); err != nil {
		a.fail(w, r, bad(err.Error()))
		return
	}
	hash, err := a.cfg.Hasher.Hash(in.Value)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cur.PasswordHash = hash
	cur.FailedLogins = 0
	cur.LockedUntil = time.Time{}
	cur.PendingActions = slices.DeleteFunc(slices.Clone(cur.PendingActions), func(s string) bool { return s == pwAction })
	if in.Temporary {
		cur.PendingActions = append(cur.PendingActions, pwAction)
	}
	if err := a.cfg.Store.UpdateUser(r.Context(), cur); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "ACTION", "user-password", cur.Username)
	noContent(w)
}
