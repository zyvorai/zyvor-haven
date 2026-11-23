// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/password"
)

const (
	maxImportUsers  = 1000
	maxImportBody   = 8 << 20
	maxImportErrors = 100
	importPathSufx  = "/users/import"
)

// importActions are the only required actions an import may carry over.
var importActions = []string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}

func (a *api) importRoutes(m *http.ServeMux) {
	m.HandleFunc("POST "+pathPrefix+"/realms/{r}/users/import", a.op("user", "action", a.importUsers))
}

// bodyLimit is the request body cap for a request path.
func bodyLimit(path string) int64 {
	if strings.HasSuffix(path, importPathSufx) {
		return maxImportBody
	}
	return maxBody
}

type importReq struct {
	Users []idp.ImportUser `json:"users"`
}

func (a *api) importUsers(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	var in importReq
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if len(in.Users) > maxImportUsers {
		writeErr(w, http.StatusRequestEntityTooLarge, "too many users in one request")
		return
	}
	ctx := r.Context()
	roles, err := a.cfg.Store.ListRoles(ctx, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	groups, err := a.cfg.Store.ListGroups(ctx, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	roleSet := make(map[string]bool, len(roles))
	for _, x := range roles {
		roleSet[x.Name] = true
	}
	groupSet := make(map[string]bool, len(groups))
	for _, g := range groups {
		groupSet[g.Path] = true
	}

	res := idp.ImportResult{}
	failed := 0
	fail := func(username, reason string) {
		failed++
		if len(res.Errors) < maxImportErrors {
			if len(username) > 255 {
				username = username[:255]
			}
			res.Errors = append(res.Errors, idp.ImportError{Username: username, Reason: reason})
		}
	}
	seen := make(map[string]bool, len(in.Users))
	for _, iu := range in.Users {
		if err := ctx.Err(); err != nil {
			a.fail(w, r, err)
			return
		}
		key := strings.ToLower(iu.Username)
		if seen[key] && iu.Username != "" {
			fail(iu.Username, "duplicate in request")
			continue
		}
		seen[key] = true
		u, reason := a.buildImportUser(rl.Name, iu, roleSet, groupSet)
		if reason != "" {
			fail(iu.Username, reason)
			continue
		}
		_, err := a.cfg.Store.GetUserByUsername(ctx, rl.Name, u.Username)
		switch {
		case err == nil:
			res.Skipped++
			continue
		case !errors.Is(err, idp.ErrNotFound):
			a.cfg.Logger.Error("admin: import lookup", "realm", rl.Name, "err", err.Error())
			fail(iu.Username, "could not be imported")
			continue
		}
		switch err := a.cfg.Store.CreateUser(ctx, u); {
		case err == nil:
			res.Created++
		case errors.Is(err, idp.ErrConflict):
			res.Skipped++
		default:
			a.cfg.Logger.Error("admin: import create", "realm", rl.Name, "err", err.Error())
			fail(iu.Username, "could not be imported")
		}
	}
	a.audit(r, rl, "IMPORT", "users:", fmt.Sprintf("created=%d skipped=%d failed=%d", res.Created, res.Skipped, failed))
	writeJSON(w, http.StatusOK, res)
}

// buildImportUser validates iu with the user-create rules and returns the core
// user, or a reason (never containing the hash).
func (a *api) buildImportUser(realm string, iu idp.ImportUser, roleSet, groupSet map[string]bool) (core.User, string) {
	var acts []string
	for _, x := range iu.RequiredActions {
		if slices.Contains(importActions, x) && !slices.Contains(acts, x) {
			acts = append(acts, x)
		}
	}
	u, err := applyUser(core.User{Realm: realm}, idp.User{
		Username: iu.Username, Email: iu.Email, FirstName: iu.FirstName, LastName: iu.LastName,
		Enabled: iu.Enabled, EmailVerified: iu.EmailVerified, RequiredActions: acts,
	})
	if err != nil {
		var he *httpErr
		if errors.As(err, &he) {
			return u, he.msg
		}
		return u, "invalid user"
	}
	if iu.PasswordHash != "" {
		if len(iu.PasswordHash) > 4096 || password.ValidateEncoded(iu.PasswordHash) != nil {
			return u, "invalid passwordHash"
		}
	}
	if len(iu.Roles) > 100 || len(iu.Groups) > 100 {
		return u, "too many roles or groups"
	}
	for _, n := range iu.Roles {
		if !roleSet[n] {
			return u, "unknown role"
		}
		if !slices.Contains(u.Roles, n) {
			u.Roles = append(u.Roles, n)
		}
	}
	for _, g := range iu.Groups {
		if !groupSet[g] {
			return u, "unknown group"
		}
		if !slices.Contains(u.Groups, g) {
			u.Groups = append(u.Groups, g)
		}
	}
	u.PasswordHash = iu.PasswordHash
	u.CreatedAt = a.cfg.Clock().UTC()
	return u, ""
}
