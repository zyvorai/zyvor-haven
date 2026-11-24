// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
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
	m.HandleFunc("POST "+p+"/{id}/send-verify-email", a.op("user", "action", a.sendMail(core.ActionVerifyEmail)))
	m.HandleFunc("POST "+p+"/{id}/send-reset-email", a.op("user", "action", a.sendMail(core.ActionResetPassword)))
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
	present, err := decode(r, &in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	next, err := applyUser(cur, in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// A changed address is unproven until its owner clicks a link, unless the
	// admin explicitly asserts emailVerified:true in this request.
	oldMail, newMail := strings.TrimSpace(cur.Email), strings.TrimSpace(in.Email)
	changed := !strings.EqualFold(oldMail, newMail)
	if changed {
		next.EmailVerified = present["emailVerified"] && in.EmailVerified && newMail != ""
	}
	if err := a.cfg.Store.UpdateUser(r.Context(), next); err != nil {
		a.fail(w, r, err)
		return
	}
	if changed {
		a.emailChanged(rl, next)
	}
	if cur.Enabled && !next.Enabled {
		a.dropUserSessions(r.Context(), rl.Name, next.ID)
	}
	a.audit(r, rl, "UPDATE", "user", next.Username)
	noContent(w)
}

// emailChanged runs after the address on u was changed. Links sent to the old
// address are already unusable (tokens are bound to the address); deleting
// them also resets the rate-limit counters so the new address is not blocked.
// If the new address is unverified and email is configured, a verification
// link is sent to it, best effort and in the background: failures are logged
// and never fail the update.
func (a *api) emailChanged(rl core.Realm, u core.User) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, purpose := range []string{core.ActionVerifyEmail, core.ActionResetPassword} {
		if _, err := a.cfg.Store.DeleteActionTokens(ctx, rl.Name, u.ID, purpose); err != nil {
			a.cfg.Logger.Error("admin: delete action tokens after email change", "purpose", purpose, "err", err.Error())
		}
	}
	if u.EmailVerified || strings.TrimSpace(u.Email) == "" || !u.Enabled || !a.cfg.Actions.Enabled() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := a.cfg.Actions.Send(ctx, rl, u, core.ActionVerifyEmail, actions.SendOpts{}); err != nil {
			a.cfg.Logger.Error("admin: send verification after email change", "err", err.Error())
		}
	}()
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
	a.dropUserSessions(r.Context(), rl.Name, cur.ID) // notify clients before the rows cascade away
	if err := a.cfg.Store.DeleteUser(r.Context(), rl.Name, cur.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.dropFedLinks(r.Context(), rl.Name, cur.ID) // federation.go
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
	if err := password.CheckPolicyFor(rl.PasswordPolicy, in.Value, password.Personal{
		Username: cur.Username, Email: cur.Email, FirstName: cur.FirstName, LastName: cur.LastName}); err != nil {
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
	a.dropUserSessions(r.Context(), rl.Name, cur.ID)
	a.audit(r, rl, "ACTION", "user-password", cur.Username)
	if a.cfg.Actions.Enabled() && cur.Email != "" {
		// Best-effort notification to the address on file; no link, no password.
		detached := context.WithoutCancel(r.Context()) // outlives the response, keeps request values
		go func(rl core.Realm, u core.User) {
			ctx, cancel := context.WithTimeout(detached, 30*time.Second)
			defer cancel()
			if err := a.cfg.Actions.Notify(ctx, rl, u, mail.KindPasswordChanged, "an administrator"); err != nil {
				a.cfg.Logger.Error("admin: password change notification failed", "realm", rl.Name, "user", u.ID, "err", err)
			}
		}(rl, cur)
	}
	noContent(w)
}

// sendMail emails the user a single-use verification or password-reset link.
// The link itself is never returned: only the address on file receives it.
func (a *api) sendMail(purpose string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rl, ok := a.realmOf(w, r)
		if !ok {
			return
		}
		if !a.cfg.Actions.Enabled() {
			a.fail(w, r, &httpErr{http.StatusConflict, "email is not configured"})
			return
		}
		u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if !u.Enabled {
			a.fail(w, r, bad("user is disabled"))
			return
		}
		switch err := a.cfg.Actions.Send(r.Context(), rl, u, purpose, actions.SendOpts{}); {
		case err == nil:
		case errors.Is(err, actions.ErrNoEmail):
			a.fail(w, r, bad("user has no email address"))
			return
		case errors.Is(err, actions.ErrRateLimited):
			a.fail(w, r, &httpErr{http.StatusTooManyRequests, "too many emails sent to this user recently"})
			return
		default:
			a.cfg.Logger.Error("admin: send action email", "purpose", purpose, "err", err.Error())
			a.fail(w, r, &httpErr{http.StatusBadGateway, "could not send email"})
			return
		}
		a.audit(r, rl, "ACTION", "user-"+purpose, u.Username)
		noContent(w)
	}
}
