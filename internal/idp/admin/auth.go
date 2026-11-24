// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

const (
	msgUnauth    = "invalid or missing token"
	msgForbidden = "forbidden"
)

// authenticate validates the bearer token. On success it returns the actor
// (a client or user, used only for audit) and status 0; otherwise the HTTP
// status and message to send.
func (a *api) authenticate(r *http.Request) (actor string, status int, msg string) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", http.StatusUnauthorized, msgUnauth
	}
	tok := strings.TrimSpace(h[7:])
	if tok == "" || len(tok) > 8192 {
		return "", http.StatusUnauthorized, msgUnauth
	}
	ctx := r.Context()
	cl, err := a.cfg.Signer.Verify(ctx, a.cfg.AdminRealm, tok)
	if err != nil {
		return "", http.StatusUnauthorized, msgUnauth
	}
	if s, _ := cl["iss"].(string); s != a.issuer {
		return "", http.StatusUnauthorized, msgUnauth
	}
	if t, _ := cl["typ"].(string); t != "Bearer" {
		return "", http.StatusUnauthorized, msgUnauth
	}
	if _, bound := cl["cnf"]; bound { // sender-constrained (DPoP) tokens are not accepted as bearer tokens here
		return "", http.StatusUnauthorized, msgUnauth
	}
	exp, ok := numClaim(cl["exp"])
	if !ok || !a.cfg.Clock().Before(time.Unix(exp, 0)) {
		return "", http.StatusUnauthorized, msgUnauth
	}
	sub, _ := cl["sub"].(string)
	if sub == "" {
		return "", http.StatusUnauthorized, msgUnauth
	}

	rl, err := a.cfg.Store.GetRealm(ctx, a.cfg.AdminRealm)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return "", http.StatusUnauthorized, msgUnauth
		}
		a.cfg.Logger.Error("admin: auth realm lookup", "err", err.Error())
		return "", http.StatusInternalServerError, "internal error"
	}
	if !rl.Enabled {
		return "", http.StatusUnauthorized, msgUnauth
	}

	// Service account of an allowed admin client; re-checked in the Store.
	if cid, _ := cl["client_id"].(string); cid != "" {
		if sub != "service-account-"+cid || !slices.Contains(a.cfg.AdminClients, cid) {
			return "", http.StatusForbidden, msgForbidden
		}
		c, err := a.cfg.Store.GetClientByClientID(ctx, rl.Name, cid)
		if err != nil {
			if errors.Is(err, idp.ErrNotFound) {
				return "", http.StatusForbidden, msgForbidden
			}
			a.cfg.Logger.Error("admin: auth client lookup", "err", err.Error())
			return "", http.StatusInternalServerError, "internal error"
		}
		if !c.Enabled || c.Public || !c.ServiceAccount {
			return "", http.StatusForbidden, msgForbidden
		}
		return "client:" + cid, 0, ""
	}

	// A user holding the admin realm role; the user is re-checked too.
	if !tokenHasRole(cl, adminRole) {
		return "", http.StatusForbidden, msgForbidden
	}
	u, err := a.cfg.Store.GetUser(ctx, rl.Name, sub)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return "", http.StatusForbidden, msgForbidden
		}
		a.cfg.Logger.Error("admin: auth user lookup", "err", err.Error())
		return "", http.StatusInternalServerError, "internal error"
	}
	if !u.Enabled || !slices.Contains(u.Roles, adminRole) {
		return "", http.StatusForbidden, msgForbidden
	}
	return "user:" + u.ID, 0, ""
}

func tokenHasRole(cl core.Claims, role string) bool {
	ra, _ := cl["realm_access"].(map[string]any)
	roles, _ := ra["roles"].([]any)
	for _, x := range roles {
		if s, _ := x.(string); s == role {
			return true
		}
	}
	return false
}

// numClaim reads a numeric claim, which Verify decodes as json.Number.
func numClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		if f, err := n.Float64(); err == nil {
			return int64(f), true
		}
	case float64:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}
