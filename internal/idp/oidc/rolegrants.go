// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"slices"

	"github.com/zyvorai/haven/internal/idp/core"
)

// effectiveRoles is the roles claim of a token issued now: the user's
// permanent roles plus the roles of their active time-boxed grants (see
// core.GrantStore). It runs at ISSUE time on every path that calls issue
// (authorization_code, refresh_token and any grant registered with
// registerGrant that issues through it), so a grant shows up in the next
// token and is gone from the first refresh after it expires or is revoked.
//
// The result is never nil. A grant for a role the user already holds changes
// nothing. If the store has no grant support, nothing is granted. If the
// grant lookup fails, the permanent roles alone are returned (fail closed: a
// temporary privilege is never conferred on an error) and the error is logged.
func (p *Provider) effectiveRoles(ctx context.Context, rl core.Realm, u core.User) []string {
	roles := slices.Clone(u.Roles)
	if roles == nil {
		roles = []string{}
	}
	gs, ok := core.StoreAs[core.GrantStore](p.cfg.Store)
	if !ok {
		return roles
	}
	granted, err := gs.ActiveRoles(ctx, rl.Name, u.ID, p.now())
	if err != nil {
		p.cfg.Logger.Error("oidc: active role grants", "realm", rl.Name, "err", err)
		return roles
	}
	for _, r := range granted {
		if !slices.Contains(roles, r) {
			roles = append(roles, r)
		}
	}
	return roles
}
