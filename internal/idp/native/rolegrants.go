// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import (
	"context"
	"net/http"

	"github.com/zyvorai/haven/internal/idp"
)

var _ idp.RoleGranter = (*Client)(nil)

// CreateRoleGrant gives the user a role until req's expiry (time-boxed access).
func (c *Client) CreateRoleGrant(ctx context.Context, realm, userID string, req idp.RoleGrantRequest) (*idp.RoleGrant, error) {
	var out idp.RoleGrant
	if err := c.call(ctx, http.MethodPost, userPath(realm, userID)+"/grants", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListRoleGrants lists a user's grants (active only, or all including ended
// ones); an empty userID lists the realm's active grants.
func (c *Client) ListRoleGrants(ctx context.Context, realm, userID string, activeOnly bool) ([]idp.RoleGrant, error) {
	state := "?state=all"
	if activeOnly {
		state = "?state=active"
	}
	if userID == "" {
		return list[idp.RoleGrant](ctx, c, realmPath(realm)+"/grants?state=active")
	}
	return list[idp.RoleGrant](ctx, c, userPath(realm, userID)+"/grants"+state)
}

// RevokeRoleGrant ends a grant now; endSessions also ends the user's SSO sessions.
func (c *Client) RevokeRoleGrant(ctx context.Context, realm, userID, grantID string, endSessions bool) error {
	path := userPath(realm, userID) + "/grants/" + esc(grantID)
	if endSessions {
		path += "?endSessions=true"
	}
	return c.call(ctx, http.MethodDelete, path, nil, nil)
}
