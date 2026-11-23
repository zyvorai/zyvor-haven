// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zyvorai/haven/internal/idp"
	"net/http"
	"net/url"
)

// ListAllUsers walks the admin API in pages so Time Machine does not silently
// truncate realms larger than the console's interactive 100-user page.
func (c *AdminClient) ListAllUsers(ctx context.Context, realm string) ([]User, error) {
	const pageSize = 100
	out := make([]User, 0, pageSize)
	for first := 0; ; first += pageSize {
		var page []User
		path := "/admin/realms/" + url.PathEscape(realm) + "/users?first=" + url.QueryEscape(intString(first)) + "&max=" + url.QueryEscape(intString(pageSize))
		_, _, err := c.do(ctx, http.MethodGet, path, nil, &page)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < pageSize {
			break
		}
	}
	return out, nil
}

func intString(v int) string {
	if v == 0 {
		return "0"
	}
	buf := [24]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func (c *AdminClient) ListUserGroups(ctx context.Context, realm, userID string) ([]Group, error) {
	var groups []Group
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/users/"+url.PathEscape(userID)+"/groups?briefRepresentation=false&max=1000", nil, &groups)
	return groups, err
}

func (c *AdminClient) JoinGroup(ctx context.Context, realm, userID, groupID string) error {
	return idp.CheckStatus(c.do(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(realm)+"/users/"+url.PathEscape(userID)+"/groups/"+url.PathEscape(groupID), nil, nil))
}

// PartialExport asks Keycloak for its native client/group/role representation.
// Haven sanitizes the returned JSON before it is stored.
func (c *AdminClient) PartialExport(ctx context.Context, realm string) (json.RawMessage, error) {
	code, raw, err := c.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(realm)+"/partial-export?exportClients=true&exportGroupsAndRoles=true", nil, nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("partial export failed: status %d: %s", code, string(raw))
	}
	return json.RawMessage(raw), nil
}

func (c *AdminClient) PartialImport(ctx context.Context, realm string, payload json.RawMessage) error {
	return idp.CheckStatus(c.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(realm)+"/partialImport", payload, nil))
}

func (c *AdminClient) CreateGroup(ctx context.Context, realm string, group Group) error {
	return idp.CheckStatus(c.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(realm)+"/groups", group, nil))
}

func (c *AdminClient) GetIdentityProvider(ctx context.Context, realm, alias string) (*IdentityProvider, error) {
	var idp IdentityProvider
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/identity-provider/instances/"+url.PathEscape(alias), nil, &idp)
	return &idp, err
}

func (c *AdminClient) UpdateIdentityProvider(ctx context.Context, realm, alias string, ip IdentityProvider) error {
	return idp.CheckStatus(c.do(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(realm)+"/identity-provider/instances/"+url.PathEscape(alias), ip, nil))
}

func (c *AdminClient) DeleteIdentityProvider(ctx context.Context, realm, alias string) error {
	return idp.CheckStatus(c.do(ctx, http.MethodDelete, "/admin/realms/"+url.PathEscape(realm)+"/identity-provider/instances/"+url.PathEscape(alias), nil, nil))
}

func (c *AdminClient) GetRotatedClientSecret(ctx context.Context, realm, id string) (*ClientSecret, error) {
	var sec ClientSecret
	code, body, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/clients/"+url.PathEscape(id)+"/client-secret/rotated", nil, &sec)
	if err := idp.CheckStatus(code, body, err); err != nil {
		return nil, err
	}
	return &sec, nil
}

func (c *AdminClient) InvalidateRotatedClientSecret(ctx context.Context, realm, id string) error {
	return idp.CheckStatus(c.do(ctx, http.MethodDelete, "/admin/realms/"+url.PathEscape(realm)+"/clients/"+url.PathEscape(id)+"/client-secret/rotated", nil, nil))
}
