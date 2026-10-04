// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type AdminClient struct {
	baseURL  string
	user     string
	password string
	http     *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

func NewFromEnv() (*AdminClient, error) {
	base := strings.TrimRight(os.Getenv("KEYCLOAK_URL"), "/")
	if base == "" {
		return nil, fmt.Errorf("KEYCLOAK_URL is required")
	}
	user := os.Getenv("KEYCLOAK_ADMIN_USER")
	if user == "" {
		user = "admin"
	}
	pass := os.Getenv("KEYCLOAK_ADMIN_PASSWORD")
	if pass == "" {
		return nil, fmt.Errorf("KEYCLOAK_ADMIN_PASSWORD is required")
	}
	return New(base, user, pass), nil
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *AdminClient) BaseURL() string { return c.baseURL }

func (c *AdminClient) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return c.accessToken, nil
	}
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "admin-cli")
	form.Set("username", c.user)
	form.Set("password", c.password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/realms/master/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("token request failed: %s", string(body))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	c.accessToken = tok.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return c.accessToken, nil
}

func (c *AdminClient) do(ctx context.Context, method, path string, in any, out any) (int, []byte, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return 0, nil, err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, raw, err
		}
	}
	return resp.StatusCode, raw, nil
}

func (c *AdminClient) ServerInfo(ctx context.Context) (*ServerInfo, error) {
	var info ServerInfo
	_, _, err := c.do(ctx, http.MethodGet, "/admin/serverinfo", nil, &info)
	return &info, err
}

func (c *AdminClient) Status(ctx context.Context) (*Status, error) {
	realms, err := c.ListRealms(ctx)
	if err != nil {
		return &Status{Connected: false, KeycloakURL: c.baseURL}, nil
	}
	info, _ := c.ServerInfo(ctx)
	st := &Status{
		Connected:   true,
		RealmCount:  len(realms),
		KeycloakURL: c.baseURL,
	}
	if info != nil {
		st.Version = info.SystemInfo.Version
	}
	return st, nil
}

func (c *AdminClient) ListRealms(ctx context.Context) ([]Realm, error) {
	var realms []Realm
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms", nil, &realms)
	return realms, err
}

func (c *AdminClient) GetRealm(ctx context.Context, realm string) (*Realm, error) {
	var r Realm
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm), nil, &r)
	return &r, err
}

func (c *AdminClient) CreateRealm(ctx context.Context, realm Realm) (int, []byte, error) {
	return c.do(ctx, http.MethodPost, "/admin/realms", realm, nil)
}

func (c *AdminClient) UpdateRealm(ctx context.Context, realm string, body Realm) (int, []byte, error) {
	return c.do(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(realm), body, nil)
}

func (c *AdminClient) DeleteRealm(ctx context.Context, realm string) (int, []byte, error) {
	return c.do(ctx, http.MethodDelete, "/admin/realms/"+url.PathEscape(realm), nil, nil)
}

func (c *AdminClient) ListClients(ctx context.Context, realm string) ([]Client, error) {
	var clients []Client
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/clients", nil, &clients)
	return clients, err
}

func (c *AdminClient) GetClient(ctx context.Context, realm, id string) (*Client, error) {
	var cl Client
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/clients/"+url.PathEscape(id), nil, &cl)
	return &cl, err
}

func (c *AdminClient) CreateClient(ctx context.Context, realm string, cl Client) (int, []byte, error) {
	return c.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(realm)+"/clients", cl, nil)
}

func (c *AdminClient) UpdateClient(ctx context.Context, realm, id string, cl Client) (int, []byte, error) {
	return c.do(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(realm)+"/clients/"+url.PathEscape(id), cl, nil)
}

func (c *AdminClient) DeleteClient(ctx context.Context, realm, id string) (int, []byte, error) {
	return c.do(ctx, http.MethodDelete, "/admin/realms/"+url.PathEscape(realm)+"/clients/"+url.PathEscape(id), nil, nil)
}

func (c *AdminClient) GetClientSecret(ctx context.Context, realm, id string) (*ClientSecret, error) {
	var sec ClientSecret
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/clients/"+url.PathEscape(id)+"/client-secret", nil, &sec)
	return &sec, err
}

func (c *AdminClient) RegenerateClientSecret(ctx context.Context, realm, id string) (*ClientSecret, error) {
	var sec ClientSecret
	_, _, err := c.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(realm)+"/clients/"+url.PathEscape(id)+"/client-secret", nil, &sec)
	return &sec, err
}

func (c *AdminClient) ListUsers(ctx context.Context, realm string, search string) ([]User, error) {
	path := "/admin/realms/" + url.PathEscape(realm) + "/users?max=100"
	if search != "" {
		path += "&search=" + url.QueryEscape(search)
	}
	var users []User
	_, _, err := c.do(ctx, http.MethodGet, path, nil, &users)
	return users, err
}

func (c *AdminClient) CreateUser(ctx context.Context, realm string, u User) (int, []byte, error) {
	return c.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(realm)+"/users", u, nil)
}

func (c *AdminClient) UpdateUser(ctx context.Context, realm, id string, u User) (int, []byte, error) {
	return c.do(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(realm)+"/users/"+url.PathEscape(id), u, nil)
}

func (c *AdminClient) DeleteUser(ctx context.Context, realm, id string) (int, []byte, error) {
	return c.do(ctx, http.MethodDelete, "/admin/realms/"+url.PathEscape(realm)+"/users/"+url.PathEscape(id), nil, nil)
}

func (c *AdminClient) ResetPassword(ctx context.Context, realm, id string, pw PasswordReset) (int, []byte, error) {
	return c.do(ctx, http.MethodPut, "/admin/realms/"+url.PathEscape(realm)+"/users/"+url.PathEscape(id)+"/reset-password", pw, nil)
}

func (c *AdminClient) ListRoles(ctx context.Context, realm string) ([]Role, error) {
	var roles []Role
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/roles", nil, &roles)
	return roles, err
}

func (c *AdminClient) CreateRole(ctx context.Context, realm string, role Role) (int, []byte, error) {
	return c.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(realm)+"/roles", role, nil)
}

func (c *AdminClient) GetUserRoleMappings(ctx context.Context, realm, userID string) (*RoleMappings, error) {
	var m RoleMappings
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/users/"+url.PathEscape(userID)+"/role-mappings", nil, &m)
	return &m, err
}

func (c *AdminClient) AddRealmRoleMappings(ctx context.Context, realm, userID string, roles []Role) (int, []byte, error) {
	return c.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(realm)+"/users/"+url.PathEscape(userID)+"/role-mappings/realm", roles, nil)
}

func (c *AdminClient) ListGroups(ctx context.Context, realm string) ([]Group, error) {
	var groups []Group
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/groups", nil, &groups)
	return groups, err
}

func (c *AdminClient) ListIdentityProviders(ctx context.Context, realm string) ([]IdentityProvider, error) {
	var idps []IdentityProvider
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/identity-provider/instances", nil, &idps)
	return idps, err
}

func (c *AdminClient) CreateIdentityProvider(ctx context.Context, realm string, idp IdentityProvider) (int, []byte, error) {
	return c.do(ctx, http.MethodPost, "/admin/realms/"+url.PathEscape(realm)+"/identity-provider/instances", idp, nil)
}

func (c *AdminClient) ListClientScopes(ctx context.Context, realm string) ([]ClientScope, error) {
	var scopes []ClientScope
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/client-scopes", nil, &scopes)
	return scopes, err
}

func (c *AdminClient) ListAdminEvents(ctx context.Context, realm string) ([]AdminEvent, error) {
	var events []AdminEvent
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/admin-events?max=50", nil, &events)
	return events, err
}

func (c *AdminClient) ListKeys(ctx context.Context, realm string) ([]Key, error) {
	var keys []Key
	_, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(realm)+"/keys", nil, &keys)
	return keys, err
}

func (c *AdminClient) RealmExists(ctx context.Context, name string) (bool, error) {
	code, _, err := c.do(ctx, http.MethodGet, "/admin/realms/"+url.PathEscape(name), nil, nil)
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

func (c *AdminClient) BootstrapRealm(ctx context.Context, name string) error {
	exists, err := c.RealmExists(ctx, name)
	if err != nil {
		return err
	}
	if !exists {
		realm := Realm{Realm: name, DisplayName: "Private Cloud", Enabled: true}
		code, raw, err := c.CreateRealm(ctx, realm)
		if err != nil {
			return err
		}
		if code >= 300 {
			return fmt.Errorf("create realm: %s", string(raw))
		}
	}
	if err := c.EnsureHavenConsoleClient(ctx, name); err != nil {
		return err
	}
	if exists {
		return nil
	}
	cl := Client{
		ClientID:                  "kubernetes",
		Name:                      "Kubernetes API",
		Enabled:                   true,
		PublicClient:              false,
		Protocol:                  "openid-connect",
		StandardFlowEnabled:       true,
		DirectAccessGrantsEnabled: false,
	}
	code, raw, err := c.CreateClient(ctx, name, cl)
	if err != nil {
		return err
	}
	if code >= 300 && code != http.StatusConflict {
		return fmt.Errorf("create client %s: %s", cl.ClientID, string(raw))
	}
	return nil
}
