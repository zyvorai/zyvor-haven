// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package native implements idp.Provider against the haven-idp Admin API
// (see internal/idp/admin/SPEC.md).
package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
)

const (
	maxBody     = 8 << 20
	tokenSkew   = 30 * time.Second
	userPage    = 100
	defaultHTTP = 30 * time.Second
)

// Config configures a Client.
type Config struct {
	BaseURL      string
	Realm        string // admin realm that issues the service-account token
	ClientID     string
	ClientSecret string
	HTTP         *http.Client
}

// Client is an idp.Provider backed by the haven-idp Admin API.
type Client struct {
	baseURL string
	realm   string
	id      string
	secret  string
	http    *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

var _ idp.Provider = (*Client)(nil)

// New builds a Client. A nil cfg.HTTP gets a 30s timeout.
func New(cfg Config) *Client {
	h := cfg.HTTP
	if h == nil {
		h = &http.Client{Timeout: defaultHTTP}
	}
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
		realm:   cfg.Realm,
		id:      cfg.ClientID,
		secret:  cfg.ClientSecret,
		http:    h,
	}
}

// BaseURL returns the haven-idp base URL.
func (c *Client) BaseURL() string { return c.baseURL }

// User returns the service-account client id (mirrors the Keycloak client).
func (c *Client) User() string { return c.id }

// Ping verifies that a token can be obtained and the Admin API answers.
func (c *Client) Ping(ctx context.Context) error {
	return c.call(ctx, http.MethodGet, "/status", nil, nil)
}

func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, errors.New("native: response body too large")
	}
	return b, nil
}

// accessToken returns a cached token or fetches one (single-flight: the mutex
// is held across the fetch so concurrent callers share a single request).
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires.Add(-tokenSkew)) {
		return c.token, nil
	}
	c.token = ""
	endpoint := c.baseURL + "/realms/" + url.PathEscape(c.realm) + "/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.id, c.secret)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		return "", &idp.StatusError{Code: resp.StatusCode, Body: body}
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("native: decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("native: token response has no access_token")
	}
	c.token = tr.AccessToken
	c.expires = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.token, nil
}

func (c *Client) invalidate(tok string) {
	c.mu.Lock()
	if c.token == tok {
		c.token = ""
	}
	c.mu.Unlock()
}

// do performs one request with a bearer token, retrying once on 401 with a
// fresh token. in may be nil, raw bytes (json.RawMessage) or any JSON value.
func (c *Client) do(ctx context.Context, method, path string, in any) (int, []byte, error) {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return 0, nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.accessToken(ctx)
		if err != nil {
			return 0, nil, err
		}
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/admin/v1"+path, rd)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return 0, nil, err
		}
		body, rerr := readLimited(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			return 0, nil, rerr
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.invalidate(tok)
			continue
		}
		return resp.StatusCode, body, nil
	}
}

// call runs a request, maps >=300 to *idp.StatusError and decodes JSON into out.
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	code, body, err := c.do(ctx, method, path, in)
	if err := idp.CheckStatus(code, body, err); err != nil {
		return err
	}
	if out != nil && len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("native: decode response: %w", err)
		}
	}
	return nil
}

func esc(s string) string { return url.PathEscape(s) }

func realmPath(realm string) string { return "/realms/" + esc(realm) }

func list[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var out []T
	if err := c.call(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Status reports Admin API health. Like the Keycloak client, an unreachable
// backend yields Connected=false and no error.
func (c *Client) Status(ctx context.Context) (*idp.Status, error) {
	var st idp.Status
	if err := c.call(ctx, http.MethodGet, "/status", nil, &st); err != nil {
		return &idp.Status{Connected: false, KeycloakURL: c.baseURL}, nil
	}
	st.KeycloakURL = c.baseURL
	return &st, nil
}

// Realms.

func (c *Client) ListRealms(ctx context.Context) ([]idp.Realm, error) {
	return list[idp.Realm](ctx, c, "/realms")
}

func (c *Client) GetRealm(ctx context.Context, realm string) (*idp.Realm, error) {
	var r idp.Realm
	if err := c.call(ctx, http.MethodGet, realmPath(realm), nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) CreateRealm(ctx context.Context, realm idp.Realm) error {
	return c.call(ctx, http.MethodPost, "/realms", realm, nil)
}

func (c *Client) UpdateRealm(ctx context.Context, realm string, body idp.Realm) error {
	return c.call(ctx, http.MethodPut, realmPath(realm), body, nil)
}

func (c *Client) DeleteRealm(ctx context.Context, realm string) error {
	return c.call(ctx, http.MethodDelete, realmPath(realm), nil, nil)
}

func (c *Client) RealmExists(ctx context.Context, name string) (bool, error) {
	err := c.call(ctx, http.MethodGet, realmPath(name), nil, nil)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, idp.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// Clients.

func (c *Client) ListClients(ctx context.Context, realm string) ([]idp.Client, error) {
	return list[idp.Client](ctx, c, realmPath(realm)+"/clients")
}

func clientPath(realm, id string) string { return realmPath(realm) + "/clients/" + esc(id) }

func (c *Client) GetClient(ctx context.Context, realm, id string) (*idp.Client, error) {
	var cl idp.Client
	if err := c.call(ctx, http.MethodGet, clientPath(realm, id), nil, &cl); err != nil {
		return nil, err
	}
	return &cl, nil
}

// CreateClient creates a client. The server returns a generated secret once in
// the response body; the Provider interface has no way to surface it, so
// callers needing it must call RegenerateClientSecret.
func (c *Client) CreateClient(ctx context.Context, realm string, cl idp.Client) error {
	return c.call(ctx, http.MethodPost, realmPath(realm)+"/clients", cl, nil)
}

// CreateClientWithSecret creates a client and returns its generated secret,
// which the server reveals only once. Public clients get an empty secret.
func (c *Client) CreateClientWithSecret(ctx context.Context, realm string, cl idp.Client) (string, string, error) {
	var out struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := c.call(ctx, http.MethodPost, realmPath(realm)+"/clients", cl, &out); err != nil {
		return "", "", err
	}
	return out.ID, out.Secret, nil
}

var _ idp.SecretCreator = (*Client)(nil)

// FindClientByClientID looks a client up with the server-side clientId filter.
func (c *Client) FindClientByClientID(ctx context.Context, realm, clientID string) (*idp.Client, error) {
	got, err := list[idp.Client](ctx, c, realmPath(realm)+"/clients?clientId="+url.QueryEscape(clientID))
	if err != nil {
		return nil, err
	}
	for i := range got {
		if got[i].ClientID == clientID { // never trust the filter alone
			return &got[i], nil
		}
	}
	return nil, nil
}

func (c *Client) UpdateClient(ctx context.Context, realm, id string, cl idp.Client) error {
	return c.call(ctx, http.MethodPut, clientPath(realm, id), cl, nil)
}

func (c *Client) DeleteClient(ctx context.Context, realm, id string) error {
	return c.call(ctx, http.MethodDelete, clientPath(realm, id), nil, nil)
}

func (c *Client) GetClientSecret(ctx context.Context, realm, id string) (*idp.ClientSecret, error) {
	var s idp.ClientSecret
	if err := c.call(ctx, http.MethodGet, clientPath(realm, id)+"/secret", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) RegenerateClientSecret(ctx context.Context, realm, id string) (*idp.ClientSecret, error) {
	var s idp.ClientSecret
	if err := c.call(ctx, http.MethodPost, clientPath(realm, id)+"/secret", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) GetRotatedClientSecret(ctx context.Context, realm, id string) (*idp.ClientSecret, error) {
	var s idp.ClientSecret
	if err := c.call(ctx, http.MethodGet, clientPath(realm, id)+"/secret/rotated", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (c *Client) InvalidateRotatedClientSecret(ctx context.Context, realm, id string) error {
	return c.call(ctx, http.MethodDelete, clientPath(realm, id)+"/secret/rotated", nil, nil)
}

func (c *Client) ListClientScopes(ctx context.Context, realm string) ([]idp.ClientScope, error) {
	return list[idp.ClientScope](ctx, c, realmPath(realm)+"/client-scopes")
}

// Users.

func (c *Client) ListUsers(ctx context.Context, realm, search string) ([]idp.User, error) {
	p := realmPath(realm) + "/users?max=" + strconv.Itoa(userPage)
	if search != "" {
		p += "&search=" + url.QueryEscape(search)
	}
	return list[idp.User](ctx, c, p)
}

// ListAllUsers walks the users route in pages of 100 until a short page.
func (c *Client) ListAllUsers(ctx context.Context, realm string) ([]idp.User, error) {
	out := make([]idp.User, 0, userPage)
	for first := 0; ; first += userPage {
		p := realmPath(realm) + "/users?first=" + strconv.Itoa(first) + "&max=" + strconv.Itoa(userPage)
		page, err := list[idp.User](ctx, c, p)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < userPage {
			return out, nil
		}
	}
}

func userPath(realm, id string) string { return realmPath(realm) + "/users/" + esc(id) }

func (c *Client) CreateUser(ctx context.Context, realm string, u idp.User) error {
	return c.call(ctx, http.MethodPost, realmPath(realm)+"/users", u, nil)
}

func (c *Client) UpdateUser(ctx context.Context, realm, id string, u idp.User) error {
	return c.call(ctx, http.MethodPut, userPath(realm, id), u, nil)
}

func (c *Client) DeleteUser(ctx context.Context, realm, id string) error {
	return c.call(ctx, http.MethodDelete, userPath(realm, id), nil, nil)
}

func (c *Client) ResetPassword(ctx context.Context, realm, id string, pw idp.PasswordReset) error {
	return c.call(ctx, http.MethodPut, userPath(realm, id)+"/password", pw, nil)
}

// EnsureUserPassword creates the user if missing, then sets a non-temporary password.
func (c *Client) EnsureUserPassword(ctx context.Context, realm, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return errors.New("username and password required")
	}
	find := func() (string, error) {
		users, err := c.ListUsers(ctx, realm, username)
		if err != nil {
			return "", err
		}
		for _, u := range users {
			if u.Username == username {
				return u.ID, nil
			}
		}
		return "", nil
	}
	id, err := find()
	if err != nil {
		return err
	}
	if id == "" {
		err := c.CreateUser(ctx, realm, idp.User{Username: username, Enabled: true, EmailVerified: true})
		if err != nil && !errors.Is(err, idp.ErrConflict) {
			return err
		}
		if id, err = find(); err != nil {
			return err
		}
		if id == "" {
			return fmt.Errorf("user %q created but not found", username)
		}
	}
	return c.ResetPassword(ctx, realm, id, idp.PasswordReset{Type: "password", Value: password})
}

// Roles and groups.

func (c *Client) ListRoles(ctx context.Context, realm string) ([]idp.Role, error) {
	return list[idp.Role](ctx, c, realmPath(realm)+"/roles")
}

func (c *Client) CreateRole(ctx context.Context, realm string, role idp.Role) error {
	return c.call(ctx, http.MethodPost, realmPath(realm)+"/roles", role, nil)
}

func (c *Client) GetUserRoleMappings(ctx context.Context, realm, userID string) (*idp.RoleMappings, error) {
	var m idp.RoleMappings
	if err := c.call(ctx, http.MethodGet, userPath(realm, userID)+"/roles", nil, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *Client) AddRealmRoleMappings(ctx context.Context, realm, userID string, roles []idp.Role) error {
	if roles == nil {
		roles = []idp.Role{}
	}
	return c.call(ctx, http.MethodPost, userPath(realm, userID)+"/roles", roles, nil)
}

func (c *Client) ListGroups(ctx context.Context, realm string) ([]idp.Group, error) {
	return list[idp.Group](ctx, c, realmPath(realm)+"/groups")
}

func (c *Client) CreateGroup(ctx context.Context, realm string, group idp.Group) error {
	return c.call(ctx, http.MethodPost, realmPath(realm)+"/groups", group, nil)
}

func (c *Client) ListUserGroups(ctx context.Context, realm, userID string) ([]idp.Group, error) {
	return list[idp.Group](ctx, c, userPath(realm, userID)+"/groups")
}

func (c *Client) JoinGroup(ctx context.Context, realm, userID, groupID string) error {
	return c.call(ctx, http.MethodPut, userPath(realm, userID)+"/groups/"+esc(groupID), nil, nil)
}

// Federation (not implemented by the server in v1; 501/404 surface unchanged).

func (c *Client) ListIdentityProviders(ctx context.Context, realm string) ([]idp.IdentityProvider, error) {
	return list[idp.IdentityProvider](ctx, c, realmPath(realm)+"/identity-providers")
}

func (c *Client) CreateIdentityProvider(ctx context.Context, realm string, ip idp.IdentityProvider) error {
	return c.call(ctx, http.MethodPost, realmPath(realm)+"/identity-providers", ip, nil)
}

func (c *Client) DeleteIdentityProvider(ctx context.Context, realm, alias string) error {
	return c.call(ctx, http.MethodDelete, realmPath(realm)+"/identity-providers/"+esc(alias), nil, nil)
}

// Events, keys, export/import.

func (c *Client) ListAdminEvents(ctx context.Context, realm string) ([]idp.AdminEvent, error) {
	return list[idp.AdminEvent](ctx, c, realmPath(realm)+"/events?max=50")
}

func (c *Client) ListKeys(ctx context.Context, realm string) ([]idp.Key, error) {
	return list[idp.Key](ctx, c, realmPath(realm)+"/keys")
}

func (c *Client) PartialExport(ctx context.Context, realm string) (json.RawMessage, error) {
	code, body, err := c.do(ctx, http.MethodGet, realmPath(realm)+"/export", nil)
	if err := idp.CheckStatus(code, body, err); err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func (c *Client) PartialImport(ctx context.Context, realm string, payload json.RawMessage) error {
	return c.call(ctx, http.MethodPost, realmPath(realm)+"/import", payload, nil)
}

const (
	importChunk     = 500
	maxImportErrors = 100
)

var _ idp.UserImporter = (*Client)(nil)

var _ idp.UserMailer = (*Client)(nil)

// mailError reports a send-* rejection as a sentinel. The *idp.StatusError is
// reachable with errors.As but deliberately does not match errors.Is
// (a 409 here is "no mail configured", not ErrConflict).
type mailError struct {
	sentinel error
	status   *idp.StatusError
}

func (e *mailError) Error() string { return e.sentinel.Error() }
func (e *mailError) Unwrap() error { return e.sentinel }

func (e *mailError) As(target any) bool {
	if t, ok := target.(**idp.StatusError); ok {
		*t = e.status
		return true
	}
	return false
}

// SendVerifyEmail asks the backend to email the user a verification link.
func (c *Client) SendVerifyEmail(ctx context.Context, realm, userID string) error {
	return c.sendMail(ctx, realm, userID, "send-verify-email")
}

// SendResetEmail asks the backend to email the user a password-reset link.
func (c *Client) SendResetEmail(ctx context.Context, realm, userID string) error {
	return c.sendMail(ctx, realm, userID, "send-reset-email")
}

func (c *Client) sendMail(ctx context.Context, realm, userID, route string) error {
	err := c.call(ctx, http.MethodPost, userPath(realm, userID)+"/"+route, nil, nil)
	if se := idp.AsStatus(err); se != nil {
		switch se.Code {
		case http.StatusConflict:
			return &mailError{idp.ErrEmailNotConfigured, se}
		case http.StatusTooManyRequests:
			return &mailError{idp.ErrRateLimited, se}
		}
	}
	return err
}

var _ idp.SessionManager = (*Client)(nil)

// ListSessions lists the live SSO sessions of the realm; userID "" lists all.
func (c *Client) ListSessions(ctx context.Context, realm, userID string) ([]idp.Session, error) {
	path := realmPath(realm) + "/sessions"
	if userID != "" {
		path = userPath(realm, userID) + "/sessions"
	}
	return list[idp.Session](ctx, c, path)
}

// EndSession ends one session (refresh tokens revoked, clients notified).
func (c *Client) EndSession(ctx context.Context, realm, sessionID string) error {
	return c.call(ctx, http.MethodDelete, realmPath(realm)+"/sessions/"+esc(sessionID), nil, nil)
}

// EndUserSessions ends every session of a user and returns how many there were.
func (c *Client) EndUserSessions(ctx context.Context, realm, userID string) (int, error) {
	var out struct {
		Ended int `json:"ended"`
	}
	err := c.call(ctx, http.MethodDelete, userPath(realm, userID)+"/sessions", nil, &out)
	return out.Ended, err
}

// ImportUsers sends users in batches of 500 and sums the results. Per-user
// errors are kept (at most 100 in total). If a request fails, the result so
// far is returned together with the error.
func (c *Client) ImportUsers(ctx context.Context, realm string, users []idp.ImportUser) (*idp.ImportResult, error) {
	total := &idp.ImportResult{}
	for start := 0; start < len(users); start += importChunk {
		end := min(start+importChunk, len(users))
		var part idp.ImportResult
		body := struct {
			Users []idp.ImportUser `json:"users"`
		}{users[start:end]}
		if err := c.call(ctx, http.MethodPost, realmPath(realm)+"/users/import", body, &part); err != nil {
			return total, err
		}
		total.Created += part.Created
		total.Skipped += part.Skipped
		for _, e := range part.Errors {
			if len(total.Errors) < maxImportErrors {
				total.Errors = append(total.Errors, e)
			}
		}
	}
	return total, nil
}
