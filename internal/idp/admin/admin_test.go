// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

const (
	realm       = "platform"
	adminSecret = "admin-secret-for-tests-0123456789abcdef"
	goodPW      = "correct-horse-battery"
)

type env struct {
	t      *testing.T
	srv    *httptest.Server
	st     *memstore.Store
	signer core.Signer
	hasher core.PasswordHasher
	token  string // haven-admin service-account token
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := memstore.New()
	h := password.New(password.TestParams)
	sg := keys.New(st, keys.Options{})
	e := &env{t: t, st: st, signer: sg, hasher: h}
	var handler http.Handler
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(e.srv.Close)
	if _, err := bootstrap.Run(context.Background(), st, h, sg, bootstrap.Options{
		Realm: realm, AdminClientSecret: adminSecret,
	}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL}))
	mux.Handle("/admin/v1/", admin.New(admin.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL, AdminRealm: realm}))
	handler = mux
	e.token = e.clientToken(realm, "haven-admin", adminSecret)
	return e
}

func (e *env) clientToken(rlm, id, secret string) string {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/realms/"+rlm+"/protocol/openid-connect/token",
		strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || json.Unmarshal(b, &out) != nil || out.AccessToken == "" {
		e.t.Fatalf("client_credentials for %s: %d %s", id, resp.StatusCode, b)
	}
	return out.AccessToken
}

// call sends a JSON request and returns status, body and headers.
func (e *env) call(method, path, token string, body any) (int, []byte, http.Header) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/admin/v1"+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

// api calls with the admin token and requires the wanted status.
func (e *env) api(want int, method, path string, body any) []byte {
	e.t.Helper()
	code, b, _ := e.call(method, path, e.token, body)
	if code != want {
		e.t.Fatalf("%s %s: got %d want %d: %s", method, path, code, want, b)
	}
	return b
}

func (e *env) createID(path string, body any) string {
	e.t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(e.api(201, "POST", path, body), &out); err != nil || out.ID == "" {
		e.t.Fatal("no id in create response")
	}
	return out.ID
}

func TestAuth(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// A service account in the admin realm that is not an admin client.
	e.createID("/realms/"+realm+"/clients", map[string]any{
		"clientId": "rogue", "enabled": true, "serviceAccountsEnabled": true})
	var rogueSecret string
	{
		cs, _ := e.st.ListClients(ctx, realm)
		for _, c := range cs {
			if c.ClientID == "rogue" {
				var out struct{ Value string }
				_ = json.Unmarshal(e.api(200, "POST", "/realms/"+realm+"/clients/"+c.ID+"/secret", nil), &out)
				rogueSecret = out.Value
			}
		}
	}
	e.createID("/realms", map[string]any{"realm": "other", "enabled": true})
	e.createID("/realms/other/clients", map[string]any{"clientId": "haven-admin", "enabled": true, "serviceAccountsEnabled": true})

	// Users: one with the admin role, one without.
	e.createID("/realms/"+realm+"/roles", map[string]any{"name": "haven-admin"})
	e.createID("/realms/"+realm+"/clients", map[string]any{
		"clientId": "app", "enabled": true, "publicClient": true, "standardFlowEnabled": true,
		"redirectUris": []string{"http://localhost/cb"}})
	mk := func(name string, admin bool) string {
		id := e.createID("/realms/"+realm+"/users", map[string]any{"username": name, "enabled": true})
		e.api(204, "PUT", "/realms/"+realm+"/users/"+id+"/password", map[string]any{"type": "password", "value": goodPW})
		if admin {
			e.api(204, "POST", "/realms/"+realm+"/users/"+id+"/roles", []map[string]string{{"name": "haven-admin"}})
		}
		return id
	}
	mk("boss", true)
	mk("pleb", false)
	bossTok := e.login("app", "boss", goodPW)
	plebTok := e.login("app", "pleb", goodPW)

	expired, err := e.signer.Sign(ctx, realm, core.Claims{
		"iss": e.srv.URL + "/realms/" + realm, "sub": "service-account-haven-admin", "client_id": "haven-admin",
		"typ": "Bearer", "exp": time.Now().Add(-time.Hour).Unix(), "realm_access": map[string]any{"roles": []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	wrongIss, _ := e.signer.Sign(ctx, realm, core.Claims{
		"iss": "https://evil.example/realms/" + realm, "sub": "service-account-haven-admin", "client_id": "haven-admin",
		"typ": "Bearer", "exp": time.Now().Add(time.Hour).Unix()})
	idTok, _ := e.signer.Sign(ctx, realm, core.Claims{
		"iss": e.srv.URL + "/realms/" + realm, "sub": "service-account-haven-admin", "client_id": "haven-admin",
		"typ": "ID", "exp": time.Now().Add(time.Hour).Unix()})
	mismatch, _ := e.signer.Sign(ctx, realm, core.Claims{
		"iss": e.srv.URL + "/realms/" + realm, "sub": "service-account-rogue", "client_id": "haven-admin",
		"typ": "Bearer", "exp": time.Now().Add(time.Hour).Unix()})
	noExp, _ := e.signer.Sign(ctx, realm, core.Claims{
		"iss": e.srv.URL + "/realms/" + realm, "sub": "service-account-haven-admin", "client_id": "haven-admin", "typ": "Bearer"})

	for name, tok := range map[string]string{
		"none": "", "garbage": "not.a.jwt", "expired": expired, "wrong issuer": wrongIss,
		"id token": idTok, "no exp": noExp,
	} {
		code, body, hdr := e.call("GET", "/status", tok, nil)
		if code != 401 || hdr.Get("WWW-Authenticate") != "Bearer" || hdr.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: got %d %v %s", name, code, hdr, body)
		}
	}
	// A real token for another realm: signed by a different key.
	{
		secret := e.regen("other", "haven-admin")
		if code, _, _ := e.call("GET", "/status", e.clientToken("other", "haven-admin", secret), nil); code != 401 {
			t.Errorf("other-realm token: got %d", code)
		}
	}
	if code, _, _ := e.call("GET", "/status", mismatch, nil); code != 403 {
		t.Errorf("sub/client mismatch: got %d", code)
	}
	if code, _, _ := e.call("GET", "/status", e.clientToken(realm, "rogue", rogueSecret), nil); code != 403 {
		t.Errorf("non-admin client: got %d", code)
	}
	if code, _, _ := e.call("GET", "/status", plebTok, nil); code != 403 {
		t.Errorf("user without role: got %d", code)
	}
	if code, _, _ := e.call("GET", "/status", bossTok, nil); code != 200 {
		t.Errorf("user with role: got %d", code)
	}
	if code, _, _ := e.call("GET", "/status", e.token, nil); code != 200 {
		t.Errorf("admin client: got %d", code)
	}

	// The Store is re-checked: disable the admin client and the token dies.
	cs, _ := e.st.ListClients(ctx, realm)
	for _, c := range cs {
		if c.ClientID == "haven-admin" {
			c.Enabled = false
			_ = e.st.UpdateClient(ctx, c)
		}
	}
	if code, _, _ := e.call("GET", "/status", e.token, nil); code != 403 {
		t.Errorf("disabled admin client: got %d", code)
	}
	// Unauthenticated callers learn nothing about routes.
	if code, _, _ := e.call("GET", "/nope", "", nil); code != 401 {
		t.Errorf("unauthenticated unknown route: got %d", code)
	}
}

func (e *env) regen(rlm, clientID string) string {
	e.t.Helper()
	cs, _ := e.st.ListClients(context.Background(), rlm)
	for _, c := range cs {
		if c.ClientID == clientID {
			var out struct{ Value string }
			_ = json.Unmarshal(e.api(200, "POST", "/realms/"+rlm+"/clients/"+c.ID+"/secret", nil), &out)
			return out.Value
		}
	}
	e.t.Fatal("client not found")
	return ""
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// login performs an authorization-code + PKCE login with a public client and
// returns the access token.
func (e *env) login(clientID, user, pw string) string {
	e.t.Helper()
	tr := e.loginTokens(clientID, user, pw, "http://localhost/cb")
	return tr["access_token"].(string)
}

func (e *env) loginTokens(clientID, user, pw, redirect string) map[string]any {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "state": {"st"},
		"scope": {"openid"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	authURL := e.srv.URL + "/realms/" + realm + "/protocol/openid-connect/auth?" + q.Encode()
	resp, err := c.Get(authURL)
	if err != nil {
		e.t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfRe.FindSubmatch(page)
	if resp.StatusCode != 200 || m == nil {
		e.t.Fatalf("login page: %d %s", resp.StatusCode, page)
	}
	resp, err = c.PostForm(authURL, url.Values{"username": {user}, "password": {pw}, "csrf": {string(m[1])}})
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc == nil || loc.Query().Get("code") == "" {
		e.t.Fatalf("login did not redirect with a code: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, err = http.PostForm(e.srv.URL+"/realms/"+realm+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {redirect},
		"client_id": {clientID}, "code_verifier": {verifier}})
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || json.Unmarshal(b, &out) != nil {
		e.t.Fatalf("token exchange: %d %s", resp.StatusCode, b)
	}
	return out
}

func TestIDTokenRejected(t *testing.T) {
	e := newEnv(t)
	e.createID("/realms/"+realm+"/roles", map[string]any{"name": "haven-admin"})
	e.createID("/realms/"+realm+"/clients", map[string]any{"clientId": "app", "enabled": true, "publicClient": true,
		"standardFlowEnabled": true, "redirectUris": []string{"http://localhost/cb"}})
	id := e.createID("/realms/"+realm+"/users", map[string]any{"username": "boss", "enabled": true})
	e.api(204, "PUT", "/realms/"+realm+"/users/"+id+"/password", map[string]any{"value": goodPW})
	e.api(204, "POST", "/realms/"+realm+"/users/"+id+"/roles", []map[string]string{{"name": "haven-admin"}})
	tr := e.loginTokens("app", "boss", goodPW, "http://localhost/cb")
	idt, _ := tr["id_token"].(string)
	if idt == "" {
		t.Fatal("no id_token")
	}
	if code, _, _ := e.call("GET", "/status", idt, nil); code != 401 {
		t.Errorf("ID token: got %d", code)
	}
	if code, _, _ := e.call("GET", "/status", tr["access_token"].(string), nil); code != 200 {
		t.Errorf("access token: got %d", code)
	}
}

func TestRealmCRUD(t *testing.T) {
	e := newEnv(t)
	var st struct {
		Connected  bool
		RealmCount int
	}
	_ = json.Unmarshal(e.api(200, "GET", "/status", nil), &st)
	if !st.Connected || st.RealmCount != 1 {
		t.Fatalf("status %+v", st)
	}

	e.createID("/realms", map[string]any{"realm": "acme", "enabled": true, "displayName": "Acme"})
	e.api(409, "POST", "/realms", map[string]any{"realm": "acme", "enabled": true})
	e.api(400, "POST", "/realms", map[string]any{"realm": "ACME", "enabled": true})
	e.api(400, "POST", "/realms", map[string]any{"realm": "Bad Name!", "enabled": true})
	e.api(400, "POST", "/realms", map[string]any{"realm": "x", "enabled": true, "sslRequired": "sometimes"})

	var rl map[string]any
	_ = json.Unmarshal(e.api(200, "GET", "/realms/acme", nil), &rl)
	if rl["sslRequired"] != "external" || rl["passwordPolicy"] != "length(12)" || rl["accessTokenLifespan"] != float64(300) ||
		rl["ssoSessionIdleTimeout"] != float64(1800) || rl["revokeRefreshToken"] != true || rl["bruteForceProtected"] != true ||
		rl["eventsEnabled"] != true || rl["adminEventsEnabled"] != true {
		t.Fatalf("secure defaults missing: %v", rl)
	}
	// Brute-force default can be turned off explicitly.
	e.createID("/realms", map[string]any{"realm": "lax", "enabled": true, "bruteForceProtected": false})
	var lax map[string]any
	_ = json.Unmarshal(e.api(200, "GET", "/realms/lax", nil), &lax)
	if lax["bruteForceProtected"] == true {
		t.Fatal("explicit false ignored")
	}

	e.api(204, "PUT", "/realms/acme", map[string]any{"realm": "acme", "enabled": true, "displayName": "Acme Inc",
		"passwordPolicy": "length(16)", "accessTokenLifespan": 600})
	_ = json.Unmarshal(e.api(200, "GET", "/realms/acme", nil), &rl)
	if rl["displayName"] != "Acme Inc" || rl["passwordPolicy"] != "length(16)" || rl["accessTokenLifespan"] != float64(600) ||
		rl["sslRequired"] != "external" || rl["bruteForceProtected"] != true {
		t.Fatalf("update: %v", rl)
	}
	e.api(400, "PUT", "/realms/acme", map[string]any{"realm": "renamed", "enabled": true})
	e.api(400, "PUT", "/realms/acme", map[string]any{"enabled": true, "accessTokenLifespan": 0})
	e.api(404, "GET", "/realms/missing", nil)

	var list []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", "/realms", nil), &list)
	if len(list) != 3 {
		t.Fatalf("realms: %d", len(list))
	}
	e.api(204, "DELETE", "/realms/acme", nil)
	e.api(404, "GET", "/realms/acme", nil)
	// The admin realm is protected.
	e.api(409, "DELETE", "/realms/"+realm, nil)
	e.api(409, "PUT", "/realms/"+realm, map[string]any{"enabled": false})
}

func TestClientCRUDAndSecrets(t *testing.T) {
	e := newEnv(t)
	base := "/realms/" + realm + "/clients"

	var cr struct{ ID, Secret string }
	_ = json.Unmarshal(e.api(201, "POST", base, map[string]any{
		"clientId": "svc", "enabled": true, "serviceAccountsEnabled": true}), &cr)
	if cr.ID == "" || len(cr.Secret) < 43 {
		t.Fatalf("confidential create must return id and secret: %+v", cr)
	}
	code, _, hdr := e.call("POST", "/realms/"+realm+"/clients", e.token, map[string]any{"clientId": "svc2", "enabled": true})
	if code != 201 || !strings.HasPrefix(hdr.Get("Location"), "/admin/v1/realms/"+realm+"/clients/") {
		t.Errorf("create: %d %v", code, hdr)
	}
	// The secret works against the real token endpoint, and is never shown again.
	e.clientToken(realm, "svc", cr.Secret)
	got := e.api(200, "GET", base+"/"+cr.ID, nil)
	if bytes.Contains(got, []byte(cr.Secret)) || bytes.Contains(got, []byte("secret")) || bytes.Contains(got, []byte(oidc.HashSecret(cr.Secret))) {
		t.Fatalf("GET leaks secret material: %s", got)
	}
	if all := e.api(200, "GET", base, nil); bytes.Contains(all, []byte(cr.Secret)) || bytes.Contains(all, []byte(oidc.HashSecret(cr.Secret))) {
		t.Fatal("list leaks secret material")
	}
	e.api(501, "GET", base+"/"+cr.ID+"/secret", nil)
	e.api(404, "GET", base+"/"+cr.ID+"/secret/rotated", nil)
	e.api(404, "DELETE", base+"/"+cr.ID+"/secret/rotated", nil)

	// Regenerate: the old secret stops working.
	var cs struct{ Type, Value string }
	_ = json.Unmarshal(e.api(200, "POST", base+"/"+cr.ID+"/secret", nil), &cs)
	if cs.Type != "secret" || len(cs.Value) < 43 || cs.Value == cr.Secret {
		t.Fatalf("regenerate: %+v", cs)
	}
	e.clientToken(realm, "svc", cs.Value)
	req, _ := http.NewRequest("POST", e.srv.URL+"/realms/"+realm+"/protocol/openid-connect/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc", cr.Secret)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Errorf("old secret still accepted: %d", resp.StatusCode)
	}

	// Public client: no secret, PKCE on, no regenerate.
	var pc struct{ ID, Secret string }
	_ = json.Unmarshal(e.api(201, "POST", base, map[string]any{"clientId": "spa", "enabled": true, "publicClient": true,
		"standardFlowEnabled": true, "redirectUris": []string{"https://spa.example/cb"}, "webOrigins": []string{"https://spa.example"}}), &pc)
	if pc.Secret != "" {
		t.Fatal("public client got a secret")
	}
	var spa map[string]any
	_ = json.Unmarshal(e.api(200, "GET", base+"/"+pc.ID, nil), &spa)
	attrs, _ := spa["attributes"].(map[string]any)
	if spa["protocol"] != "openid-connect" || attrs["pkce.code.challenge.method"] != "S256" || spa["publicClient"] != true {
		t.Fatalf("spa mapping: %v", spa)
	}
	e.api(400, "POST", base+"/"+pc.ID+"/secret", nil)

	// Update.
	e.api(204, "PUT", base+"/"+pc.ID, map[string]any{"clientId": "spa", "enabled": true, "publicClient": true, "standardFlowEnabled": true,
		"redirectUris": []string{"https://spa.example/cb", "https://spa.example/cb2"}})
	_ = json.Unmarshal(e.api(200, "GET", base+"/"+pc.ID, nil), &spa)
	if len(spa["redirectUris"].([]any)) != 2 {
		t.Fatalf("update: %v", spa)
	}
	e.api(400, "PUT", base+"/"+pc.ID, map[string]any{"clientId": "other", "enabled": true, "publicClient": true})

	// Validation and conflicts.
	e.api(409, "POST", base, map[string]any{"clientId": "svc", "enabled": true})
	e.api(400, "POST", base, map[string]any{"clientId": "a", "enabled": true, "directAccessGrantsEnabled": true})
	e.api(400, "POST", base, map[string]any{"clientId": "b", "enabled": true, "implicitFlowEnabled": true})
	e.api(400, "POST", base, map[string]any{"clientId": "c", "enabled": true, "secret": "mine"})
	e.api(400, "POST", base, map[string]any{"clientId": "d", "enabled": true, "publicClient": true, "serviceAccountsEnabled": true})
	e.api(400, "POST", base, map[string]any{"clientId": "e", "enabled": true, "redirectUris": []string{"javascript:alert(1)"}})
	e.api(400, "POST", base, map[string]any{"clientId": "f", "enabled": true, "redirectUris": []string{"https://*.example/cb"}})
	e.api(400, "POST", base, map[string]any{"clientId": "g", "enabled": true, "attributes": map[string]string{"pkce.code.challenge.method": "plain"}})
	e.api(404, "GET", base+"/nope", nil)

	e.api(204, "DELETE", base+"/"+pc.ID, nil)
	e.api(404, "GET", base+"/"+pc.ID, nil)
	// The admin client cannot be removed through the API.
	cl, _ := e.st.GetClientByClientID(context.Background(), realm, "haven-admin")
	e.api(409, "DELETE", base+"/"+cl.ID, nil)
}

func TestUsersRolesGroupsAndPassword(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm
	id := e.createID(r+"/users", map[string]any{"username": "Alice", "email": "a@example.com", "firstName": "A", "enabled": true})
	e.api(409, "POST", r+"/users", map[string]any{"username": "alice", "enabled": true})
	e.api(400, "POST", r+"/users", map[string]any{"username": "", "enabled": true})
	e.api(400, "POST", r+"/users", map[string]any{"username": "x", "enabled": true, "password": "abc"})
	e.api(400, "POST", r+"/users", map[string]any{"username": "x", "enabled": true, "requiredActions": []string{"drop table"}})

	var u map[string]any
	_ = json.Unmarshal(e.api(200, "GET", r+"/users/"+id, nil), &u)
	if u["username"] != "Alice" || u["email"] != "a@example.com" {
		t.Fatalf("get: %v", u)
	}
	e.api(204, "PUT", r+"/users/"+id, map[string]any{"username": "Alice", "email": "alice@example.com", "enabled": true, "emailVerified": true})
	_ = json.Unmarshal(e.api(200, "GET", r+"/users/"+id, nil), &u)
	if u["email"] != "alice@example.com" || u["emailVerified"] != true {
		t.Fatalf("update: %v", u)
	}
	e.createID(r+"/users", map[string]any{"username": "bob", "enabled": true})
	var list []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", r+"/users?search=ali&first=0&max=10", nil), &list)
	if len(list) != 1 {
		t.Fatalf("search: %v", list)
	}
	_ = json.Unmarshal(e.api(200, "GET", r+"/users?max=1", nil), &list)
	if len(list) != 1 {
		t.Fatalf("max: %v", list)
	}
	e.api(400, "GET", r+"/users?max=abc", nil)

	// Password policy enforced; responses never carry hashes.
	e.api(400, "PUT", r+"/users/"+id+"/password", map[string]any{"type": "password", "value": "short"})
	e.api(400, "PUT", r+"/users/"+id+"/password", map[string]any{"type": "otp", "value": goodPW})
	e.api(204, "PUT", r+"/users/"+id+"/password", map[string]any{"type": "password", "value": goodPW, "temporary": true})
	got := e.api(200, "GET", r+"/users/"+id, nil)
	if bytes.Contains(got, []byte("argon2")) || bytes.Contains(got, []byte("assword")) && !bytes.Contains(got, []byte("UPDATE_PASSWORD")) {
		t.Fatalf("user body: %s", got)
	}
	_ = json.Unmarshal(got, &u)
	if acts, _ := u["requiredActions"].([]any); len(acts) != 1 || acts[0] != "UPDATE_PASSWORD" {
		t.Fatalf("temporary password action: %v", u)
	}
	e.api(204, "PUT", r+"/users/"+id+"/password", map[string]any{"type": "password", "value": goodPW + "2"})
	u = nil
	_ = json.Unmarshal(e.api(200, "GET", r+"/users/"+id, nil), &u)
	if acts, _ := u["requiredActions"].([]any); len(acts) != 0 {
		t.Fatalf("action not cleared: %v", u)
	}
	// Reset clears a lockout.
	cu, _ := e.st.GetUser(context.Background(), realm, id)
	cu.FailedLogins, cu.LockedUntil = 5, time.Now().Add(time.Hour)
	_ = e.st.UpdateUser(context.Background(), cu)
	e.api(204, "PUT", r+"/users/"+id+"/password", map[string]any{"value": goodPW})
	cu, _ = e.st.GetUser(context.Background(), realm, id)
	if cu.FailedLogins != 0 || !cu.LockedUntil.IsZero() {
		t.Fatal("lockout not reset")
	}

	// A user created through the API can log in with the password route's password.
	e.createID(r+"/clients", map[string]any{"clientId": "app", "enabled": true, "publicClient": true,
		"standardFlowEnabled": true, "redirectUris": []string{"http://localhost/cb"}})
	if tok := e.login("app", "alice", goodPW); tok == "" {
		t.Fatal("no token")
	}

	// Roles.
	e.api(400, "POST", r+"/users/"+id+"/roles", []map[string]string{{"name": "ghost"}})
	rid := e.createID(r+"/roles", map[string]any{"name": "editor", "description": "Edits"})
	if rid == "" {
		t.Fatal("role id")
	}
	e.api(409, "POST", r+"/roles", map[string]any{"name": "editor"})
	e.api(400, "POST", r+"/roles", map[string]any{"name": "bad role!"})
	e.api(204, "POST", r+"/users/"+id+"/roles", []map[string]string{{"name": "editor"}})
	e.api(204, "POST", r+"/users/"+id+"/roles", []map[string]string{{"name": "editor"}}) // idempotent
	var rm struct {
		RealmMappings []map[string]any
	}
	_ = json.Unmarshal(e.api(200, "GET", r+"/users/"+id+"/roles", nil), &rm)
	if len(rm.RealmMappings) != 1 || rm.RealmMappings[0]["name"] != "editor" || rm.RealmMappings[0]["description"] != "Edits" {
		t.Fatalf("role mappings: %v", rm)
	}
	var roles []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", r+"/roles", nil), &roles)
	if len(roles) != 1 {
		t.Fatalf("roles: %v", roles)
	}

	// Groups.
	gid := e.createID(r+"/groups", map[string]any{"name": "staff"})
	e.api(409, "POST", r+"/groups", map[string]any{"name": "staff"})
	e.api(400, "POST", r+"/groups", map[string]any{"name": "a/b"})
	e.api(204, "PUT", r+"/users/"+id+"/groups/"+gid, nil)
	e.api(404, "PUT", r+"/users/"+id+"/groups/missing", nil)
	var gs []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", r+"/users/"+id+"/groups", nil), &gs)
	if len(gs) != 1 || gs[0]["path"] != "/staff" {
		t.Fatalf("user groups: %v", gs)
	}
	_ = json.Unmarshal(e.api(200, "GET", r+"/groups", nil), &gs)
	if len(gs) != 1 || gs[0]["path"] != "/staff" || gs[0]["id"] != gid {
		t.Fatalf("groups: %v", gs)
	}

	e.api(204, "DELETE", r+"/users/"+id, nil)
	e.api(404, "GET", r+"/users/"+id, nil)
	e.api(404, "DELETE", r+"/users/"+id, nil)
}

func TestMiscRoutes(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm
	var scopes []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", r+"/client-scopes", nil), &scopes)
	if len(scopes) != 4 {
		t.Fatalf("scopes: %v", scopes)
	}
	if string(bytes.TrimSpace(e.api(200, "GET", r+"/identity-providers", nil))) != "[]" {
		t.Fatal("identity providers must be an empty list")
	}
	e.api(501, "POST", r+"/identity-providers", map[string]any{"alias": "x"})
	e.api(404, "DELETE", r+"/identity-providers/x", nil)
	var ks []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", r+"/keys", nil), &ks)
	if len(ks) == 0 || ks[0]["providerId"] != "ecdsa-generated" || ks[0]["type"] != "EC" || ks[0]["status"] != "ACTIVE" || ks[0]["kid"] == "" {
		t.Fatalf("keys: %v", ks)
	}
	if bytes.Contains(e.api(200, "GET", r+"/keys", nil), []byte("PRIVATE")) {
		t.Fatal("private key leaked")
	}
	var errBody map[string]string
	_ = json.Unmarshal(e.api(404, "GET", "/does/not/exist", nil), &errBody)
	if errBody["error"] == "" {
		t.Fatal("error JSON shape")
	}
}

func TestBodyRules(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm
	e.api(400, "POST", r+"/roles", `{"name":"x","bogus":1}`)
	e.api(400, "POST", r+"/roles", `{"name":"x"} {"name":"y"}`)
	e.api(400, "POST", r+"/roles", `not json`)
	e.api(400, "POST", r+"/roles", `[]`)
	big := `{"name":"x","description":"` + strings.Repeat("a", 2<<20) + `"}`
	code, _, _ := e.call("POST", r+"/roles", e.token, big)
	if code != 413 && code != 400 {
		t.Fatalf("oversized body: %d", code)
	}
	if code != 413 {
		t.Logf("oversized body gave %d", code)
	}
}

func TestEventsRecorded(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm
	e.createID(r+"/roles", map[string]any{"name": "auditor"})
	id := e.createID(r+"/users", map[string]any{"username": "carol", "enabled": true})
	e.api(204, "PUT", r+"/users/"+id+"/password", map[string]any{"value": goodPW})
	e.api(204, "DELETE", r+"/users/"+id, nil)
	body := e.api(200, "GET", r+"/events?max=50", nil)
	var evs []struct {
		Time          int64
		OperationType string
		ResourceType  string
		ResourcePath  string
	}
	if err := json.Unmarshal(body, &evs); err != nil || len(evs) < 4 {
		t.Fatalf("events: %v %s", err, body)
	}
	if evs[0].OperationType != "DELETE" || evs[0].ResourceType != "USER" || evs[0].ResourcePath != "carol" || evs[0].Time == 0 {
		t.Fatalf("newest first: %+v", evs[0])
	}
	if bytes.Contains(body, []byte(goodPW)) || bytes.Contains(body, []byte("argon2")) {
		t.Fatal("event leaks secrets")
	}
	var one []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", r+"/events?max=1", nil), &one)
	if len(one) != 1 {
		t.Fatalf("max=1: %v", one)
	}
	// Realms that disable admin events record nothing.
	e.createID("/realms", map[string]any{"realm": "quiet", "enabled": true, "adminEventsEnabled": false})
	e.createID("/realms/quiet/roles", map[string]any{"name": "r"})
	if got := e.api(200, "GET", "/realms/quiet/events", nil); strings.TrimSpace(string(got)) != "[]" {
		t.Fatalf("quiet realm events: %s", got)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm
	e.createID(r+"/roles", map[string]any{"name": "viewer", "description": "Views"})
	e.createID(r+"/groups", map[string]any{"name": "ops"})
	e.createID(r+"/clients", map[string]any{"clientId": "web", "enabled": true, "publicClient": true, "standardFlowEnabled": true,
		"redirectUris": []string{"https://web.example/cb"}})
	e.createID(r+"/clients", map[string]any{"clientId": "worker", "enabled": true, "serviceAccountsEnabled": true})

	exp := e.api(200, "GET", r+"/export", nil)
	var parsed struct {
		Version int
		Realm   string
		Roles   []map[string]any
		Clients []map[string]any
	}
	if err := json.Unmarshal(exp, &parsed); err != nil || parsed.Version != 1 || parsed.Realm != realm || len(parsed.Roles) != 1 {
		t.Fatalf("export: %v %s", err, exp)
	}
	if bytes.Contains(exp, []byte(`"secret"`)) {
		t.Fatal("export carries secrets")
	}

	e.createID("/realms", map[string]any{"realm": "copy", "enabled": true})
	var res struct{ Imported map[string]int }
	_ = json.Unmarshal(e.api(200, "POST", "/realms/copy/import", exp), &res)
	if res.Imported["roles"] != 1 || res.Imported["groups"] != 1 || res.Imported["clients"] != 3 { // web, worker, haven-admin
		t.Fatalf("import counts: %v", res)
	}
	// Idempotent: a second import skips everything.
	_ = json.Unmarshal(e.api(200, "POST", "/realms/copy/import", exp), &res)
	if res.Imported["roles"] != 0 || res.Imported["groups"] != 0 || res.Imported["clients"] != 0 {
		t.Fatalf("second import: %v", res)
	}
	var again struct {
		Roles, Groups, Clients []map[string]any
	}
	_ = json.Unmarshal(e.api(200, "GET", "/realms/copy/export", nil), &again)
	if len(again.Roles) != 1 || len(again.Groups) != 1 || len(again.Clients) != 3 {
		t.Fatalf("copy export: %+v", again)
	}
	e.api(400, "POST", "/realms/copy/import", `{"version":2,"realm":"x"}`)
	e.api(400, "POST", "/realms/copy/import", `{"version":1,"realm":"x","clients":[{"clientId":"bad","enabled":true,"directAccessGrantsEnabled":true}]}`)
	e.api(404, "POST", "/realms/nope/import", `{"version":1,"realm":"x"}`)
}

// TestAPIClientCanLogIn is the end-to-end sanity check: a client and user
// created purely through the API complete an authorization-code + PKCE login.
func TestAPIClientCanLogIn(t *testing.T) {
	e := newEnv(t)
	e.createID("/realms", map[string]any{"realm": "tenant", "enabled": true})
	e.createID("/realms/tenant/clients", map[string]any{"clientId": "console", "enabled": true, "publicClient": true,
		"standardFlowEnabled": true, "redirectUris": []string{"http://localhost/cb"}})
	uid := e.createID("/realms/tenant/users", map[string]any{"username": "dana", "enabled": true})
	e.api(204, "PUT", "/realms/tenant/users/"+uid+"/password", map[string]any{"type": "password", "value": goodPW})
	// loginTokens targets the platform realm; point it at tenant instead.
	tr := e.loginIn("tenant", "console", "dana", goodPW)
	if tr["access_token"] == "" || tr["id_token"] == "" {
		t.Fatalf("tokens: %v", tr)
	}
}

func (e *env) loginIn(rlm, clientID, user, pw string) map[string]any {
	e.t.Helper()
	// Reuse the platform helper by temporarily addressing another realm.
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := strings.Repeat("w", 50)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {clientID}, "redirect_uri": {"http://localhost/cb"}, "response_type": {"code"}, "state": {"st"},
		"scope": {"openid"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	authURL := e.srv.URL + "/realms/" + rlm + "/protocol/openid-connect/auth?" + q.Encode()
	resp, err := c.Get(authURL)
	if err != nil {
		e.t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfRe.FindSubmatch(page)
	if m == nil {
		e.t.Fatalf("login page: %d", resp.StatusCode)
	}
	resp, err = c.PostForm(authURL, url.Values{"username": {user}, "password": {pw}, "csrf": {string(m[1])}})
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Query().Get("code") == "" {
		e.t.Fatalf("no code: %d", resp.StatusCode)
	}
	resp, err = http.PostForm(e.srv.URL+"/realms/"+rlm+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {"http://localhost/cb"},
		"client_id": {clientID}, "code_verifier": {verifier}})
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || json.Unmarshal(b, &out) != nil {
		e.t.Fatalf("token: %d %s", resp.StatusCode, b)
	}
	return out
}

func TestClientListClientIDFilter(t *testing.T) {
	e := newEnv(t)
	base := "/realms/" + realm + "/clients"
	for _, id := range []string{"alpha", "alpha-two", "beta"} {
		e.api(201, "POST", base, map[string]any{"clientId": id, "enabled": true})
	}
	ids := func(q string) []string {
		var cs []struct {
			ClientID string `json:"clientId"`
		}
		if err := json.Unmarshal(e.api(200, "GET", base+q, nil), &cs); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cs {
			out = append(out, c.ClientID)
		}
		return out
	}
	if got := ids("?clientId=alpha"); len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("filter must be an exact match, got %v", got)
	}
	if got := ids("?clientId=nope"); len(got) != 0 {
		t.Fatalf("unknown clientId must return an empty list, got %v", got)
	}
	if got := ids(""); len(got) < 3 {
		t.Fatalf("no filter must list everything, got %v", got)
	}
}
