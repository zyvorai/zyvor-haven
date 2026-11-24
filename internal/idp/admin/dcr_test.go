// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

const dcrRealm = "apps"

var hcIDRE = regexp.MustCompile(`^hc_[A-Za-z0-9_-]{22}$`)

// dcrEnv is the full stack with a realm "apps", one user and event logging on.
func dcrEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.createID("/realms", map[string]any{"realm": dcrRealm, "enabled": true})
	rl, err := e.st.GetRealm(context.Background(), dcrRealm)
	if err != nil {
		t.Fatal(err)
	}
	rl.AuthEventsLogged, rl.AdminEventsLogged = true, true
	if err := e.st.UpdateRealm(context.Background(), rl); err != nil {
		t.Fatal(err)
	}
	uid := e.createID("/realms/"+dcrRealm+"/users", map[string]any{"username": "carol", "enabled": true})
	e.api(204, "PUT", "/realms/"+dcrRealm+"/users/"+uid+"/password", map[string]any{"type": "password", "value": goodPW})
	return e
}

type iatInfo struct{ ID, Token string }

func (e *env) iat(count int) iatInfo {
	e.t.Helper()
	var out iatInfo
	if err := json.Unmarshal(e.api(201, "POST", "/realms/"+dcrRealm+"/initial-access-tokens",
		map[string]any{"count": count, "note": "test"}), &out); err != nil || out.Token == "" || out.ID == "" {
		e.t.Fatalf("initial access token: %v", err)
	}
	return out
}

type dcrResp struct {
	Status int
	Hdr    http.Header
	Raw    []byte
	M      map[string]any
}

func (e *env) dcrDo(method, path, tok string, body any) dcrResp {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/realms/"+dcrRealm+"/clients-registrations/openid-connect"+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	r := dcrResp{Status: resp.StatusCode, Hdr: resp.Header, Raw: raw}
	_ = json.Unmarshal(raw, &r.M)
	return r
}

func (e *env) register(tok string, body any) dcrResp { return e.dcrDo("POST", "", tok, body) }

func (e *env) registerOK(tok string, body any) dcrResp {
	e.t.Helper()
	r := e.register(tok, body)
	if r.Status != 201 {
		e.t.Fatalf("register: %d %s", r.Status, r.Raw)
	}
	return r
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func (e *env) dcrClients() []core.Client {
	cs, _ := e.st.ListClients(context.Background(), dcrRealm)
	return cs
}

func (e *env) iatRemaining(id string) int {
	var l []struct {
		ID        string `json:"id"`
		Remaining int    `json:"remaining"`
	}
	_ = json.Unmarshal(e.api(200, "GET", "/realms/"+dcrRealm+"/initial-access-tokens", nil), &l)
	for _, x := range l {
		if x.ID == id {
			return x.Remaining
		}
	}
	e.t.Fatalf("token %s not listed", id)
	return -1
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// codeFlow runs authorization code + PKCE for a registered client and returns
// the token response (fatal on failure) plus the login page it saw.
func (e *env) codeFlow(clientID, secret, redirect string) (map[string]any, string) {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "state": {"st"},
		"scope": {"openid"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	authURL := e.srv.URL + "/realms/" + dcrRealm + "/protocol/openid-connect/auth?" + q.Encode()
	resp, err := c.Get(authURL)
	if err != nil {
		e.t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := csrfRe.FindSubmatch(page)
	if resp.StatusCode != 200 || m == nil {
		e.t.Fatalf("login page: %d %s", resp.StatusCode, page)
	}
	resp, err = c.PostForm(authURL, url.Values{"username": {"carol"}, "password": {goodPW}, "csrf": {string(m[1])}})
	if err != nil {
		e.t.Fatal(err)
	}
	// Dynamically registered clients go through the consent screen (consent.go).
	if cp, _ := io.ReadAll(resp.Body); resp.StatusCode == 200 && strings.Contains(string(cp), "consent_decision") {
		cm, dm := csrfRe.FindSubmatch(cp), regexp.MustCompile(`name="consent_proof" value="([^"]+)"`).FindSubmatch(cp)
		if cm == nil || dm == nil {
			e.t.Fatalf("consent page without csrf/digest: %s", cp)
		}
		_ = resp.Body.Close()
		resp, err = c.PostForm(authURL, url.Values{"consent_decision": {"allow"}, "consent_proof": {string(dm[1])}, "csrf": {string(cm[1])}})
		if err != nil {
			e.t.Fatal(err)
		}
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc == nil || loc.Query().Get("code") == "" {
		e.t.Fatalf("no code: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {redirect},
		"code_verifier": {verifier}}
	tr := e.tokenReq(clientID, secret, form)
	if tr.Status != 200 {
		e.t.Fatalf("token exchange: %d %s", tr.Status, tr.Raw)
	}
	return tr.M, string(page)
}

func (e *env) tokenReq(clientID, secret string, form url.Values) dcrResp {
	e.t.Helper()
	if secret == "" {
		form.Set("client_id", clientID)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/realms/"+dcrRealm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	r := dcrResp{Status: resp.StatusCode, Raw: raw}
	_ = json.Unmarshal(raw, &r.M)
	return r
}

func (e *env) authPage(clientID, redirect string) (int, string) {
	e.t.Helper()
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "state": {"st"}, "scope": {"openid"},
		"code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"}}
	resp, err := http.Get(e.srv.URL + "/realms/" + dcrRealm + "/protocol/openid-connect/auth?" + q.Encode())
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// ---- flows ----

func TestDCRPublicSPAEndToEnd(t *testing.T) {
	e := dcrEnv(t)
	iat := e.iat(1)
	r := e.registerOK(iat.Token, map[string]any{
		"client_name": "My SPA", "redirect_uris": []string{"http://localhost/cb"},
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "scope": "openid profile offline_access",
		"contacts": []string{"ops@example.com"}, "client_uri": "https://spa.example",
	})
	id := str(r.M, "client_id")
	if !hcIDRE.MatchString(id) {
		t.Fatalf("client_id %q", id)
	}
	if _, has := r.M["client_secret"]; has {
		t.Error("a public client got a secret")
	}
	if str(r.M, "registration_access_token") == "" || !strings.HasSuffix(str(r.M, "registration_client_uri"), "/realms/apps/clients-registrations/openid-connect/"+id) {
		t.Errorf("registration management fields: %s", r.Raw)
	}
	if r.M["client_id_issued_at"].(float64) < 1e9 || r.Hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("issued_at / cache headers: %s %v", r.Raw, r.Hdr)
	}
	// Stored as a public PKCE-only client with the DCR marker.
	cl, err := e.st.GetClientByClientID(context.Background(), dcrRealm, id)
	if err != nil || !cl.Public || !cl.RequirePKCE || !cl.AuthCodeFlow || cl.ServiceAccount || cl.SecretHash != "" || cl.Name != "My SPA" {
		t.Fatalf("stored client: %+v %v", cl, err)
	}
	rc, err := e.st.GetRegisteredClient(context.Background(), dcrRealm, id)
	if err != nil || rc.CreatedVia != "dcr" || rc.InitialTokenID != iat.ID || rc.ClientUUID != cl.ID {
		t.Fatalf("marker: %+v %v", rc, err)
	}
	// Tokens are stored hashed only.
	if rc.RegTokenHash != sha(str(r.M, "registration_access_token")) || strings.Contains(rc.RegTokenHash, "hrat_") {
		t.Error("registration token not stored as sha256")
	}
	// The registered client really works: PKCE code flow, then refresh.
	tr, _ := e.codeFlow(id, "", "http://localhost/cb")
	if str(tr, "access_token") == "" || str(tr, "id_token") == "" || str(tr, "refresh_token") == "" {
		t.Fatalf("token response: %v", tr)
	}
	rf := e.tokenReq(id, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {str(tr, "refresh_token")}})
	if rf.Status != 200 {
		t.Fatalf("refresh: %d %s", rf.Status, rf.Raw)
	}
	// PKCE is mandatory: an authorization request without a challenge is refused.
	resp, _ := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Get(
		e.srv.URL + "/realms/apps/protocol/openid-connect/auth?client_id=" + id +
			"&redirect_uri=http://localhost/cb&response_type=code&state=s")
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("no-PKCE authorization not refused: %d %s", resp.StatusCode, loc)
	}
	// client_credentials is not granted.
	if cc := e.tokenReq(id, "", url.Values{"grant_type": {"client_credentials"}}); cc.Status == 200 {
		t.Error("public client got client_credentials")
	}
}

func TestDCRConfidentialWebEndToEnd(t *testing.T) {
	e := dcrEnv(t)
	r := e.registerOK(e.iat(2).Token, map[string]any{
		"client_name": "Web", "redirect_uris": []string{"http://localhost/cb"},
		"grant_types": []string{"authorization_code", "client_credentials"}, "token_endpoint_auth_method": "client_secret_post",
	})
	id, secret := str(r.M, "client_id"), str(r.M, "client_secret")
	if secret == "" || r.M["client_secret_expires_at"].(float64) != 0 || r.M["token_endpoint_auth_method"] != "client_secret_post" {
		t.Fatalf("confidential fields: %s", r.Raw)
	}
	cl, _ := e.st.GetClientByClientID(context.Background(), dcrRealm, id)
	if cl.Public || cl.SecretHash != oidc.HashSecret(secret) || cl.SecretHash == secret || !cl.RequirePKCE || !cl.ServiceAccount {
		t.Fatalf("stored client: %+v", cl)
	}
	tr, _ := e.codeFlow(id, secret, "http://localhost/cb")
	if str(tr, "access_token") == "" {
		t.Fatal("no access token")
	}
	if bad := e.tokenReq(id, "wrong-secret", url.Values{"grant_type": {"client_credentials"}}); bad.Status != 401 {
		t.Errorf("wrong secret: %d", bad.Status)
	}
	cc := e.tokenReq(id, secret, url.Values{"grant_type": {"client_credentials"}})
	if cc.Status != 200 || str(cc.M, "access_token") == "" {
		t.Fatalf("client_credentials: %d %s", cc.Status, cc.Raw)
	}
	// Without the grant, client_credentials is refused.
	r2 := e.registerOK(e.iat(1).Token, map[string]any{"redirect_uris": []string{"http://localhost/cb"}})
	id2, sec2 := str(r2.M, "client_id"), str(r2.M, "client_secret")
	if x := e.tokenReq(id2, sec2, url.Values{"grant_type": {"client_credentials"}}); x.Status == 200 {
		t.Error("client_credentials worked without being granted")
	}
	if r2.M["token_endpoint_auth_method"] != "client_secret_basic" {
		t.Errorf("default auth method: %v", r2.M["token_endpoint_auth_method"])
	}
}

func TestDCRClientCredentialsOnlyNoRedirects(t *testing.T) {
	e := dcrEnv(t)
	r := e.registerOK(e.iat(1).Token, map[string]any{"grant_types": []string{"client_credentials"}, "client_name": "svc"})
	if x := e.tokenReq(str(r.M, "client_id"), str(r.M, "client_secret"), url.Values{"grant_type": {"client_credentials"}}); x.Status != 200 {
		t.Fatalf("%d %s", x.Status, x.Raw)
	}
	if st, _ := e.authPage(str(r.M, "client_id"), "http://localhost/cb"); st != 400 {
		t.Errorf("a client_credentials-only client could start a login: %d", st)
	}
}

func TestDCRNative(t *testing.T) {
	e := dcrEnv(t)
	iat := e.iat(5)
	for _, uri := range []string{"http://127.0.0.1:8123/cb", "http://[::1]:9/cb", "http://localhost:1234/cb", "com.example.app:/oauth2redirect", "https://app.example/cb"} {
		r := e.register(iat.Token, map[string]any{"application_type": "native", "token_endpoint_auth_method": "none", "redirect_uris": []string{uri}})
		if r.Status != 201 {
			t.Errorf("%s: %d %s", uri, r.Status, r.Raw)
		}
	}
}

// ---- secrets are shown once ----

func TestDCRSecretsReturnedOnce(t *testing.T) {
	e := dcrEnv(t)
	iat := e.iat(1)
	r := e.registerOK(iat.Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"}})
	id, secret, reg := str(r.M, "client_id"), str(r.M, "client_secret"), str(r.M, "registration_access_token")
	g := e.dcrDo("GET", "/"+id, reg, nil)
	if g.Status != 200 {
		t.Fatalf("GET: %d %s", g.Status, g.Raw)
	}
	for _, f := range []string{"client_secret", "registration_access_token", "client_secret_expires_at"} {
		if _, has := g.M[f]; has {
			t.Errorf("management GET returned %s", f)
		}
	}
	// Neither appears in any other response, nor in the store as plaintext.
	list := string(e.api(200, "GET", "/realms/"+dcrRealm+"/registered-clients", nil))
	iats := string(e.api(200, "GET", "/realms/"+dcrRealm+"/initial-access-tokens", nil))
	cl := string(e.api(200, "GET", "/realms/"+dcrRealm+"/clients?clientId="+id, nil))
	for name, body := range map[string]string{"GET": string(g.Raw), "registered": list, "iats": iats, "clients": cl} {
		for what, v := range map[string]string{"secret": secret, "registration token": reg, "initial token": iat.Token} {
			if strings.Contains(body, v) {
				t.Errorf("%s response leaks the %s", name, what)
			}
		}
	}
	rc, _ := e.st.GetRegisteredClient(context.Background(), dcrRealm, id)
	c, _ := e.st.GetClientByClientID(context.Background(), dcrRealm, id)
	ts, _ := e.st.ListInitialAccessTokens(context.Background(), dcrRealm)
	if rc.RegTokenHash == reg || c.SecretHash == secret || len(ts) != 1 || ts[0].TokenHash == iat.Token || ts[0].TokenHash != sha(iat.Token) {
		t.Error("a token or secret is stored in the clear")
	}
}

// ---- validation ----

// The full rule table is in oidc/dcr_test.go (no rate limit there); over HTTP
// a representative set must be refused with the right RFC 7591 error, create
// nothing and not consume a use of the token.
func TestDCRValidation(t *testing.T) {
	e := dcrEnv(t)
	iat := e.iat(1000)
	ok := func(extra map[string]any) map[string]any {
		m := map[string]any{"redirect_uris": []string{"https://app.example/cb"}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name string
		body any
		code string
	}{
		{"http non-loopback", ok(map[string]any{"redirect_uris": []string{"http://evil.example/cb"}}), "invalid_redirect_uri"},
		{"wildcard host", ok(map[string]any{"redirect_uris": []string{"https://*.example.com/cb"}}), "invalid_redirect_uri"},
		{"javascript", ok(map[string]any{"redirect_uris": []string{"javascript:alert(1)"}}), "invalid_redirect_uri"},
		{"fragment", ok(map[string]any{"redirect_uris": []string{"https://app.example/cb#x"}}), "invalid_redirect_uri"},
		{"redirects missing", map[string]any{"client_name": "x"}, "invalid_redirect_uri"},
		{"password grant", ok(map[string]any{"grant_types": []string{"password"}}), "invalid_client_metadata"},
		{"device grant", ok(map[string]any{"grant_types": []string{"urn:ietf:params:oauth:grant-type:device_code"}}), "invalid_client_metadata"},
		{"auth method private_key_jwt", ok(map[string]any{"token_endpoint_auth_method": "private_key_jwt"}), "invalid_client_metadata"},
		{"unknown scope", ok(map[string]any{"scope": "openid admin"}), "invalid_client_metadata"},
		{"logout uri http", ok(map[string]any{"backchannel_logout_uri": "http://evil.example/lo"}), "invalid_client_metadata"},
		{"not json", "not json", "invalid_client_metadata"},
		{"software statement", ok(map[string]any{"software_statement": "eyJ.x.y"}), "invalid_software_statement"},
	}
	for _, c := range cases {
		r := e.register(iat.Token, c.body)
		if r.Status != 400 || str(r.M, "error") != c.code {
			t.Errorf("%s: got %d %s", c.name, r.Status, r.Raw)
		}
	}
	if n := len(e.dcrClients()); n != 0 {
		t.Errorf("%d clients were created by rejected requests", n)
	}
	if got := e.iatRemaining(iat.ID); got != 1000 {
		t.Errorf("rejected requests consumed the token: remaining %d", got)
	}
}

func TestDCRRedirectNoReflection(t *testing.T) {
	e := dcrEnv(t)
	r := e.register(e.iat(1).Token, map[string]any{"redirect_uris": []string{"javascript:alert('XSS_MARKER')"}})
	if r.Status != 400 || strings.Contains(string(r.Raw), "XSS_MARKER") {
		t.Errorf("input reflected: %d %s", r.Status, r.Raw)
	}
	ok := e.registerOK(e.iat(1).Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"},
		"unknown_field": "<img src=x onerror=UNK_MARKER>", "jwks_uri": "https://x.example/jwks"})
	if strings.Contains(string(ok.Raw), "UNK_MARKER") || strings.Contains(string(ok.Raw), "unknown_field") {
		t.Errorf("unknown field reflected: %s", ok.Raw)
	}
}

func TestDCRBodyCap(t *testing.T) {
	e := dcrEnv(t)
	iat := e.iat(1)
	big := map[string]any{"redirect_uris": []string{"https://a.example/cb"}, "client_name": strings.Repeat("x", 17<<10)}
	if r := e.register(iat.Token, big); r.Status != 413 {
		t.Errorf("oversize body: %d %s", r.Status, r.Raw)
	}
	if e.iatRemaining(iat.ID) != 1 {
		t.Error("oversize request consumed the token")
	}
	e.registerOK(iat.Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"}})
}

// ---- initial access tokens ----

func TestDCRTokenLifecycle(t *testing.T) {
	e := dcrEnv(t)
	body := map[string]any{"redirect_uris": []string{"https://a.example/cb"}}
	ctx := context.Background()

	var generic string
	deny := func(name, tok string) {
		t.Helper()
		r := e.register(tok, body)
		if r.Status != 401 || str(r.M, "error") != "invalid_token" || !strings.Contains(r.Hdr.Get("WWW-Authenticate"), "invalid_token") {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
		if generic == "" {
			generic = string(r.Raw)
		} else if string(r.Raw) != generic {
			t.Errorf("%s: distinguishable error body %s", name, r.Raw)
		}
	}
	deny("no header", "")
	deny("garbage", "hiat_nonsense")

	// Exhaustion.
	one := e.iat(1)
	e.registerOK(one.Token, body)
	deny("exhausted", one.Token)
	if e.iatRemaining(one.ID) != 0 {
		t.Error("remaining not 0")
	}

	// Expiry (stored directly: the Admin API's minimum is a second).
	now := time.Now().UTC()
	if err := e.st.PutInitialAccessToken(ctx, core.InitialAccessToken{Realm: dcrRealm, TokenHash: sha("hiat_expired"), Count: 5,
		Remaining: 5, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	deny("expired", "hiat_expired")

	// Revocation.
	rev := e.iat(5)
	e.api(204, "DELETE", "/realms/"+dcrRealm+"/initial-access-tokens/"+rev.ID, nil)
	deny("revoked", rev.Token)
	e.api(404, "DELETE", "/realms/"+dcrRealm+"/initial-access-tokens/"+rev.ID, nil)

	// A token of another realm does not work here.
	e.createID("/realms", map[string]any{"realm": "elsewhere", "enabled": true})
	var other iatInfo
	_ = json.Unmarshal(e.api(201, "POST", "/realms/elsewhere/initial-access-tokens", map[string]any{}), &other)
	deny("other realm's token", other.Token)

	// A token issued before the realm was recreated is dead.
	stale := e.iat(5)
	e.api(204, "DELETE", "/realms/"+dcrRealm, nil)
	e.createID("/realms", map[string]any{"realm": dcrRealm, "enabled": true})
	deny("token from a deleted realm", stale.Token)
}

func TestDCRTokenAdminAPI(t *testing.T) {
	e := dcrEnv(t)
	base := "/realms/" + dcrRealm + "/initial-access-tokens"
	// Defaults: one use, 24 hours.
	var d struct {
		ID, Token string
		Count     int
		ExpiresAt time.Time
	}
	if err := json.Unmarshal(e.api(201, "POST", base, nil), &d); err != nil || d.Count != 1 || d.Token == "" {
		t.Fatalf("defaults: %+v %v", d, err)
	}
	if dur := time.Until(d.ExpiresAt); dur < 23*time.Hour || dur > 25*time.Hour {
		t.Errorf("default expiry %v", dur)
	}
	for name, b := range map[string]map[string]any{
		"zero expiry": {"expirationSeconds": 0}, "negative expiry": {"expirationSeconds": -5},
		"31 days": {"expirationSeconds": 31 * 24 * 3600}, "zero count": {"count": 0}, "1001": {"count": 1001},
		"note control": {"note": "a\x01b"}, "long note": {"note": strings.Repeat("n", 256)}, "unknown field": {"bogus": 1},
	} {
		if code, body, _ := e.call("POST", base, e.token, b); code != 400 {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	e.api(201, "POST", base, map[string]any{"expirationSeconds": 30 * 24 * 3600, "count": 1000, "note": "max"})
	// List: no token, no hash.
	raw := string(e.api(200, "GET", base, nil))
	if strings.Contains(raw, d.Token) || strings.Contains(raw, sha(d.Token)) || strings.Contains(strings.ToLower(raw), "tokenhash") {
		t.Errorf("list exposes the token: %s", raw)
	}
	var l []map[string]any
	_ = json.Unmarshal([]byte(raw), &l)
	if len(l) != 2 || l[0]["id"] != d.ID || l[0]["remaining"].(float64) != 1 || l[1]["note"] != "max" {
		t.Errorf("list: %s", raw)
	}
	// Needs the admin token.
	for _, tok := range []string{"", "garbage"} {
		if code, _, _ := e.call("POST", base, tok, nil); code != 401 {
			t.Errorf("unauthenticated create: %d", code)
		}
	}
	// The registration endpoint's own tokens do not grant admin access.
	if code, _, _ := e.call("GET", base, d.Token, nil); code != 401 {
		t.Errorf("initial token on the admin API: %d", code)
	}
	e.api(404, "POST", "/realms/nope/initial-access-tokens", nil)
}

// Two registrations racing for the last use: exactly one wins.
func TestDCRTokenRace(t *testing.T) {
	e := dcrEnv(t)
	iat := e.iat(1)
	const n = 15 // below the per-IP rate limit
	var wins, other atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r := e.register(iat.Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"}})
			switch r.Status {
			case 201:
				wins.Add(1)
			case 401:
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || other.Load() != 0 {
		t.Fatalf("%d winners (want exactly 1), %d unexpected statuses", wins.Load(), other.Load())
	}
	if got := len(e.dcrClients()); got != 1 {
		t.Fatalf("%d clients created", got)
	}
}

// ---- management ----

func TestDCRManagementAuthSeparation(t *testing.T) {
	e := dcrEnv(t)
	iat := e.iat(5)
	a := e.registerOK(iat.Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"}, "client_name": "A"})
	b := e.registerOK(iat.Token, map[string]any{"redirect_uris": []string{"https://b.example/cb"}, "client_name": "B"})
	aID, aTok := str(a.M, "client_id"), str(a.M, "registration_access_token")
	bID, bTok := str(b.M, "client_id"), str(b.M, "registration_access_token")

	// An admin-created client with its own secret and a known client_id.
	cid := e.createID("/realms/"+dcrRealm+"/clients", map[string]any{"clientId": "admin-made", "enabled": true,
		"publicClient": true, "standardFlowEnabled": true, "redirectUris": []string{"https://x.example/cb"}, "name": "Admin"})
	_ = cid

	var generic string
	check401 := func(name string, r dcrResp) {
		t.Helper()
		if r.Status != 401 || str(r.M, "error") != "invalid_token" {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
		if generic == "" {
			generic = string(r.Raw)
		} else if string(r.Raw) != generic {
			t.Errorf("%s: distinguishable body %s", name, r.Raw)
		}
	}
	put := map[string]any{"redirect_uris": []string{"https://evil.example/cb"}, "client_name": "pwned"}
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		check401(m+" initial token", e.dcrDo(m, "/"+aID, iat.Token, put))
		check401(m+" A's token on B", e.dcrDo(m, "/"+bID, aTok, put))
		check401(m+" no token", e.dcrDo(m, "/"+aID, "", put))
		check401(m+" admin token", e.dcrDo(m, "/"+aID, e.token, put))
		check401(m+" admin-created client, A's token", e.dcrDo(m, "/admin-made", aTok, put))
		check401(m+" admin-created client, initial token", e.dcrDo(m, "/admin-made", iat.Token, put))
		check401(m+" unknown client", e.dcrDo(m, "/hc_doesnotexist", aTok, put))
		check401(m+" odd client id", e.dcrDo(m, "/%2e%2e", aTok, put))
	}
	// Registration tokens do not register.
	if r := e.register(aTok, map[string]any{"redirect_uris": []string{"https://a.example/cb"}}); r.Status != 401 {
		t.Errorf("registration token used to register: %d", r.Status)
	}
	// Nothing changed.
	for _, c := range e.dcrClients() {
		if strings.Contains(c.Name, "pwned") || strings.Contains(strings.Join(c.RedirectURIs, ","), "evil") {
			t.Fatalf("a client was modified: %+v", c)
		}
	}
	if cl, err := e.st.GetClientByClientID(context.Background(), dcrRealm, "admin-made"); err != nil || cl.Name != "Admin" {
		t.Fatalf("admin-made client touched: %+v %v", cl, err)
	}
	if _, err := e.st.GetClientByClientID(context.Background(), dcrRealm, bID); err != nil {
		t.Fatal("client B was deleted")
	}
	_ = bTok

	// A client_id reused after an admin deleted the DCR client does not
	// inherit the old registration token.
	rawA, _ := e.st.GetClientByClientID(context.Background(), dcrRealm, aID)
	e.api(204, "DELETE", "/realms/"+dcrRealm+"/clients/"+rawA.ID, nil)
	e.api(201, "POST", "/realms/"+dcrRealm+"/clients", map[string]any{"clientId": aID, "enabled": true, "name": "Reused"})
	check401("reused client_id with the old registration token", e.dcrDo("DELETE", "/"+aID, aTok, nil))
	if _, err := e.st.GetClientByClientID(context.Background(), dcrRealm, aID); err != nil {
		t.Fatal("reused client was deleted through a stale registration")
	}
}

func TestDCRManagementCRUD(t *testing.T) {
	e := dcrEnv(t)
	r := e.registerOK(e.iat(1).Token, map[string]any{"redirect_uris": []string{"http://localhost/cb"}, "client_name": "Old",
		"grant_types": []string{"authorization_code", "client_credentials"}})
	id, secret, reg := str(r.M, "client_id"), str(r.M, "client_secret"), str(r.M, "registration_access_token")

	g := e.dcrDo("GET", "/"+id, reg, nil)
	if g.Status != 200 || str(g.M, "client_name") != "Old" || g.M["client_id"] != id {
		t.Fatalf("GET: %d %s", g.Status, g.Raw)
	}
	// Invalid PUT changes nothing.
	for name, b := range map[string]any{
		"bad redirect":      map[string]any{"redirect_uris": []string{"http://evil.example/cb"}},
		"secret in body":    map[string]any{"redirect_uris": []string{"https://n.example/cb"}, "client_secret": "mine"},
		"token in body":     map[string]any{"redirect_uris": []string{"https://n.example/cb"}, "registration_access_token": "mine"},
		"other client_id":   map[string]any{"redirect_uris": []string{"https://n.example/cb"}, "client_id": "hc_other"},
		"to public":         map[string]any{"redirect_uris": []string{"https://n.example/cb"}, "token_endpoint_auth_method": "none"},
		"password grant":    map[string]any{"redirect_uris": []string{"https://n.example/cb"}, "grant_types": []string{"password"}},
		"software stmt":     map[string]any{"redirect_uris": []string{"https://n.example/cb"}, "software_statement": "x"},
		"missing redirects": map[string]any{"client_name": "x"},
	} {
		if p := e.dcrDo("PUT", "/"+id, reg, b); p.Status != 400 {
			t.Errorf("%s: %d %s", name, p.Status, p.Raw)
		}
	}
	if cl, _ := e.st.GetClientByClientID(context.Background(), dcrRealm, id); cl.Name != "Old" || cl.RedirectURIs[0] != "http://localhost/cb" {
		t.Fatalf("invalid PUT modified the client: %+v", cl)
	}
	// Valid PUT replaces the metadata, rotates nothing and returns neither secret.
	p := e.dcrDo("PUT", "/"+id, reg, map[string]any{"redirect_uris": []string{"https://new.example/cb"}, "client_name": "New",
		"grant_types": []string{"authorization_code"}, "contacts": []string{"x@example.com"}})
	if p.Status != 200 || str(p.M, "client_name") != "New" || p.M["grant_types"].([]any)[0] != "authorization_code" {
		t.Fatalf("PUT: %d %s", p.Status, p.Raw)
	}
	if _, has := p.M["client_secret"]; has {
		t.Error("PUT returned a secret")
	}
	if _, has := p.M["registration_access_token"]; has {
		t.Error("PUT returned a registration token")
	}
	cl, _ := e.st.GetClientByClientID(context.Background(), dcrRealm, id)
	if cl.Name != "New" || cl.RedirectURIs[0] != "https://new.example/cb" || cl.ServiceAccount || cl.SecretHash != oidc.HashSecret(secret) {
		t.Fatalf("after PUT: %+v", cl)
	}
	if e.dcrDo("GET", "/"+id, reg, nil).Status != 200 {
		t.Error("registration token stopped working after PUT (nothing should rotate)")
	}
	// An admin-disabled client stays disabled.
	cl.Enabled = false
	_ = e.st.UpdateClient(context.Background(), cl)
	e.dcrDo("PUT", "/"+id, reg, map[string]any{"redirect_uris": []string{"https://new.example/cb"}})
	if cl2, _ := e.st.GetClientByClientID(context.Background(), dcrRealm, id); cl2.Enabled {
		t.Error("PUT re-enabled an admin-disabled client")
	}
	cl.Enabled = true
	_ = e.st.UpdateClient(context.Background(), cl)

	// DELETE removes the client and the registration.
	if d := e.dcrDo("DELETE", "/"+id, reg, nil); d.Status != 204 {
		t.Fatalf("DELETE: %d %s", d.Status, d.Raw)
	}
	if _, err := e.st.GetClientByClientID(context.Background(), dcrRealm, id); !errors.Is(err, idp.ErrNotFound) {
		t.Error("client still exists")
	}
	if _, err := e.st.GetRegisteredClient(context.Background(), dcrRealm, id); !errors.Is(err, idp.ErrNotFound) {
		t.Error("registration record still exists")
	}
	if e.dcrDo("GET", "/"+id, reg, nil).Status != 401 {
		t.Error("registration token works after DELETE")
	}
	if x := e.tokenReq(id, secret, url.Values{"grant_type": {"client_credentials"}}); x.Status == 200 {
		t.Error("deleted client still gets tokens")
	}
	if got := string(e.api(200, "GET", "/realms/"+dcrRealm+"/registered-clients", nil)); strings.Contains(got, id) {
		t.Errorf("deleted client still listed: %s", got)
	}
}

// ---- policy ----

func TestDCRPolicyAndCap(t *testing.T) {
	e := dcrEnv(t)
	pol := "/realms/" + dcrRealm + "/registration-policy"
	var d struct {
		MaxClients        int
		AllowedGrantTypes []string
	}
	_ = json.Unmarshal(e.api(200, "GET", pol, nil), &d)
	if d.MaxClients != 100 || len(d.AllowedGrantTypes) != 3 {
		t.Fatalf("defaults: %+v", d)
	}
	for name, b := range map[string]any{
		"missing maxClients": map[string]any{"allowedGrantTypes": []string{"authorization_code"}},
		"negative":           map[string]any{"maxClients": -1},
		"huge":               map[string]any{"maxClients": 1000000},
		"password":           map[string]any{"maxClients": 1, "allowedGrantTypes": []string{"password"}},
		"empty list":         map[string]any{"maxClients": 1, "allowedGrantTypes": []string{}},
		"duplicate":          map[string]any{"maxClients": 1, "allowedGrantTypes": []string{"authorization_code", "authorization_code"}},
		"unknown field":      map[string]any{"maxClients": 1, "x": 1},
	} {
		if code, body, _ := e.call("PUT", pol, e.token, b); code != 400 {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	e.api(200, "PUT", pol, map[string]any{"maxClients": 2, "allowedGrantTypes": []string{"authorization_code", "refresh_token"}})

	iat := e.iat(10)
	body := map[string]any{"redirect_uris": []string{"https://a.example/cb"}}
	a := e.registerOK(iat.Token, body)
	e.registerOK(iat.Token, body)
	before := e.iatRemaining(iat.ID)
	r := e.register(iat.Token, body)
	if r.Status != 403 || str(r.M, "error") != "access_denied" {
		t.Fatalf("over cap: %d %s", r.Status, r.Raw)
	}
	if e.iatRemaining(iat.ID) != before || len(e.dcrClients()) != 2 {
		t.Error("a refused registration consumed a token use or left a client")
	}
	// An admin-created client does not count against the cap.
	e.api(201, "POST", "/realms/"+dcrRealm+"/clients", map[string]any{"clientId": "manual", "enabled": true})
	if r := e.register(iat.Token, body); r.Status != 403 {
		t.Errorf("cap with admin clients: %d", r.Status)
	}
	// Policy restricts grants.
	if r := e.register(iat.Token, map[string]any{"grant_types": []string{"client_credentials"}}); r.Status != 400 {
		t.Errorf("grant outside the policy: %d %s", r.Status, r.Raw)
	}
	// Deleting frees a slot.
	if d := e.dcrDo("DELETE", "/"+str(a.M, "client_id"), str(a.M, "registration_access_token"), nil); d.Status != 204 {
		t.Fatal("delete")
	}
	e.registerOK(iat.Token, body)
	// maxClients 0 switches registration off.
	e.api(200, "PUT", pol, map[string]any{"maxClients": 0})
	if r := e.register(iat.Token, body); r.Status != 403 {
		t.Errorf("maxClients 0: %d", r.Status)
	}
	_ = json.Unmarshal(e.api(200, "GET", pol, nil), &d)
	if d.MaxClients != 0 || len(d.AllowedGrantTypes) != 3 {
		t.Errorf("policy after PUT: %+v", d)
	}
}

// Concurrent registrations never leave more clients than the cap.
func TestDCRCapRace(t *testing.T) {
	e := dcrEnv(t)
	e.api(200, "PUT", "/realms/"+dcrRealm+"/registration-policy", map[string]any{"maxClients": 3})
	iat := e.iat(20)
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if e.register(iat.Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"}}).Status == 201 {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	n := len(e.dcrClients())
	rows, _ := e.st.ListRegisteredClients(context.Background(), dcrRealm)
	if n > 3 || len(rows) != n || int(wins.Load()) != n {
		t.Fatalf("clients=%d rows=%d wins=%d (cap 3)", n, len(rows), wins.Load())
	}
}

func TestDCRRegisteredClientsListing(t *testing.T) {
	e := dcrEnv(t)
	e.api(201, "POST", "/realms/"+dcrRealm+"/clients", map[string]any{"clientId": "manual", "enabled": true})
	iat := e.iat(1)
	r := e.registerOK(iat.Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"}, "client_name": "Tool"})
	var l []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", "/realms/"+dcrRealm+"/registered-clients", nil), &l)
	if len(l) != 1 || l[0]["clientId"] != str(r.M, "client_id") || l[0]["createdVia"] != "dcr" || l[0]["initialTokenId"] != iat.ID {
		t.Fatalf("listing: %v", l)
	}
}

// ---- rate limit ----

func TestDCRRateLimit(t *testing.T) {
	e := dcrEnv(t)
	var limited, denied int
	for i := 0; i < 25; i++ {
		switch r := e.register("hiat_guess", map[string]any{}); r.Status {
		case 401:
			denied++
		case 429:
			limited++
			if r.Hdr.Get("Retry-After") == "" {
				t.Error("no Retry-After")
			}
		default:
			t.Fatalf("status %d", r.Status)
		}
	}
	if denied != 20 || limited != 5 {
		t.Errorf("401s=%d 429s=%d, want 20/5", denied, limited)
	}
	// A valid token is limited too: guessing and using share the budget.
	if r := e.register(e.iat(1).Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"}}); r.Status != 429 {
		t.Errorf("valid token past the limit: %d", r.Status)
	}
}

func TestDCRManagementRateLimit(t *testing.T) {
	e := dcrEnv(t)
	var last int
	n401 := 0
	for i := 0; i < 65; i++ {
		last = e.dcrDo("GET", "/hc_x", "hrat_guess", nil).Status
		if last == 401 {
			n401++
		}
	}
	if n401 != 60 || last != 429 {
		t.Errorf("401s=%d last=%d", n401, last)
	}
}

// failRL makes the rate-limit store fail; DCR must fail closed.
type failRL struct{ core.Store }

func (failRL) HitRateLimit(context.Context, string, time.Time, time.Duration, int) (bool, error) {
	return true, errors.New("boom")
}
func (f failRL) Unwrap() core.Store { return f.Store }

func TestDCRRateLimitFailsClosed(t *testing.T) {
	e := dcrEnv(t)
	iat := e.iat(1)
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: failRL{e.st}, Signer: e.signer, Hasher: e.hasher, BaseURL: e.srv.URL}))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/realms/apps/clients-registrations/openid-connect",
		strings.NewReader(`{"redirect_uris":["https://a.example/cb"]}`))
	req.Header.Set("Authorization", "Bearer "+iat.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 503 || len(e.dcrClients()) != 0 {
		t.Errorf("status %d, clients %d", resp.StatusCode, len(e.dcrClients()))
	}
}

// ---- feature off, discovery, disabled realm ----

type noDCR struct{ core.Store }

func TestDCRFeatureOffAndDiscovery(t *testing.T) {
	e := dcrEnv(t)
	disc := func(base string) map[string]any {
		resp, err := http.Get(base + "/realms/apps/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m
	}
	if got := str(disc(e.srv.URL), "registration_endpoint"); got != e.srv.URL+"/realms/apps/clients-registrations/openid-connect" {
		t.Errorf("registration_endpoint %q", got)
	}
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: noDCR{e.st}, Signer: e.signer, Hasher: e.hasher, BaseURL: e.srv.URL}))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if _, has := disc(srv.URL)["registration_endpoint"]; has {
		t.Error("registration_endpoint advertised without a DCR store")
	}
	for _, m := range []string{"POST", "GET", "PUT", "DELETE"} {
		p := "/realms/apps/clients-registrations/openid-connect"
		if m != "POST" {
			p += "/hc_x"
		}
		req, _ := http.NewRequest(m, srv.URL+p, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer x")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 501 {
			t.Errorf("%s without a store: %d", m, resp.StatusCode)
		}
	}
	// Disabled / unknown realm: 404.
	rl, _ := e.st.GetRealm(context.Background(), dcrRealm)
	rl.Enabled = false
	_ = e.st.UpdateRealm(context.Background(), rl)
	iat := e.iat(1)
	if r := e.register(iat.Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"}}); r.Status != 404 {
		t.Errorf("disabled realm: %d", r.Status)
	}
}

func TestDCRAdminRoutesWithoutStore(t *testing.T) {
	e := newEnvWith(t, func(cfg *admin.Config, st *memstore.Store, _ string) { cfg.Store = noDCR{st} })
	for _, p := range []string{"/realms/" + realm + "/initial-access-tokens", "/realms/" + realm + "/registration-policy", "/realms/" + realm + "/registered-clients"} {
		if code, body, _ := e.call("GET", p, e.token, nil); code != 501 {
			t.Errorf("GET %s: %d %s", p, code, body)
		}
	}
}

// ---- audit ----

func TestDCRAuditEvents(t *testing.T) {
	e := dcrEnv(t)
	iat := e.iat(3)
	e.register("hiat_bad", map[string]any{}) // CLIENT_REGISTER_ERROR (invalid_token)
	r := e.registerOK(iat.Token, map[string]any{"redirect_uris": []string{"https://a.example/cb"}, "client_name": "audited"})
	id, secret, reg := str(r.M, "client_id"), str(r.M, "client_secret"), str(r.M, "registration_access_token")
	e.dcrDo("PUT", "/"+id, reg, map[string]any{"redirect_uris": []string{"https://b.example/cb"}})
	e.dcrDo("DELETE", "/"+id, reg, nil)
	evs, _ := e.st.ListEvents(context.Background(), dcrRealm, 100)
	got := map[string]bool{}
	for _, ev := range evs {
		got[ev.Type] = true
		all := ev.Detail + ev.UserID + ev.ClientID + ev.IP + ev.Type
		for what, v := range map[string]string{"secret": secret, "registration token": reg, "initial token": iat.Token, "bad token": "hiat_bad"} {
			if strings.Contains(all, v) {
				t.Errorf("event %s leaks the %s", ev.Type, what)
			}
		}
	}
	for _, typ := range []string{"CLIENT_REGISTER", "CLIENT_REGISTER_ERROR", "CLIENT_UPDATE_REGISTRATION", "CLIENT_DELETE_REGISTRATION"} {
		if !got[typ] {
			t.Errorf("no %s event (have %v)", typ, got)
		}
	}
}

// ---- XSS ----

func TestDCRClientNameEscapedOnLoginPage(t *testing.T) {
	e := dcrEnv(t)
	name := `<script>alert(1)</script><img src=x onerror=alert(2)>"'&`
	r := e.registerOK(e.iat(1).Token, map[string]any{"redirect_uris": []string{"http://localhost/cb"}, "client_name": name,
		"token_endpoint_auth_method": "none"})
	if str(r.M, "client_name") != name {
		t.Fatalf("client_name round trip: %q", str(r.M, "client_name"))
	}
	st, page := e.authPage(str(r.M, "client_id"), "http://localhost/cb")
	if st != 200 || !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("login page: %d\n%s", st, page)
	}
	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img src=x") {
		t.Error("client_name rendered unescaped")
	}
	// The JSON API returns it as data, with a JSON content type.
	if ct := e.dcrDo("GET", "/"+str(r.M, "client_id"), str(r.M, "registration_access_token"), nil).Hdr.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
}
