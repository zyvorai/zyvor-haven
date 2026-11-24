// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const deviceURN = "urn:ietf:params:oauth:grant-type:device_code"

func (e *env) allowDevice() {
	e.t.Helper()
	e.api(200, "PUT", "/realms/"+dcrRealm+"/registration-policy", map[string]any{"maxClients": 10,
		"allowedGrantTypes": []string{"authorization_code", "refresh_token", "client_credentials", deviceURN}})
}

// ---- DCR accepts the device grant, under the same safety rules ----

func TestDCRDeviceGrantNeedsPolicyOptIn(t *testing.T) {
	e := dcrEnv(t)
	body := map[string]any{"grant_types": []string{deviceURN}, "token_endpoint_auth_method": "none", "client_name": "tv"}
	// The default policy (existing realms) does not hand out the device grant.
	if r := e.register(e.iat(5).Token, body); r.Status != 400 || str(r.M, "error") != "invalid_client_metadata" {
		t.Fatalf("default policy: %d %s", r.Status, r.Raw)
	}
	var pol struct{ AllowedGrantTypes []string }
	_ = json.Unmarshal(e.api(200, "GET", "/realms/"+dcrRealm+"/registration-policy", nil), &pol)
	for _, g := range pol.AllowedGrantTypes {
		if g == deviceURN {
			t.Fatal("device grant is in the default policy")
		}
	}
	e.allowDevice()
	if r := e.register(e.iat(5).Token, body); r.Status != 201 {
		t.Fatalf("after opt-in: %d %s", r.Status, r.Raw)
	}
}

func TestDCRDeviceClientWorks(t *testing.T) {
	e := dcrEnv(t)
	e.allowDevice()
	iat := e.iat(10)
	r := e.registerOK(iat.Token, map[string]any{"grant_types": []string{deviceURN, "refresh_token"},
		"token_endpoint_auth_method": "none", "client_name": "tv", "scope": "openid offline_access"})
	id := str(r.M, "client_id")
	if gt, _ := json.Marshal(r.M["grant_types"]); !strings.Contains(string(gt), deviceURN) {
		t.Fatalf("grant_types echo: %s", gt)
	}
	if _, has := r.M["client_secret"]; has {
		t.Fatal("public device client got a secret")
	}
	if rt, _ := r.M["response_types"].([]any); len(rt) != 0 {
		t.Fatalf("response_types for a device-only client: %v", rt)
	}
	cl := e.dcrClients()
	if len(cl) != 1 || !cl[0].DeviceFlow || cl[0].AuthCodeFlow || cl[0].ServiceAccount || !cl[0].Public {
		t.Fatalf("stored client: %+v", cl)
	}
	// It can start a device authorization and is told to wait.
	resp, err := http.PostForm(e.srv.URL+"/realms/"+dcrRealm+"/protocol/openid-connect/auth/device", url.Values{"client_id": {id}, "scope": {"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var dev map[string]any
	_ = json.Unmarshal(b, &dev)
	if resp.StatusCode != 200 || str(dev, "device_code") == "" {
		t.Fatalf("device authorization: %d %s", resp.StatusCode, b)
	}
	if p := e.tokenReq(id, "", url.Values{"grant_type": {deviceURN}, "device_code": {str(dev, "device_code")}}); p.Status != 400 || str(p.M, "error") != "authorization_pending" {
		t.Fatalf("poll: %d %s", p.Status, p.Raw)
	}
	// It is not an authorization-code client: no login can start for it.
	if st, _ := e.authPage(id, "http://localhost/cb"); st != 400 {
		t.Errorf("a device-only client could start a code-flow login: %d", st)
	}
	// And it cannot use client_credentials.
	if x := e.tokenReq(id, "", url.Values{"grant_type": {"client_credentials"}}); x.Status == 200 {
		t.Error("client_credentials worked for a device client")
	}
}

func TestDCRDeviceGrantRules(t *testing.T) {
	e := dcrEnv(t)
	e.allowDevice()
	iat := e.iat(20)
	for name, c := range map[string]struct {
		body map[string]any
		code int
	}{
		"device + client_credentials":  {map[string]any{"grant_types": []string{deviceURN, "client_credentials"}}, 400},
		"refresh alone":                {map[string]any{"grant_types": []string{"refresh_token"}}, 400},
		"device + response_types code": {map[string]any{"grant_types": []string{deviceURN}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"}, 400},
		"offline_access w/o refresh":   {map[string]any{"grant_types": []string{deviceURN}, "scope": "openid offline_access", "token_endpoint_auth_method": "none"}, 400},
		"unknown grant":                {map[string]any{"grant_types": []string{deviceURN, "password"}}, 400},
		"unknown scope":                {map[string]any{"grant_types": []string{deviceURN}, "scope": "openid admin", "token_endpoint_auth_method": "none"}, 400},
		"device + code needs redirect": {map[string]any{"grant_types": []string{deviceURN, "authorization_code"}}, 400},
		"device + code with redirect":  {map[string]any{"grant_types": []string{deviceURN, "authorization_code"}, "redirect_uris": []string{"https://a.example/cb"}}, 201},
		"confidential device client":   {map[string]any{"grant_types": []string{deviceURN}}, 201},
	} {
		if r := e.register(iat.Token, c.body); r.Status != c.code {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	// Narrowing the policy again closes the door.
	e.api(200, "PUT", "/realms/"+dcrRealm+"/registration-policy", map[string]any{"maxClients": 10, "allowedGrantTypes": []string{"authorization_code"}})
	if r := e.register(iat.Token, map[string]any{"grant_types": []string{deviceURN}}); r.Status != 400 {
		t.Errorf("after narrowing: %d %s", r.Status, r.Raw)
	}
}

func TestDCRDeviceGrantUpdate(t *testing.T) {
	e := dcrEnv(t)
	e.allowDevice()
	r := e.registerOK(e.iat(5).Token, map[string]any{"grant_types": []string{deviceURN}, "token_endpoint_auth_method": "none"})
	id, reg := str(r.M, "client_id"), str(r.M, "registration_access_token")
	// Dropping the device grant on update turns the flow off for the client.
	u := e.dcrDo("PUT", "/"+id, reg, map[string]any{"client_id": id, "grant_types": []string{"authorization_code"},
		"token_endpoint_auth_method": "none", "redirect_uris": []string{"https://a.example/cb"}})
	if u.Status != 200 {
		t.Fatalf("update: %d %s", u.Status, u.Raw)
	}
	if cl := e.dcrClients(); len(cl) != 1 || cl[0].DeviceFlow {
		t.Fatalf("device flow still on: %+v", cl)
	}
	// Adding it back is subject to the policy again.
	e.api(200, "PUT", "/realms/"+dcrRealm+"/registration-policy", map[string]any{"maxClients": 10, "allowedGrantTypes": []string{"authorization_code"}})
	if u := e.dcrDo("PUT", "/"+id, reg, map[string]any{"client_id": id, "grant_types": []string{deviceURN}, "token_endpoint_auth_method": "none"}); u.Status != 400 {
		t.Fatalf("update outside policy: %d %s", u.Status, u.Raw)
	}
	e.allowDevice()
	if u := e.dcrDo("PUT", "/"+id, reg, map[string]any{"client_id": id, "grant_types": []string{deviceURN}, "token_endpoint_auth_method": "none"}); u.Status != 200 {
		t.Fatalf("update: %d %s", u.Status, u.Raw)
	}
	if cl := e.dcrClients(); len(cl) != 1 || !cl[0].DeviceFlow || cl[0].AuthCodeFlow {
		t.Fatalf("device flow not on: %+v", cl)
	}
}

func TestPolicyAcceptsDeviceGrantOnly(t *testing.T) {
	e := dcrEnv(t)
	pol := "/realms/" + dcrRealm + "/registration-policy"
	if code, body, _ := e.call("PUT", pol, e.token, map[string]any{"maxClients": 1, "allowedGrantTypes": []string{deviceURN, deviceURN}}); code != 400 {
		t.Errorf("duplicate: %d %s", code, body)
	}
	if code, body, _ := e.call("PUT", pol, e.token, map[string]any{"maxClients": 1, "allowedGrantTypes": []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"}}); code != 400 {
		t.Errorf("other URN: %d %s", code, body)
	}
}

// ---- the Admin API never accepts a DPoP-bound token as a bearer token ----

func TestAdminRejectsDPoPBoundToken(t *testing.T) {
	e := newEnv(t)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
	enc := base64.RawURLEncoding.EncodeToString
	hdr, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": map[string]any{"kty": "EC", "crv": "P-256",
		"x": enc(pad(k.X.Bytes())), "y": enc(pad(k.Y.Bytes()))}})
	cl, _ := json.Marshal(map[string]any{"jti": "j1", "htm": "POST", "iat": time.Now().Unix(),
		"htu": e.srv.URL + "/realms/" + realm + "/protocol/openid-connect/token"})
	signed := enc(hdr) + "." + enc(cl)
	h := sha256.Sum256([]byte(signed))
	rr, ss, _ := ecdsa.Sign(rand.Reader, k, h[:])
	proof := signed + "." + enc(append(pad(rr.Bytes()), pad(ss.Bytes())...))

	req, _ := http.NewRequest("POST", e.srv.URL+"/realms/"+realm+"/protocol/openid-connect/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	req.SetBasicAuth("haven-admin", adminSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	_ = json.Unmarshal(b, &out)
	if resp.StatusCode != 200 || out.TokenType != "DPoP" || out.AccessToken == "" {
		t.Fatalf("bound admin token: %d %s", resp.StatusCode, b)
	}
	// The unbound admin token still works; the bound one is refused as a bearer.
	if code, body, _ := e.call("GET", "/realms", e.token, nil); code != 200 {
		t.Fatalf("control: %d %s", code, body)
	}
	if code, body, _ := e.call("GET", "/realms", out.AccessToken, nil); code != 401 {
		t.Fatalf("DPoP-bound token accepted by the Admin API: %d %s", code, body)
	}
}
