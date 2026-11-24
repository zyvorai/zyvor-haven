// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
)

// validate runs a raw JSON body through the same path as the handler.
func validate(t *testing.T, body string, allowed []string) (dcrNormalized, *dcrErr) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	m, err := dcrReadMeta(w, r)
	if err != nil {
		return dcrNormalized{}, err
	}
	return dcrValidate(m, allowed)
}

func TestDCRValidateTable(t *testing.T) {
	all := core.DCRGrantTypes
	longURI := `"https://app.example/` + strings.Repeat("a", 2100) + `"`
	eleven := make([]string, 11)
	contacts := make([]string, 11)
	for i := range eleven {
		eleven[i] = `"https://app.example/cb` + string(rune('a'+i)) + `"`
		contacts[i] = `"a@example.com"`
	}
	r := func(uris string, extra string) string {
		s := `{"redirect_uris":[` + uris + `]`
		if extra != "" {
			s += "," + extra
		}
		return s + "}"
	}
	const good = `"https://app.example/cb"`
	cases := []struct {
		name, body, code string
	}{
		// redirect URIs
		{"http non-loopback", r(`"http://evil.example/cb"`, ""), "invalid_redirect_uri"},
		{"http localhost lookalike", r(`"http://localhost.evil.example/cb"`, ""), "invalid_redirect_uri"},
		{"wildcard host", r(`"https://*.example.com/cb"`, ""), "invalid_redirect_uri"},
		{"wildcard path", r(`"https://app.example/*"`, ""), "invalid_redirect_uri"},
		{"javascript", r(`"javascript:alert(1)"`, ""), "invalid_redirect_uri"},
		{"JAVASCRIPT upper", r(`"JavaScript:alert(1)"`, ""), "invalid_redirect_uri"},
		{"data", r(`"data:text/html,x"`, ""), "invalid_redirect_uri"},
		{"vbscript", r(`"vbscript:x"`, ""), "invalid_redirect_uri"},
		{"file", r(`"file:///etc/passwd"`, ""), "invalid_redirect_uri"},
		{"blob", r(`"blob:https://a.example/x"`, ""), "invalid_redirect_uri"},
		{"fragment", r(`"https://app.example/cb#x"`, ""), "invalid_redirect_uri"},
		{"userinfo", r(`"https://u:p@app.example/cb"`, ""), "invalid_redirect_uri"},
		{"no host", r(`"https:///cb"`, ""), "invalid_redirect_uri"},
		{"too long", r(longURI, ""), "invalid_redirect_uri"},
		{"eleven uris", r(strings.Join(eleven, ","), ""), "invalid_redirect_uri"},
		{"empty uri", r(`""`, ""), "invalid_redirect_uri"},
		{"control char", r(`"https://app.example/cb\n"`, ""), "invalid_redirect_uri"},
		{"leading space", r(`" https://app.example/cb"`, ""), "invalid_redirect_uri"},
		{"backslash", r(`"https://app.example\\@evil.example/cb"`, ""), "invalid_redirect_uri"},
		{"custom scheme for web", r(`"com.example.app:/cb"`, ""), "invalid_redirect_uri"},
		{"custom scheme no dot (native)", r(`"myapp:/cb"`, `"application_type":"native"`), "invalid_redirect_uri"},
		{"ftp (native)", r(`"ftp://a.example/cb"`, `"application_type":"native"`), "invalid_redirect_uri"},
		{"native http non-loopback", r(`"http://app.example/cb"`, `"application_type":"native"`), "invalid_redirect_uri"},
		{"redirects missing", `{}`, "invalid_redirect_uri"},
		{"redirects empty list", `{"redirect_uris":[]}`, "invalid_redirect_uri"},
		// grants
		{"password grant", r(good, `"grant_types":["password"]`), "invalid_client_metadata"},
		{"implicit grant", r(good, `"grant_types":["implicit"]`), "invalid_client_metadata"},
		{"device grant", r(good, `"grant_types":["urn:ietf:params:oauth:grant-type:device_code"]`), "invalid_client_metadata"},
		{"jwt-bearer grant", r(good, `"grant_types":["urn:ietf:params:oauth:grant-type:jwt-bearer"]`), "invalid_client_metadata"},
		{"refresh alone", r(good, `"grant_types":["refresh_token"]`), "invalid_client_metadata"},
		{"refresh + cc, no code", r(good, `"grant_types":["refresh_token","client_credentials"]`), "invalid_client_metadata"},
		{"public client_credentials", r(good, `"token_endpoint_auth_method":"none","grant_types":["authorization_code","client_credentials"]`), "invalid_client_metadata"},
		{"public cc only", `{"token_endpoint_auth_method":"none","grant_types":["client_credentials"]}`, "invalid_client_metadata"},
		// response types
		{"response_type token", r(good, `"response_types":["token"]`), "invalid_client_metadata"},
		{"response_type hybrid", r(good, `"response_types":["code id_token"]`), "invalid_client_metadata"},
		{"code response without code grant", `{"grant_types":["client_credentials"],"response_types":["code"]}`, "invalid_client_metadata"},
		// auth method, scope, type
		{"auth method private_key_jwt", r(good, `"token_endpoint_auth_method":"private_key_jwt"`), "invalid_client_metadata"},
		{"auth method tls", r(good, `"token_endpoint_auth_method":"tls_client_auth"`), "invalid_client_metadata"},
		{"unknown scope", r(good, `"scope":"openid admin"`), "invalid_client_metadata"},
		{"offline_access without refresh", r(good, `"scope":"openid offline_access"`), "invalid_client_metadata"},
		{"application_type", r(good, `"application_type":"desktop"`), "invalid_client_metadata"},
		// other metadata
		{"logout uri http", r(good, `"backchannel_logout_uri":"http://evil.example/lo"`), "invalid_client_metadata"},
		{"logout uri creds", r(good, `"backchannel_logout_uri":"https://u:p@a.example/lo"`), "invalid_client_metadata"},
		{"client_name too long", r(good, `"client_name":"`+strings.Repeat("n", 256)+`"`), "invalid_client_metadata"},
		{"client_name control", r(good, `"client_name":"a\u0000b"`), "invalid_client_metadata"},
		{"eleven contacts", r(good, `"contacts":[`+strings.Join(contacts, ",")+`]`), "invalid_client_metadata"},
		{"empty contact", r(good, `"contacts":[""]`), "invalid_client_metadata"},
		{"logo javascript", r(good, `"logo_uri":"javascript:alert(1)"`), "invalid_client_metadata"},
		{"client_uri http", r(good, `"client_uri":"http://evil.example"`), "invalid_client_metadata"},
		{"policy_uri userinfo", r(good, `"policy_uri":"https://u:p@a.example/p"`), "invalid_client_metadata"},
		{"tos_uri no host", r(good, `"tos_uri":"https:///x"`), "invalid_client_metadata"},
		// shape
		{"redirect_uris wrong type", `{"redirect_uris":"https://a.example/cb"}`, "invalid_client_metadata"},
		{"grant_types wrong type", r(good, `"grant_types":"authorization_code"`), "invalid_client_metadata"},
		{"client_name wrong type", r(good, `"client_name":5`), "invalid_client_metadata"},
		{"not json", `not json`, "invalid_client_metadata"},
		{"trailing data", r(good, "") + ` {}`, "invalid_client_metadata"},
		{"array body", `[]`, "invalid_client_metadata"},
		{"empty body", ``, "invalid_client_metadata"},
		{"software statement", r(good, `"software_statement":"eyJ.x.y"`), "invalid_software_statement"},
	}
	for _, c := range cases {
		_, err := validate(t, c.body, all)
		if err == nil || err.code != c.code {
			t.Errorf("%s: got %v, want %s", c.name, err, c.code)
		}
	}
	// Policy restricts grants.
	if _, err := validate(t, r(good, `"grant_types":["authorization_code"]`), []string{"client_credentials"}); err == nil || err.code != "invalid_client_metadata" {
		t.Errorf("policy not enforced: %v", err)
	}
	// Defaults.
	if n, err := validate(t, r(good, `"response_types":[],"scope":""`), all); err != nil || n.reg.Scope != "openid profile email" {
		t.Errorf("defaults: %v %+v", err, n.reg)
	}
}

func TestDCRValidateAccepts(t *testing.T) {
	good := []string{
		`{"redirect_uris":["https://app.example/cb"]}`,
		`{"redirect_uris":["http://localhost:3000/cb","http://127.0.0.1:8080/cb","http://[::1]:1/cb"]}`,
		`{"application_type":"native","redirect_uris":["com.example.app:/cb","http://127.0.0.1:5/cb"]}`,
		`{"grant_types":["client_credentials"]}`,
		`{"redirect_uris":["https://a.example/cb"],"grant_types":["authorization_code","refresh_token"],"scope":"openid offline_access"}`,
		`{"redirect_uris":["https://a.example/cb"],"unknown":{"x":[1,2]},"jwks_uri":"https://a.example/jwks","backchannel_logout_session_required":true}`,
	}
	for _, b := range good {
		if _, err := validate(t, b, core.DCRGrantTypes); err != nil {
			t.Errorf("%s: %+v", b, err)
		}
	}
	n, _ := validate(t, `{"redirect_uris":["https://a.example/cb","https://a.example/cb"],"token_endpoint_auth_method":"none"}`, core.DCRGrantTypes)
	if len(n.client.RedirectURIs) != 1 || !n.client.Public || !n.client.RequirePKCE {
		t.Errorf("normalisation: %+v", n.client)
	}
}
