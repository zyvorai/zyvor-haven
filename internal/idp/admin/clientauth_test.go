// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
)

func TestClientAuthAdmin(t *testing.T) {
	e := newEnv(t)
	base := "/realms/" + realm + "/clients"
	conf := e.createID(base, map[string]any{"clientId": "bank", "enabled": true, "publicClient": false, "serviceAccountsEnabled": true})
	pub := e.createID(base, map[string]any{"clientId": "spa", "enabled": true, "publicClient": true, "standardFlowEnabled": true})
	url := base + "/" + conf + "/authentication"
	stored := func() core.Client {
		c, err := e.st.GetClientByClientID(context.Background(), realm, "bank")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	e.api(404, "GET", url, nil)
	e.api(404, "DELETE", url, nil)
	before := stored().SecretHash
	if before == "" {
		t.Fatal("expected a secret")
	}
	// A secret method (with certificate binding) keeps the secret.
	e.api(200, "PUT", url, map[string]any{"method": "client_secret_post", "certificateBoundTokens": true})
	if stored().SecretHash != before {
		t.Fatal("secret changed")
	}
	e.api(200, "POST", base+"/"+conf+"/secret", nil)

	jwks := ecJWKS(t, false)
	bads := map[string]map[string]any{
		"unknown field":        {"method": "private_key_jwt", "jwks": jwks, "bogus": true},
		"no method":            {},
		"unknown method":       {"method": "client_secret_jwt"},
		"no keys":              {"method": "private_key_jwt"},
		"private key":          {"method": "private_key_jwt", "jwks": ecJWKS(t, true)},
		"keys and uri":         {"method": "private_key_jwt", "jwks": jwks, "jwksUri": "https://c.example/k"},
		"http uri":             {"method": "private_key_jwt", "jwksUri": "http://c.example/k"},
		"loopback http uri":    {"method": "private_key_jwt", "jwksUri": "http://127.0.0.1/k"},
		"bad alg":              {"method": "private_key_jwt", "jwks": jwks, "signingAlg": "HS256"},
		"none on confidential": {"method": "none"},
		"tls without subject":  {"method": "tls_client_auth"},
		"tls two subjects":     {"method": "tls_client_auth", "tlsSubjectDn": "CN=a", "tlsSanDns": "a.example"},
		"self signed no x5c":   {"method": "self_signed_tls_client_auth", "jwks": jwks},
	}
	for name, b := range bads {
		t.Run(name, func(t *testing.T) { e.api(400, "PUT", url, b) })
	}
	if stored().SecretHash == "" {
		t.Fatal("a refused update removed the secret")
	}
	e.api(400, "PUT", base+"/"+pub+"/authentication", map[string]any{"method": "private_key_jwt", "jwks": jwks})
	e.api(200, "PUT", base+"/"+pub+"/authentication", map[string]any{"method": "none"})

	// A key method deletes the secret, and none can be made while it is set.
	e.api(200, "PUT", url, map[string]any{"method": "private_key_jwt", "jwks": jwks, "signingAlg": "ES256"})
	if stored().SecretHash != "" {
		t.Fatal("secret survived switching to private_key_jwt")
	}
	e.api(409, "POST", base+"/"+conf+"/secret", nil)
	if stored().SecretHash != "" {
		t.Fatal("a secret was created for a key client")
	}
	var got map[string]any
	if err := json.Unmarshal(e.api(200, "GET", url, nil), &got); err != nil {
		t.Fatal(err)
	}
	if got["method"] != "private_key_jwt" || got["signingAlg"] != "ES256" || got["jwks"] == nil {
		t.Fatalf("stored: %v", got)
	}
	// Editing the client does not bring a secret back.
	e.api(204, "PUT", base+"/"+conf, map[string]any{"clientId": "bank", "name": "Bank", "enabled": true, "publicClient": false, "serviceAccountsEnabled": true})
	if stored().SecretHash != "" {
		t.Fatal("client update restored a secret")
	}
	e.api(200, "PUT", url, map[string]any{"method": "tls_client_auth", "tlsSanDns": "client.example"})
	e.api(204, "DELETE", url, nil)
	if stored().SecretHash != "" {
		t.Fatal("deleting the settings restored a secret")
	}
	e.api(200, "POST", base+"/"+conf+"/secret", nil) // an explicit step
	if stored().SecretHash == "" {
		t.Fatal("no secret after regeneration")
	}

	e.api(404, "GET", base+"/nope/authentication", nil)
	e.api(404, "PUT", base+"/nope/authentication", map[string]any{"method": "client_secret_basic"})
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		if code, _, _ := e.call(m, url, "", map[string]any{"method": "client_secret_basic"}); code != 401 {
			t.Errorf("unauthenticated %s: %d", m, code)
		}
	}
	evs, err := e.st.ListEvents(context.Background(), realm, 200)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range evs {
		if strings.Contains(ev.Detail, "client-authentication") {
			found = true
			if strings.Contains(ev.Detail, "kty") {
				t.Errorf("audit detail leaks key material: %q", ev.Detail)
			}
		}
	}
	if !found {
		t.Error("no audit event")
	}
}

func TestClientAuthAdminProtectsAdminClient(t *testing.T) {
	e := newEnv(t)
	cl, err := e.st.GetClientByClientID(context.Background(), realm, "haven-admin")
	if err != nil {
		t.Skip("no haven-admin client in this environment: " + err.Error())
	}
	url := "/realms/" + realm + "/clients/" + cl.ID + "/authentication"
	e.api(409, "PUT", url, map[string]any{"method": "private_key_jwt", "jwks": ecJWKS(t, false)})
	e.api(409, "PUT", url, map[string]any{"method": "client_secret_basic", "certificateBoundTokens": true})
	after, _ := e.st.GetClientByClientID(context.Background(), realm, "haven-admin")
	if after.SecretHash != cl.SecretHash {
		t.Fatal("admin secret changed")
	}
}
