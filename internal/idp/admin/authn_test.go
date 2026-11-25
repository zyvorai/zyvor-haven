// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

func TestACRPolicyAPI(t *testing.T) {
	e := newEnv(t)
	e.createID("/realms", map[string]any{"realm": "other", "enabled": true})
	path := "/realms/other/acr-policy"
	var got struct {
		core.ACRPolicy
		Default bool `json:"default"`
	}
	read := func() {
		t.Helper()
		got.ACRPolicy, got.Default = core.ACRPolicy{}, false
		if err := json.Unmarshal(e.api(200, "GET", path, nil), &got); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if !got.Default || len(got.Levels) != 3 || got.EnrollOnStepUp {
		t.Fatalf("default: %+v", got)
	}
	custom := map[string]any{"enrollOnStepUp": true, "levels": []any{
		map[string]any{"acr": "silver", "anyOf": [][]string{{"pwd"}}},
		map[string]any{"acr": "gold", "anyOf": [][]string{{"pwd", "otp"}}},
	}}
	e.api(200, "PUT", path, custom)
	read()
	if got.Default || len(got.Levels) != 2 || got.Levels[1].Value != "gold" || !got.EnrollOnStepUp {
		t.Fatalf("stored: %+v", got)
	}
	for name, body := range map[string]any{
		"no levels":       map[string]any{"levels": []any{}},
		"unknown method":  map[string]any{"levels": []any{map[string]any{"acr": "x", "anyOf": [][]string{{"sms"}}}}},
		"quote in value":  map[string]any{"levels": []any{map[string]any{"acr": `x"y`, "anyOf": [][]string{{"pwd"}}}}},
		"unknown field":   `{"levels":[{"acr":"x","anyOf":[["pwd"]]}],"nope":1}`,
		"admin elsewhere": map[string]any{"adminAcr": "x", "levels": []any{map[string]any{"acr": "x", "anyOf": [][]string{{"pwd"}}}}},
	} {
		if code, b, _ := e.call("PUT", path, e.token, body); code != 400 {
			t.Errorf("%s: %d %s", name, code, b)
		}
	}
	read()
	if len(got.Levels) != 2 {
		t.Fatal("a rejected PUT changed the policy")
	}
	e.api(204, "DELETE", path, nil)
	read()
	if !got.Default {
		t.Fatal("delete must restore the default")
	}
	e.api(404, "GET", "/realms/nope/acr-policy", nil)
}

func TestAdminAPIStepUpChallenge(t *testing.T) {
	e := newEnv(t)
	e.createID("/realms/"+realm+"/roles", map[string]any{"name": "haven-admin"})
	e.createID("/realms/"+realm+"/clients", map[string]any{
		"clientId": "app", "enabled": true, "publicClient": true, "standardFlowEnabled": true,
		"redirectUris": []string{"http://localhost/cb"}})
	id := e.createID("/realms/"+realm+"/users", map[string]any{"username": "boss", "enabled": true})
	e.api(204, "PUT", "/realms/"+realm+"/users/"+id+"/password", map[string]any{"type": "password", "value": goodPW})
	e.api(204, "POST", "/realms/"+realm+"/users/"+id+"/roles", []map[string]string{{"name": "haven-admin"}})
	userTok := e.login("app", "boss", goodPW) // a real password sign-in
	path := "/realms/" + realm + "/acr-policy"
	policy := func(adminACR string, maxAge int) {
		t.Helper()
		p := core.DefaultACRPolicy()
		p.AdminACR, p.AdminMaxAgeSeconds = adminACR, int64(maxAge)
		e.api(200, "PUT", path, p)
	}
	expect := func(what, tok string, want int, challenge ...string) {
		t.Helper()
		code, b, h := e.call("GET", "/realms", tok, nil)
		if code != want {
			t.Fatalf("%s: %d %s", what, code, b)
		}
		www := h.Get("WWW-Authenticate")
		for _, c := range challenge {
			if !strings.Contains(www, c) {
				t.Fatalf("%s: challenge %q lacks %q", what, www, c)
			}
		}
	}
	expect("no requirement", userTok, 200)

	policy(core.ACRMultiFactor, 0)
	expect("password token against mfa", userTok, 401, `Bearer error="insufficient_user_authentication"`,
		`acr_values="`+core.ACRMultiFactor+`"`)
	expect("service accounts carry no user authentication", e.token, 200)
	if _, _, h := e.call("GET", "/realms", "", nil); strings.Contains(h.Get("WWW-Authenticate"), "acr_values") {
		t.Fatal("the requirement is disclosed to an unauthenticated caller")
	}
	// A writing route is refused too, and nothing changes.
	if code, _, _ := e.call("DELETE", path, userTok, nil); code != 401 {
		t.Fatalf("delete with a weak token: %d", code)
	}
	policy(core.ACRSingleFactor, 0)
	expect("password token meets 1fa", userTok, 200)

	// Tokens with chosen claims, signed by the realm key.
	sign := func(amr []string, authTime time.Time) string {
		t.Helper()
		c := core.Claims{"iss": e.srv.URL + "/realms/" + realm, "sub": id, "typ": "Bearer",
			"exp": time.Now().Add(time.Hour).Unix(), "realm_access": map[string]any{"roles": []string{"haven-admin"}},
			"amr": amr, "acr": core.ACRPhishingResistant}
		if !authTime.IsZero() {
			c["auth_time"] = authTime.Unix()
		}
		tok, err := e.signer.Sign(context.Background(), realm, c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	policy(core.ACRMultiFactor, 300)
	expect("mfa and fresh", sign([]string{"pwd", "otp", "mfa"}, time.Now()), 200)
	expect("stronger than required", sign([]string{"webauthn", "user", "uv", "mfa"}, time.Now()), 200)
	expect("stale", sign([]string{"pwd", "otp", "mfa"}, time.Now().Add(-time.Hour)), 401, `max_age="300"`)
	expect("no auth_time", sign([]string{"pwd", "otp", "mfa"}, time.Time{}), 401, "insufficient_user_authentication")
	// The level is judged from the methods under the current ladder, not from
	// the acr string the token was issued with.
	expect("acr claim alone", sign([]string{"pwd"}, time.Now()), 401, "insufficient_user_authentication")
	policy("", 300)
	expect("max age only", sign([]string{"pwd"}, time.Now()), 200)
	expect("max age only, stale", sign([]string{"pwd"}, time.Now().Add(-time.Hour)), 401, `max_age="300"`)
}
