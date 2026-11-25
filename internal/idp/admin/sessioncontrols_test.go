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

func (e *env) auditAdmin() {
	e.t.Helper()
	ctx := context.Background()
	rl, err := e.st.GetRealm(ctx, realm)
	if err != nil {
		e.t.Fatal(err)
	}
	rl.AdminEventsLogged = true
	if err := e.st.UpdateRealm(ctx, rl); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) audited(detail string) bool {
	evs, _ := e.st.ListEvents(context.Background(), realm, 100)
	for _, ev := range evs {
		if strings.HasPrefix(ev.Type, "ADMIN_") && strings.HasPrefix(ev.Detail, detail) {
			return true
		}
	}
	return false
}

func (e *env) getJSON(path string) map[string]any {
	e.t.Helper()
	var out map[string]any
	if err := json.Unmarshal(e.api(200, "GET", path, nil), &out); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func TestSessionPolicyAdmin(t *testing.T) {
	e := newEnv(t)
	e.auditAdmin()
	r := "/realms/" + realm + "/session-policy"
	got := e.getJSON(r)
	if got["maxSessionsPerUser"] != float64(0) || got["rememberMe"] != false || got["onLimit"] != "revoke_oldest" ||
		got["rememberMaxSeconds"] != float64(0) {
		t.Fatalf("default must be everything off: %v", got)
	}
	e.api(200, "PUT", r, map[string]any{"maxSessionsPerUser": 3, "onLimit": "deny_new", "rememberMe": true,
		"rememberIdleSeconds": 86400, "rememberMaxSeconds": 864000})
	p, err := e.st.GetSessionPolicy(context.Background(), realm)
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxSessions != 3 || p.OnLimit != core.SessionLimitDenyNew || !p.RememberMe || p.RememberIdle != 24*time.Hour || p.RememberMax != 240*time.Hour {
		t.Fatalf("stored: %+v", p)
	}
	if !e.audited("session-policy ") {
		t.Error("not audited")
	}
	// Opting in without lifetimes shows the defaults that apply.
	e.api(200, "PUT", r, map[string]any{"rememberMe": true})
	if got = e.getJSON(r); got["rememberIdleSeconds"] != float64(7*86400) || got["rememberMaxSeconds"] != float64(30*86400) || got["maxSessionsPerUser"] != float64(0) {
		t.Fatalf("effective values: %v", got)
	}
	for name, b := range map[string]map[string]any{
		"unknown field":  {"bogus": 1},
		"negative limit": {"maxSessionsPerUser": -1},
		"huge limit":     {"maxSessionsPerUser": 1001},
		"action":         {"onLimit": "ignore"},
		"max too long":   {"rememberMe": true, "rememberMaxSeconds": 91 * 86400},
		"max overflow":   {"rememberMe": true, "rememberMaxSeconds": int64(1) << 62},
		"idle overflow":  {"rememberMe": true, "rememberIdleSeconds": int64(1) << 62},
		"max too short":  {"rememberMe": true, "rememberMaxSeconds": 3600},
		"idle too short": {"rememberMe": true, "rememberIdleSeconds": 60},
		"negative":       {"rememberIdleSeconds": -5},
		"idle over max":  {"rememberMe": true, "rememberIdleSeconds": 3 * 86400, "rememberMaxSeconds": 2 * 86400},
	} {
		t.Run(name, func(t *testing.T) { e.api(400, "PUT", r, b) })
	}
	if p, _ := e.st.GetSessionPolicy(context.Background(), realm); !p.RememberMe || p.MaxSessions != 0 {
		t.Fatalf("a refused request changed the policy: %+v", p)
	}
	if code, _, _ := e.call("PUT", r, "", map[string]any{}); code != 401 {
		t.Errorf("unauthenticated PUT: %d", code)
	}
	if code, _, _ := e.call("GET", r, "", nil); code != 401 {
		t.Errorf("unauthenticated GET: %d", code)
	}
	e.api(404, "GET", "/realms/nope/session-policy", nil)
}

func TestPasskeyOnlyAdmin(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm + "/passkey-policy"
	only := func() bool {
		v, err := e.st.PasskeyOnly(context.Background(), realm)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if got := e.getJSON(r); got["passkeyOnly"] != false || only() {
		t.Fatalf("default off: %v", got)
	}
	e.api(200, "PUT", r, map[string]any{"passkeyOnly": true})
	if !only() {
		t.Fatal("not stored")
	}
	// A client that only knows requirePasskeys leaves it alone.
	e.api(200, "PUT", r, map[string]any{"requirePasskeys": true})
	if got := e.getJSON(r); got["passkeyOnly"] != true || got["requirePasskeys"] != true {
		t.Fatalf("%v", got)
	}
	e.api(200, "PUT", r, map[string]any{"requirePasskeys": true, "passkeyOnly": false})
	if only() {
		t.Fatal("not switched off")
	}
	if code, _, _ := e.call("PUT", r, "", map[string]any{"passkeyOnly": true}); code != 401 || only() {
		t.Errorf("unauthenticated PUT: %d", code)
	}
}

func TestFrontchannelAdmin(t *testing.T) {
	e := newEnv(t)
	e.auditAdmin()
	ctx := context.Background()
	if err := e.st.CreateClient(ctx, core.Client{ID: "c-fc", Realm: realm, ClientID: "web", Enabled: true,
		RedirectURIs: []string{"https://web.example/cb"}}); err != nil {
		t.Fatal(err)
	}
	r := "/realms/" + realm + "/clients/c-fc/frontchannel-logout"
	if got := e.getJSON(r); got["frontchannelLogoutUrl"] != "" {
		t.Fatalf("%v", got)
	}
	for name, b := range map[string]map[string]any{
		"other origin":  {"frontchannelLogoutUrl": "https://evil.example/fc"},
		"http":          {"frontchannelLogoutUrl": "http://web.example/fc"},
		"injection":     {"frontchannelLogoutUrl": "https://web.example;script-src/fc"},
		"fragment":      {"frontchannelLogoutUrl": "https://web.example/fc#x"},
		"missing field": {},
		"unknown field": {"frontchannelLogoutUrl": "", "x": 1},
	} {
		t.Run(name, func(t *testing.T) { e.api(400, "PUT", r, b) })
	}
	e.api(200, "PUT", r, map[string]any{"frontchannelLogoutUrl": "https://web.example/fc"})
	if got := e.getJSON(r); got["frontchannelLogoutUrl"] != "https://web.example/fc" {
		t.Fatalf("%v", got)
	}
	if !e.audited("client web frontchannel-logout") {
		t.Error("not audited")
	}
	if code, _, _ := e.call("PUT", r, "", map[string]any{"frontchannelLogoutUrl": ""}); code != 401 {
		t.Errorf("unauthenticated PUT: %d", code)
	}
	e.api(404, "PUT", "/realms/"+realm+"/clients/nope/frontchannel-logout", map[string]any{"frontchannelLogoutUrl": ""})
	e.api(200, "PUT", r, map[string]any{"frontchannelLogoutUrl": ""})
	if got := e.getJSON(r); got["frontchannelLogoutUrl"] != "" {
		t.Fatalf("not removed: %v", got)
	}
}
