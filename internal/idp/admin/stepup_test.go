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

func TestStepUpPolicyAdmin(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm + "/stepup-policy"

	var got map[string]any
	if err := json.Unmarshal(e.api(200, "GET", r, nil), &got); err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != false || got["allowFallback"] != false || got["enforce"] != false {
		t.Fatalf("default must be everything off: %v", got)
	}

	body := map[string]any{"allowFallback": true, "enabled": true, "enforce": true, "onNewDevice": true, "onIpChange": true,
		"idleAfterSeconds": 3600, "onMaxAge": true, "sensitiveScopes": []string{"offline_access", "roles", "roles"},
		"sensitiveAuthMaxAgeSeconds": 300}
	e.api(200, "PUT", r, body)
	p, err := e.st.GetStepUpPolicy(context.Background(), realm)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enforce || !p.OnNewDevice || p.IdleAfter != time.Hour || p.SensitiveAuthMaxAge != 5*time.Minute ||
		len(p.SensitiveScopes) != 2 { // duplicate removed
		t.Fatalf("stored: %+v", p)
	}
	if err := json.Unmarshal(e.api(200, "GET", r, nil), &got); err != nil || got["idleAfterSeconds"] != float64(3600) {
		t.Fatalf("%v %v", err, got)
	}

	bads := map[string]map[string]any{
		"unknown field":      {"enabled": true, "bogus": 1},
		"negative idle":      {"enabled": true, "idleAfterSeconds": -1},
		"huge idle":          {"enabled": true, "idleAfterSeconds": 99999999999},
		"bad scope":          {"enabled": true, "sensitiveScopes": []string{"has space"}},
		"enforce w/o enable": {"enforce": true},
		"too many scopes": {"enabled": true, "sensitiveScopes": []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k",
			"l", "m", "n", "o", "p", "q", "r", "s", "t", "u"}},
	}
	for name, b := range bads {
		t.Run(name, func(t *testing.T) { e.api(400, "PUT", r, b) })
	}
	// Without a bearer token nothing is writable.
	if code, _, _ := e.call("PUT", r, "", body); code != 401 {
		t.Errorf("unauthenticated PUT: %d", code)
	}
}

func TestDevicesAdmin(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm
	alice, bob := e.mkUser("alice"), e.mkUser("bob")
	ctx := context.Background()
	now := time.Now().UTC()
	for _, d := range []core.KnownDevice{
		{Realm: realm, UserID: alice, Hash: "hashA1", IPHash: "SECRET-IP-HASH", LastSeen: now},
		{Realm: realm, UserID: alice, Hash: "hashA2", IPHash: "x", LastSeen: now.Add(-time.Hour)},
		{Realm: realm, UserID: bob, Hash: "hashB1", IPHash: "y", LastSeen: now},
	} {
		if err := e.st.TouchDevice(ctx, d, 20); err != nil {
			t.Fatal(err)
		}
	}
	raw := e.api(200, "GET", r+"/users/"+alice+"/devices", nil)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil || len(list) != 2 || list[0]["id"] != "hashA1" {
		t.Fatalf("%v %s", err, raw)
	}
	if strings.Contains(string(raw), "SECRET-IP-HASH") || strings.Contains(strings.ToLower(string(raw)), "iphash") {
		t.Errorf("device list leaks the IP hash: %s", raw)
	}
	e.api(404, "GET", r+"/users/nope/devices", nil)

	e.api(204, "DELETE", r+"/users/"+alice+"/devices/hashA1", nil)
	if l, _ := e.st.ListDevices(ctx, realm, alice); len(l) != 1 {
		t.Fatalf("after single delete: %+v", l)
	}
	// Another user's device cannot be deleted through this user's path.
	e.api(204, "DELETE", r+"/users/"+alice+"/devices/hashB1", nil)
	if l, _ := e.st.ListDevices(ctx, realm, bob); len(l) != 1 {
		t.Fatalf("bob's device was deleted via alice's path: %+v", l)
	}
	e.api(204, "DELETE", r+"/users/"+alice+"/devices", nil)
	if l, _ := e.st.ListDevices(ctx, realm, alice); len(l) != 0 {
		t.Fatalf("after delete all: %+v", l)
	}
	if l, _ := e.st.ListDevices(ctx, realm, bob); len(l) != 1 {
		t.Fatalf("delete-all touched another user: %+v", l)
	}
}
