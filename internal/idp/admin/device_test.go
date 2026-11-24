// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClientDeviceFlowEnabled(t *testing.T) {
	e := newEnv(t)
	base := "/realms/" + realm + "/clients"
	get := func(id string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(e.api(200, "GET", base+"/"+id, nil), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	body := func(on bool) map[string]any {
		m := map[string]any{"clientId": "cli", "enabled": true, "publicClient": true}
		if on {
			m["deviceFlowEnabled"] = true
		}
		return m
	}
	id := e.createID(base, body(true))
	if got := get(id)["deviceFlowEnabled"]; got != true {
		t.Fatalf("get after create: %v", got)
	}
	var list []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", base+"?clientId=cli", nil), &list)
	if len(list) != 1 || list[0]["deviceFlowEnabled"] != true {
		t.Fatalf("list: %v", list)
	}
	// Client PUT is a full replace: omitting the key switches the flow off.
	e.api(204, "PUT", base+"/"+id, body(false))
	if _, has := get(id)["deviceFlowEnabled"]; has {
		t.Fatal("omitted key must clear the flag")
	}
	e.api(204, "PUT", base+"/"+id, body(true))
	if get(id)["deviceFlowEnabled"] != true {
		t.Fatal("update did not set the flag")
	}
	// A service account has no user to approve a device.
	bad := map[string]any{"clientId": "svc", "enabled": true, "serviceAccountsEnabled": true, "deviceFlowEnabled": true}
	if code, out, _ := e.call("POST", base, e.token, bad); code != 400 || !strings.Contains(string(out), "deviceFlowEnabled") {
		t.Fatalf("service account + device flow: %d %s", code, out)
	}
}
