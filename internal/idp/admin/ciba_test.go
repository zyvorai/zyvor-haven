// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
)

func TestClientCIBAOptIn(t *testing.T) {
	e := newEnv(t)
	base := "/realms/" + realm + "/clients"
	conf := e.createID(base, map[string]any{"clientId": "agent", "enabled": true})
	pub := e.createID(base, map[string]any{"clientId": "spa", "enabled": true, "publicClient": true})
	get := func(id string) bool {
		var m map[string]any
		if err := json.Unmarshal(e.api(200, "GET", base+"/"+id+"/ciba", nil), &m); err != nil {
			t.Fatal(err)
		}
		return m["enabled"] == true
	}
	if get(conf) {
		t.Fatal("CIBA must be off by default")
	}
	e.api(200, "PUT", base+"/"+conf+"/ciba", map[string]any{"enabled": true})
	if !get(conf) {
		t.Fatal("not enabled after PUT")
	}
	cs, _ := core.StoreAs[core.CIBAStore](e.st)
	if on, _ := cs.CIBAClientEnabled(context.Background(), realm, conf); !on {
		t.Fatal("store does not see the opt-in")
	}
	// A public client cannot be switched on; switching off is always allowed.
	e.api(400, "PUT", base+"/"+pub+"/ciba", map[string]any{"enabled": true})
	e.api(200, "PUT", base+"/"+pub+"/ciba", map[string]any{"enabled": false})
	e.api(400, "PUT", base+"/"+conf+"/ciba", map[string]any{"enabled": true, "bogus": 1})
	e.api(404, "PUT", base+"/nope/ciba", map[string]any{"enabled": true})
	e.api(404, "GET", base+"/nope/ciba", nil)
	e.api(200, "PUT", base+"/"+conf+"/ciba", map[string]any{"enabled": false})
	if get(conf) {
		t.Fatal("still enabled after switching off")
	}
	// No token, no write.
	if code, _, _ := e.call("PUT", base+"/"+conf+"/ciba", "", map[string]any{"enabled": true}); code != 401 {
		t.Errorf("unauthenticated PUT: %d", code)
	}
}
