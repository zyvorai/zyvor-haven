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

func TestAdminPasskeys(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rl, _ := e.st.GetRealm(ctx, realm)
	rl.AdminEventsLogged = true
	if err := e.st.UpdateRealm(ctx, rl); err != nil {
		t.Fatal(err)
	}
	uid := e.mkUser("alice")
	other := e.mkUser("bob")
	used := time.Now().UTC().Truncate(time.Microsecond)
	for _, p := range []core.Passkey{
		{Realm: realm, UserID: uid, CredentialID: "cred-a", PublicKey: []byte("SECRET-KEY-BYTES"), Name: "Laptop", BackupEligible: true, Transports: []string{"internal"}, LastUsedAt: used, SignCount: 3},
		{Realm: realm, UserID: other, CredentialID: "cred-b", PublicKey: []byte{1}, Name: "Bob's"},
	} {
		if err := e.st.AddPasskey(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	base := "/realms/" + realm + "/users/" + uid + "/passkeys"

	raw := e.api(200, "GET", base, nil)
	if strings.Contains(string(raw), "SECRET-KEY") || strings.Contains(strings.ToLower(string(raw)), "publickey") {
		t.Fatalf("public key material in the response: %s", raw)
	}
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil || len(list) != 1 || list[0]["id"] != "cred-a" || list[0]["name"] != "Laptop" || list[0]["lastUsedAt"] == nil {
		t.Fatalf("list: %s", raw)
	}
	// A user without passkeys: empty array, not null.
	if got := strings.TrimSpace(string(e.api(200, "GET", "/realms/"+realm+"/users/"+e.mkUser("carol")+"/passkeys", nil))); got != "[]" {
		t.Errorf("empty list: %s", got)
	}
	e.api(404, "GET", "/realms/"+realm+"/users/nope/passkeys", nil)

	// Another user's credential is not reachable through this user's path.
	e.api(404, "DELETE", base+"/cred-b", nil)
	if _, err := e.st.GetPasskey(ctx, realm, "cred-b"); err != nil {
		t.Fatal("deleted through another user")
	}
	e.api(404, "DELETE", base+"/nope", nil)
	e.api(204, "DELETE", base+"/cred-a", nil)
	if _, err := e.st.GetPasskey(ctx, realm, "cred-a"); err == nil {
		t.Fatal("not deleted")
	}
	evs, _ := e.st.ListEvents(ctx, realm, 50)
	var audited bool
	for _, ev := range evs {
		if ev.Type == "ADMIN_DELETE" && strings.HasPrefix(ev.Detail, "passkey ") {
			audited = true
			if strings.Contains(ev.Detail, "cred-a") {
				t.Error("credential id in audit detail")
			}
		}
	}
	if !audited {
		t.Error("deletion not audited")
	}

	// Authentication is required.
	if code, _, _ := e.call("GET", base, "", nil); code != 401 {
		t.Errorf("unauthenticated list: %d", code)
	}
	if code, _, _ := e.call("DELETE", base+"/cred-b", "", nil); code != 401 {
		t.Errorf("unauthenticated delete: %d", code)
	}
}

func TestAdminPasskeyPolicy(t *testing.T) {
	e := newEnv(t)
	p := "/realms/" + realm + "/passkey-policy"
	if got := string(e.api(200, "GET", p, nil)); !strings.Contains(got, `"requirePasskeys":false`) {
		t.Fatalf("default: %s", got)
	}
	e.api(200, "PUT", p, map[string]any{"requirePasskeys": true})
	if got := string(e.api(200, "GET", p, nil)); !strings.Contains(got, `"requirePasskeys":true`) {
		t.Fatalf("after put: %s", got)
	}
	e.api(400, "PUT", p, map[string]any{"requirePasskeys": true, "extra": 1})
	e.api(404, "GET", "/realms/nope/passkey-policy", nil)
}
