// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

const importPath = "/realms/" + realm + "/users/import"

func (e *env) importUsers(want int, users ...map[string]any) idp.ImportResult {
	e.t.Helper()
	b := e.api(want, "POST", importPath, map[string]any{"users": users})
	var res idp.ImportResult
	if want == 200 {
		if err := json.Unmarshal(b, &res); err != nil {
			e.t.Fatal(err)
		}
	}
	return res
}

func (e *env) hash(pw string) string {
	e.t.Helper()
	h, err := e.hasher.Hash(pw)
	if err != nil {
		e.t.Fatal(err)
	}
	return h
}

func TestImportHappyPathAndSkip(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm
	e.createID(r+"/roles", map[string]any{"name": "editor"})
	e.createID(r+"/groups", map[string]any{"name": "staff"})
	h := e.hash("imported-pass-123")

	res := e.importUsers(200,
		map[string]any{"username": "ann", "email": "ann@example.com", "enabled": true, "emailVerified": true,
			"passwordHash": h, "roles": []string{"editor"}, "groups": []string{"/staff"},
			"requiredActions": []string{"UPDATE_PASSWORD", "TERMS_AND_CONDITIONS", "VERIFY_EMAIL"}},
		map[string]any{"username": "ben", "enabled": true},
	)
	if res.Created != 2 || res.Skipped != 0 || len(res.Errors) != 0 {
		t.Fatalf("result: %+v", res)
	}
	u, err := e.st.GetUserByUsername(t.Context(), realm, "ann")
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash != h || len(u.Roles) != 1 || u.Roles[0] != "editor" || len(u.Groups) != 1 || u.Groups[0] != "/staff" ||
		u.CreatedAt.IsZero() || !u.EmailVerified || len(u.PendingActions) != 2 {
		t.Fatalf("stored user: %+v", u)
	}
	var list []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", r+"/users?search=ann", nil), &list)
	if len(list) != 1 || list[0]["username"] != "ann" {
		t.Fatalf("list: %v", list)
	}

	// Existing users are skipped and never modified, password included.
	res = e.importUsers(200, map[string]any{"username": "ANN", "enabled": false, "email": "x@y.z",
		"passwordHash": e.hash("attacker-pass-999")})
	if res.Created != 0 || res.Skipped != 1 {
		t.Fatalf("skip: %+v", res)
	}
	u2, _ := e.st.GetUserByUsername(t.Context(), realm, "ann")
	if u2.PasswordHash != h || !u2.Enabled || u2.Email != "ann@example.com" {
		t.Fatalf("existing user modified: %+v", u2)
	}
}

func TestImportPerUserErrors(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm
	e.createID(r+"/roles", map[string]any{"name": "editor"})
	res := e.importUsers(200,
		map[string]any{"username": "dup", "enabled": true},
		map[string]any{"username": "DUP", "enabled": true},
		map[string]any{"username": "badrole", "roles": []string{"nope"}},
		map[string]any{"username": "badgroup", "groups": []string{"/nope"}},
		map[string]any{"username": "badhash", "passwordHash": "plaintext-secret-value"},
		map[string]any{"username": " "},
		map[string]any{"username": "good", "enabled": true},
	)
	if res.Created != 2 || res.Skipped != 0 || len(res.Errors) != 5 {
		t.Fatalf("result: %+v", res)
	}
	want := map[string]string{"DUP": "duplicate in request", "badrole": "unknown role", "badgroup": "unknown group",
		"badhash": "invalid passwordHash", " ": "invalid username"}
	for _, er := range res.Errors {
		if want[er.Username] != er.Reason {
			t.Errorf("error %+v", er)
		}
	}
	for _, n := range []string{"badrole", "badgroup", "badhash"} {
		if _, err := e.st.GetUserByUsername(t.Context(), realm, n); err == nil {
			t.Errorf("%s was created", n)
		}
	}
	// Errors are capped at 100.
	var many []map[string]any
	for i := 0; i < 150; i++ {
		many = append(many, map[string]any{"username": "u" + strconv.Itoa(i), "roles": []string{"nope"}})
	}
	if res := e.importUsers(200, many...); len(res.Errors) != 100 || res.Created != 0 {
		t.Fatalf("cap: %d %+v", len(res.Errors), res.Created)
	}
}

func TestImportRejections(t *testing.T) {
	e := newEnv(t)
	// A plaintext password field is an unknown field.
	e.api(400, "POST", importPath, `{"users":[{"username":"x","password":"hunter2hunter2"}]}`)
	e.api(400, "POST", importPath, `{"users":[],"extra":1}`)
	e.api(400, "POST", importPath, `not json`)
	e.api(404, "POST", "/realms/ghost/users/import", `{"users":[]}`)
	// Too many users.
	many := make([]map[string]any, 1001)
	for i := range many {
		many[i] = map[string]any{"username": "u" + strconv.Itoa(i)}
	}
	e.importUsers(413, many...)
	if us, _ := e.st.ListUsers(t.Context(), realm, "u1", 0, 10); len(us) != 0 {
		t.Fatal("users created by a rejected request")
	}
	// Oversize body (> 8 MiB).
	big := `{"users":[{"username":"x","firstName":"` + strings.Repeat("a", 9<<20) + `"}]}`
	e.api(413, "POST", importPath, big)
	// A body between 1 and 8 MiB is accepted (users with 1000-char names are
	// fine individually, this checks the raised limit).
	pad := strings.Repeat("a", 200)
	var fat []map[string]any
	for i := 0; i < 1000; i++ {
		fat = append(fat, map[string]any{"username": "fat" + strconv.Itoa(i), "firstName": pad, "lastName": pad, "email": pad})
	}
	if res := e.importUsers(200, fat...); res.Created != 1000 {
		t.Fatalf("fat: %+v", res)
	}
}

func TestImportAuthRequired(t *testing.T) {
	e := newEnv(t)
	body := `{"users":[{"username":"x"}]}`
	if c, _, _ := e.call("POST", importPath, "", body); c != 401 {
		t.Errorf("no token: %d", c)
	}
	if c, _, _ := e.call("POST", importPath, "garbage", body); c != 401 {
		t.Errorf("bad token: %d", c)
	}
	e.createID("/realms/"+realm+"/clients", map[string]any{"clientId": "rogue", "enabled": true, "serviceAccountsEnabled": true})
	cs, _ := e.st.ListClients(t.Context(), realm)
	for _, c := range cs {
		if c.ClientID == "rogue" {
			var out struct{ Value string }
			_ = json.Unmarshal(e.api(200, "POST", "/realms/"+realm+"/clients/"+c.ID+"/secret", nil), &out)
			if code, _, _ := e.call("POST", importPath, e.clientToken(realm, "rogue", out.Value), body); code != 403 {
				t.Errorf("non-admin: %d", code)
			}
		}
	}
	if _, err := e.st.GetUserByUsername(t.Context(), realm, "x"); err == nil {
		t.Fatal("unauthorized import created a user")
	}
}

func TestImportEventAndNoHashLeak(t *testing.T) {
	e, rec := newObsEnv(t)
	h := e.hash("imported-pass-123")
	hashPart := h[len(h)-20:]
	b := e.api(200, "POST", importPath, map[string]any{"users": []map[string]any{
		{"username": "secretname1", "passwordHash": h, "enabled": true},
		{"username": "secretname2", "passwordHash": h, "roles": []string{"nope"}},
		{"username": "secretname1"},
	}})
	if bytes.Contains(b, []byte(hashPart)) || bytes.Contains(b, []byte("argon2")) {
		t.Fatalf("response leaks hash: %s", b)
	}
	ev := e.api(200, "GET", "/realms/"+realm+"/events?max=5", nil)
	if bytes.Contains(ev, []byte(hashPart)) || bytes.Contains(ev, []byte("secretname")) {
		t.Fatalf("event leaks data: %s", ev)
	}
	evs, err := e.st.ListEvents(t.Context(), realm, 5)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range evs {
		if x.Type == "ADMIN_IMPORT" {
			found = true
			if x.Detail != "users: created=1 skipped=0 failed=2" {
				t.Errorf("detail: %q", x.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("no ADMIN_IMPORT event: %+v", evs)
	}
	rec.expect(t, "adminop:"+realm+":user:action:ok")
	// A rejected request reports ok=false.
	e.api(400, "POST", importPath, `{"bogus":1}`)
	rec.expect(t, "adminop:"+realm+":user:action:err")
}

// pbkdf2Hash builds a `$pbkdf2-sha256$` hash as in the kcimport contract.
func pbkdf2Hash(t *testing.T, pw string) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	dk, err := pbkdf2.Key(sha256.New, pw, salt, 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawStdEncoding
	return "$pbkdf2-sha256$i=1000$" + enc.EncodeToString(salt) + "$" + enc.EncodeToString(dk)
}

func TestImportLegacyHashLogin(t *testing.T) {
	e := newEnv(t)
	e.createID("/realms/"+realm+"/clients", map[string]any{
		"clientId": "app", "enabled": true, "publicClient": true, "standardFlowEnabled": true,
		"redirectUris": []string{"http://localhost/cb"}})
	e.importUsers(200, map[string]any{"username": "legacy", "enabled": true, "passwordHash": pbkdf2Hash(t, goodPW)})
	var list []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", "/realms/"+realm+"/users?search=legacy", nil), &list)
	if len(list) != 1 {
		t.Fatalf("list: %v", list)
	}
	if tok := e.login("app", "legacy", goodPW); tok == "" {
		t.Fatal("legacy login failed")
	}
}
