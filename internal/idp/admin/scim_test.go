// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

const (
	scimRealm = "corp"
	patchOp   = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	userURN   = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupURN  = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

type scimEnv struct {
	*env
	tok string // SCIM token of scimRealm
}

// newSCIMEnv is newEnv plus the SCIM handler, a realm "corp" and its token.
func newSCIMEnv(t *testing.T) *scimEnv {
	t.Helper()
	st := memstore.New()
	h := password.New(password.TestParams)
	sg := keys.New(st, keys.Options{})
	e := &env{t: t, st: st, signer: sg, hasher: h}
	var handler http.Handler
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(e.srv.Close)
	if _, err := bootstrap.Run(context.Background(), st, h, sg, bootstrap.Options{Realm: realm, AdminClientSecret: adminSecret}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL}))
	acfg := admin.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL, AdminRealm: realm}
	mux.Handle("/admin/v1/", admin.New(acfg))
	mux.Handle("/realms/{r}/scim/v2/", admin.SCIM(acfg))
	handler = mux
	e.token = e.clientToken(realm, "haven-admin", adminSecret)

	e.createID("/realms", map[string]any{"realm": scimRealm, "enabled": true})
	rl, err := st.GetRealm(context.Background(), scimRealm)
	if err != nil {
		t.Fatal(err)
	}
	rl.AdminEventsLogged = true
	if err := st.UpdateRealm(context.Background(), rl); err != nil {
		t.Fatal(err)
	}
	se := &scimEnv{env: e}
	se.tok = se.issue(scimRealm, false)
	return se
}

// issue creates or rotates a realm's SCIM token through the Admin API.
func (e *scimEnv) issue(rlm string, readOnly bool) string {
	e.t.Helper()
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(e.api(201, "POST", "/realms/"+rlm+"/scim/token", map[string]any{"readOnly": readOnly}), &out); err != nil || out.Token == "" {
		e.t.Fatal("no token issued")
	}
	return out.Token
}

// scim sends a request to /realms/corp/scim/v2 with the given bearer token.
func (e *scimEnv) scimAs(tok, method, path string, body any, hdr ...string) (int, map[string]any, http.Header) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/realms/"+scimRealm+"/scim/v2"+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/scim+json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp.Header
}

func (e *scimEnv) scim(want int, method, path string, body any, hdr ...string) (map[string]any, http.Header) {
	e.t.Helper()
	code, m, h := e.scimAs(e.tok, method, path, body, hdr...)
	if code != want {
		e.t.Fatalf("%s %s: got %d want %d: %v", method, path, code, want, m)
	}
	return m, h
}

func (e *scimEnv) mkUser(name string, extra map[string]any) map[string]any {
	e.t.Helper()
	b := map[string]any{"schemas": []string{userURN}, "userName": name,
		"name":   map[string]any{"givenName": "G" + name, "familyName": "F" + name},
		"emails": []map[string]any{{"value": name + "@example.com", "primary": true}}}
	for k, v := range extra {
		b[k] = v
	}
	m, _ := e.scim(201, "POST", "/Users", b)
	return m
}

func patch(ops ...map[string]any) map[string]any {
	return map[string]any{"schemas": []string{patchOp}, "Operations": ops}
}

func scimNames(m map[string]any) []string {
	var out []string
	for _, r := range m["Resources"].([]any) {
		out = append(out, r.(map[string]any)["userName"].(string))
	}
	return out
}

func TestSCIMTokenLifecycle(t *testing.T) {
	e := newSCIMEnv(t)
	base := "/realms/" + scimRealm + "/scim/token"

	var st map[string]any
	_ = json.Unmarshal(e.api(200, "GET", base, nil), &st)
	if st["configured"] != true || st["readOnly"] != false || st["token"] != nil {
		t.Fatalf("status: %v", st)
	}

	// Only the hash is stored.
	got, err := e.st.GetSCIMToken(context.Background(), scimRealm)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(e.tok))
	if got.TokenHash != hex.EncodeToString(sum[:]) || strings.Contains(got.TokenHash, e.tok) {
		t.Fatalf("stored token is not the sha256 of the issued one: %q", got.TokenHash)
	}
	if !strings.HasPrefix(e.tok, "scim_") {
		t.Fatalf("token has no scim_ prefix")
	}

	e.scim(200, "GET", "/Users", nil)

	// Rotation: the old token dies at once.
	old := e.tok
	e.tok = e.issue(scimRealm, false)
	if e.tok == old {
		t.Fatal("rotation returned the same token")
	}
	if code, _, _ := e.scimAs(old, "GET", "/Users", nil); code != 401 {
		t.Fatalf("rotated-out token: %d", code)
	}
	e.scim(200, "GET", "/Users", nil)

	// The token never reaches the audit trail.
	evs, _ := e.st.ListEvents(context.Background(), scimRealm, 100)
	found := false
	for _, ev := range evs {
		if strings.Contains(ev.Detail, e.tok) || strings.Contains(ev.Detail, old) {
			t.Fatalf("token in audit detail: %q", ev.Detail)
		}
		if ev.Detail == "scim-token issued" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit event for token issue: %v", evs)
	}

	// Revocation.
	e.api(204, "DELETE", base, nil)
	if code, _, _ := e.scimAs(e.tok, "GET", "/Users", nil); code != 401 {
		t.Fatalf("revoked token: %d", code)
	}
	e.api(404, "DELETE", base, nil)
	_ = json.Unmarshal(e.api(200, "GET", base, nil), &st)
	if st["configured"] != false {
		t.Fatalf("status after revoke: %v", st)
	}
	// Admin API access is needed to manage the token.
	if code, _, _ := e.call("POST", base, "", nil); code != 401 {
		t.Fatalf("token issue without admin token: %d", code)
	}
}

func TestSCIMAuthNegative(t *testing.T) {
	e := newSCIMEnv(t)
	other := e.createID("/realms", map[string]any{"realm": "other", "enabled": true})
	_ = other
	otherTok := e.issue("other", false)

	var bodies []string
	try := func(name, tok string) {
		t.Helper()
		code, m, h := e.scimAs(tok, "GET", "/Users", nil)
		if code != 401 || h.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: got %d", name, code)
		}
		b, _ := json.Marshal(m)
		bodies = append(bodies, string(b))
	}
	try("no token", "")
	try("garbage", "scim_nope")
	try("admin API token", e.token)
	try("other realm's token", otherTok)
	try("hash of the token", func() string { s := sha256.Sum256([]byte(e.tok)); return hex.EncodeToString(s[:]) }())
	try("token plus suffix", e.tok+"x")
	try("huge token", strings.Repeat("a", 600))
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Errorf("auth failures differ: %s vs %s", b, bodies[0])
		}
	}

	// Unknown realm and a realm without a token look the same as a wrong token.
	for _, rlm := range []string{"nonexistent", "other2", "../x"} {
		req, _ := http.NewRequest("GET", e.srv.URL+"/realms/"+rlm+"/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer "+e.tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 401 && resp.StatusCode != 404 && resp.StatusCode != 301 {
			t.Errorf("realm %q: %d", rlm, resp.StatusCode)
		}
		if resp.StatusCode == 404 || resp.StatusCode == 301 {
			continue
		}
	}
	e.createID("/realms", map[string]any{"realm": "other2", "enabled": true})
	req, _ := http.NewRequest("GET", e.srv.URL+"/realms/other2/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer "+e.tok)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Errorf("realm without token: %d", resp.StatusCode)
	}

	// A disabled realm refuses its own token.
	rl, _ := e.st.GetRealm(context.Background(), scimRealm)
	rl.Enabled = false
	_ = e.st.UpdateRealm(context.Background(), rl)
	if code, _, _ := e.scimAs(e.tok, "GET", "/Users", nil); code != 401 {
		t.Errorf("disabled realm: %d", code)
	}
	rl.Enabled = true
	_ = e.st.UpdateRealm(context.Background(), rl)
	e.scim(200, "GET", "/Users", nil)

	// A token issued for an earlier incarnation of the realm is dead.
	good, _ := e.st.GetSCIMToken(context.Background(), scimRealm)
	good.RealmID = "some-other-incarnation"
	_ = e.st.PutSCIMToken(context.Background(), good)
	if code, _, _ := e.scimAs(e.tok, "GET", "/Users", nil); code != 401 {
		t.Errorf("token of another realm incarnation: %d", code)
	}
}

func TestSCIMReadOnlyToken(t *testing.T) {
	e := newSCIMEnv(t)
	e.mkUser("alice", nil)
	e.tok = e.issue(scimRealm, true)
	e.scim(200, "GET", "/Users", nil)
	e.scim(200, "GET", "/ServiceProviderConfig", nil)
	e.scim(403, "POST", "/Users", map[string]any{"userName": "bob"})
	m, _ := e.scim(200, "GET", `/Users?filter=userName%20eq%20%22alice%22`, nil)
	id := m["Resources"].([]any)[0].(map[string]any)["id"].(string)
	e.scim(403, "PATCH", "/Users/"+id, patch(map[string]any{"op": "replace", "path": "active", "value": false}))
	e.scim(403, "PUT", "/Users/"+id, map[string]any{"userName": "alice"})
	e.scim(403, "DELETE", "/Users/"+id, nil)
	e.scim(403, "POST", "/Groups", map[string]any{"displayName": "g"})
	e.scim(200, "GET", "/Users/"+id, nil)
}

func TestSCIMRateLimit(t *testing.T) {
	e := newSCIMEnv(t)
	defer admin.SetSCIMLimits(5, 3)()
	for i := 0; i < 5; i++ {
		e.scim(200, "GET", "/ServiceProviderConfig", nil)
	}
	code, _, h := e.scimAs(e.tok, "GET", "/ServiceProviderConfig", nil)
	if code != 429 || h.Get("Retry-After") == "" {
		t.Fatalf("request limit: %d", code)
	}
}

func TestSCIMFailedAuthRateLimit(t *testing.T) {
	e := newSCIMEnv(t)
	defer admin.SetSCIMLimits(1000, 3)()
	var codes []int
	for i := 0; i < 5; i++ {
		c, _, _ := e.scimAs("scim_wrong", "GET", "/Users", nil)
		codes = append(codes, c)
	}
	if codes[0] != 401 || codes[1] != 401 || codes[2] != 401 || codes[4] != 429 {
		t.Fatalf("codes %v", codes)
	}
}

func TestSCIMDiscovery(t *testing.T) {
	e := newSCIMEnv(t)
	m, h := e.scim(200, "GET", "/ServiceProviderConfig", nil)
	if h.Get("Content-Type") != "application/scim+json" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", h)
	}
	if m["bulk"].(map[string]any)["supported"] != false || m["patch"].(map[string]any)["supported"] != true ||
		m["etag"].(map[string]any)["supported"] != true || m["changePassword"].(map[string]any)["supported"] != false ||
		m["filter"].(map[string]any)["maxResults"] != float64(100) {
		t.Fatalf("service provider config: %v", m)
	}
	rt, _ := e.scim(200, "GET", "/ResourceTypes", nil)
	if rt["totalResults"] != float64(2) {
		t.Fatalf("resource types: %v", rt)
	}
	e.scim(200, "GET", "/ResourceTypes/User", nil)
	e.scim(404, "GET", "/ResourceTypes/Nope", nil)
	sc, _ := e.scim(200, "GET", "/Schemas", nil)
	if sc["totalResults"] != float64(2) {
		t.Fatalf("schemas: %v", sc)
	}
	e.scim(200, "GET", "/Schemas/"+userURN, nil)
	// Bulk is explicitly not supported.
	m, _ = e.scim(501, "POST", "/Bulk", map[string]any{})
	if !strings.Contains(m["detail"].(string), "bulk") {
		t.Fatalf("bulk: %v", m)
	}
	// Discovery needs the token as well.
	if code, _, _ := e.scimAs("", "GET", "/ServiceProviderConfig", nil); code != 401 {
		t.Fatalf("discovery without token: %d", code)
	}
	e.scim(404, "GET", "/Nope", nil)
}

func TestSCIMUserLifecycle(t *testing.T) {
	e := newSCIMEnv(t)
	ctx := context.Background()
	created, h := e.scim(201, "POST", "/Users", map[string]any{
		"schemas": []string{userURN}, "userName": "Alice", "externalId": "ext-a",
		"name":   map[string]any{"givenName": "Alice", "familyName": "Smith"},
		"emails": []map[string]any{{"value": "work@example.com", "type": "work"}, {"value": "alice@example.com", "primary": true}},
		"active": true, "displayName": "ignored", "locale": "en", "groups": []any{map[string]any{"value": "x"}},
	})
	id := created["id"].(string)
	if h.Get("Location") == "" || h.Get("ETag") == "" || created["meta"].(map[string]any)["version"] != h.Get("ETag") {
		t.Fatalf("headers %v / %v", h, created["meta"])
	}
	if created["externalId"] != "ext-a" || created["active"] != true || created["displayName"] != "Alice Smith" {
		t.Fatalf("resource: %v", created)
	}
	em := created["emails"].([]any)[0].(map[string]any)
	if em["value"] != "alice@example.com" || em["primary"] != true {
		t.Fatalf("emails: %v", created["emails"])
	}
	for _, k := range []string{"password", "roles"} {
		if _, has := created[k]; has {
			t.Fatalf("%s in resource", k)
		}
	}
	// Stored through the Admin-layer rules: no password, not email-verified.
	u, _ := e.st.GetUser(ctx, scimRealm, id)
	if u.PasswordHash != "" || u.EmailVerified || !u.Enabled || u.Username != "Alice" {
		t.Fatalf("stored user: %+v", u)
	}
	// ...and the Admin API sees the same user.
	var adm map[string]any
	_ = json.Unmarshal(e.api(200, "GET", "/realms/"+scimRealm+"/users/"+id, nil), &adm)
	if adm["username"] != "Alice" {
		t.Fatalf("admin view: %v", adm)
	}

	// Duplicates: userName (any case) and externalId.
	if m, _ := e.scim(409, "POST", "/Users", map[string]any{"userName": "alice"}); m["scimType"] != "uniqueness" {
		t.Fatalf("dup username: %v", m)
	}
	e.scim(409, "POST", "/Users", map[string]any{"userName": "other", "externalId": "ext-a"})
	e.scim(400, "POST", "/Users", map[string]any{"externalId": "x"})
	e.scim(400, "POST", "/Users", "not json")
	e.scim(400, "POST", "/Users", "[1]")
	e.scim(400, "POST", "/Users", map[string]any{"userName": "bad", "emails": []map[string]any{{"value": "no-at-sign"}}})
	e.scim(400, "POST", "/Users", map[string]any{"userName": "ctl\x01"})

	got, gh := e.scim(200, "GET", "/Users/"+id, nil)
	if got["userName"] != "Alice" || gh.Get("ETag") != h.Get("ETag") {
		t.Fatalf("get: %v", got)
	}
	e.scim(304, "GET", "/Users/"+id, nil, "If-None-Match", h.Get("ETag"))
	e.scim(404, "GET", "/Users/does-not-exist", nil)

	// PUT replaces; omitted attributes are cleared; a changed address is unverified.
	u.EmailVerified = true
	_ = e.st.UpdateUser(ctx, u)
	cur, ch := e.scim(200, "GET", "/Users/"+id, nil)
	put, ph := e.scim(200, "PUT", "/Users/"+id, map[string]any{"userName": "alice2", "name": map[string]any{"givenName": "Al"},
		"emails": []map[string]any{{"value": "alice@example.com"}}, "active": true}, "If-Match", ch.Get("ETag"))
	_ = cur
	if put["userName"] != "alice2" || put["name"].(map[string]any)["familyName"] != "" {
		t.Fatalf("put: %v", put)
	}
	if _, has := put["externalId"]; has {
		t.Fatalf("PUT without externalId must clear it: %v", put)
	}
	if ph.Get("ETag") == ch.Get("ETag") {
		t.Fatal("ETag did not change")
	}
	u, _ = e.st.GetUser(ctx, scimRealm, id)
	if !u.EmailVerified {
		t.Fatal("unchanged address lost its verified flag")
	}
	e.scim(200, "PUT", "/Users/"+id, map[string]any{"userName": "alice2", "emails": []map[string]any{{"value": "new@example.com"}}})
	u, _ = e.st.GetUser(ctx, scimRealm, id)
	if u.EmailVerified || u.Email != "new@example.com" {
		t.Fatalf("changed address must be unverified: %+v", u)
	}

	// DELETE.
	e.scim(204, "DELETE", "/Users/"+id, nil)
	e.scim(404, "GET", "/Users/"+id, nil)
	e.scim(404, "DELETE", "/Users/"+id, nil)
	if _, err := e.st.GetUser(ctx, scimRealm, id); err == nil {
		t.Fatal("user still stored")
	}

	// Audit trail: actor is the SCIM token, not an admin.
	evs, _ := e.st.ListEvents(ctx, scimRealm, 100)
	var types []string
	for _, ev := range evs {
		if strings.HasPrefix(ev.Detail, "user ") {
			if ev.UserID != "scim:"+scimRealm {
				t.Errorf("event actor %q", ev.UserID)
			}
			types = append(types, ev.Type)
		}
	}
	for _, want := range []string{"ADMIN_CREATE", "ADMIN_UPDATE", "ADMIN_DELETE"} {
		if !strings.Contains(strings.Join(types, " "), want) {
			t.Errorf("no %s event in %v", want, types)
		}
	}
}

func TestSCIMUserPatch(t *testing.T) {
	e := newSCIMEnv(t)
	ctx := context.Background()
	u := e.mkUser("pat", map[string]any{"externalId": "e1"})
	id := u["id"].(string)
	etag := u["meta"].(map[string]any)["version"].(string)

	// Sessions of a deactivated user end.
	if err := e.st.PutSession(ctx, core.Session{ID: "s1", CookieHash: "c1", Realm: scimRealm, UserID: id, ExpiresAt: time.Now().Add(time.Hour), IdleExpires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, _ := e.scim(200, "PATCH", "/Users/"+id, patch(
		map[string]any{"op": "Replace", "path": "active", "value": "False"},
		map[string]any{"op": "replace", "path": "name.givenName", "value": "Pat"},
		map[string]any{"op": "add", "path": `emails[type eq "work"].value`, "value": "p@example.com"},
		map[string]any{"op": "remove", "path": "externalId"},
		map[string]any{"op": "replace", "value": map[string]any{"name.familyName": "Ator"}},
	), "If-Match", etag)
	if got["active"] != false || got["name"].(map[string]any)["givenName"] != "Pat" || got["name"].(map[string]any)["familyName"] != "Ator" ||
		got["emails"].([]any)[0].(map[string]any)["value"] != "p@example.com" {
		t.Fatalf("patch result: %v", got)
	}
	if _, has := got["externalId"]; has {
		t.Fatal("externalId not removed")
	}
	if _, err := e.st.GetSession(ctx, scimRealm, "s1"); err == nil {
		t.Fatal("session of deactivated user still alive")
	}
	if usr, _ := e.st.GetUser(ctx, scimRealm, id); usr.Enabled {
		t.Fatal("user still enabled")
	}
	// Stale If-Match.
	m, _ := e.scim(412, "PATCH", "/Users/"+id, patch(map[string]any{"op": "replace", "path": "active", "value": true}), "If-Match", etag)
	if m["status"] != "412" {
		t.Fatalf("412 body: %v", m)
	}
	e.scim(412, "DELETE", "/Users/"+id, nil, "If-Match", etag)
	e.scim(200, "PATCH", "/Users/"+id, patch(map[string]any{"op": "replace", "path": "active", "value": true}), "If-Match", "*")

	// Rejections.
	for name, op := range map[string]map[string]any{
		"password":        {"op": "replace", "path": "password", "value": "x"},
		"roles":           {"op": "add", "path": "roles", "value": []any{map[string]any{"value": "haven-admin"}}},
		"groups":          {"op": "add", "path": "groups", "value": []any{}},
		"remove userName": {"op": "remove", "path": "userName"},
		"unknown":         {"op": "replace", "path": "foo", "value": "x"},
		"bad op":          {"op": "move", "path": "active", "value": true},
		"bad active":      {"op": "replace", "path": "active", "value": "maybe"},
		"no path remove":  {"op": "remove"},
		"pw in object":    {"op": "replace", "value": map[string]any{"password": "x"}},
		"missing value":   {"op": "replace", "path": "userName"},
		"reserved name":   {"op": "replace", "path": "userName", "value": "service-account-x"},
	} {
		if code, _, _ := e.scimAs(e.tok, "PATCH", "/Users/"+id, patch(op)); code != 400 {
			t.Errorf("%s: got %d, want 400", name, code)
		}
	}
	e.scim(400, "PATCH", "/Users/"+id, map[string]any{"Operations": []any{}})
	e.scim(400, "PATCH", "/Users/"+id, map[string]any{"schemas": []string{patchOp}, "Operations": []any{}})
	many := make([]map[string]any, 101)
	for i := range many {
		many[i] = map[string]any{"op": "replace", "path": "active", "value": true}
	}
	e.scim(400, "PATCH", "/Users/"+id, patch(many...))
	// A failed PATCH changes nothing.
	usr, _ := e.st.GetUser(ctx, scimRealm, id)
	if usr.Username != "pat" || !usr.Enabled {
		t.Fatalf("failed patch altered the user: %+v", usr)
	}
}

func urlEscape(s string) string { return url.QueryEscape(s) }

// plainStore hides the optional store extensions.
type plainStore struct{ core.Store }

func TestSCIMPasswordNotSynced(t *testing.T) {
	e := newSCIMEnv(t)
	m, _ := e.scim(400, "POST", "/Users", map[string]any{"userName": "pw", "password": "hunter2hunter2"})
	if m["scimType"] != "mutability" || strings.Contains(fmt.Sprint(m), "hunter2") {
		t.Fatalf("password create: %v", m)
	}
	if _, err := e.st.GetUserByUsername(context.Background(), scimRealm, "pw"); err == nil {
		t.Fatal("user was created despite the rejected request")
	}
	u := e.mkUser("pw2", nil)
	e.scim(400, "PUT", "/Users/"+u["id"].(string), map[string]any{"userName": "pw2", "password": "x"})
}

func TestSCIMFilterAndPaging(t *testing.T) {
	e := newSCIMEnv(t)
	for _, n := range []string{"anna", "annabel", "bob", "carl", "dora"} {
		extra := map[string]any{"externalId": "x-" + n}
		if n == "dora" {
			extra["active"] = false
		}
		e.mkUser(n, extra)
	}
	q := func(f string) []string {
		t.Helper()
		m, _ := e.scim(200, "GET", "/Users?filter="+strings.ReplaceAll(strings.ReplaceAll(f, " ", "%20"), `"`, "%22"), nil)
		return scimNames(m)
	}
	eqs := func(name string, got []string, want ...string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: got %v want %v", name, got, want)
		}
	}
	eqs("eq", q(`userName eq "BOB"`), "bob")
	eqs("sw", q(`userName sw "ann"`), "anna", "annabel")
	eqs("co", q(`userName co "ar"`), "carl")
	eqs("and", q(`userName sw "ann" and userName ew "bel"`), "annabel")
	eqs("or", q(`userName eq "bob" or userName eq "carl"`), "bob", "carl")
	eqs("active false", q(`active eq false`), "dora")
	eqs("externalId", q(`externalId eq "x-carl"`), "carl")
	eqs("externalId or", q(`externalId eq "x-carl" or externalId eq "x-bob"`), "bob", "carl")
	eqs("email", q(`emails.value eq "dora@example.com"`), "dora")
	eqs("none", q(`userName eq "nobody"`))
	eqs("pr", q(`externalId pr and active eq true`), "anna", "annabel", "bob", "carl")

	all, _ := e.scim(200, "GET", "/Users", nil)
	if all["totalResults"] != float64(5) || all["startIndex"] != float64(1) || all["itemsPerPage"] != float64(5) {
		t.Fatalf("list: %v", all)
	}
	p2, _ := e.scim(200, "GET", "/Users?startIndex=2&count=2", nil)
	eqs("page 2", scimNames(p2), "annabel", "bob")
	if p2["totalResults"] != float64(5) || p2["itemsPerPage"] != float64(2) {
		t.Fatalf("page: %v", p2)
	}
	p3, _ := e.scim(200, "GET", "/Users?startIndex=5&count=10", nil)
	eqs("page tail", scimNames(p3), "dora")
	p4, _ := e.scim(200, "GET", "/Users?startIndex=99", nil)
	if p4["totalResults"] != float64(5) || len(p4["Resources"].([]any)) != 0 {
		t.Fatalf("beyond end: %v", p4)
	}
	c0, _ := e.scim(200, "GET", "/Users?count=0", nil)
	if c0["totalResults"] != float64(5) || len(c0["Resources"].([]any)) != 0 {
		t.Fatalf("count=0: %v", c0)
	}
	e.scim(200, "GET", "/Users?startIndex=-5&count=-1", nil) // clamped, not an error
	e.scim(400, "GET", "/Users?startIndex=abc", nil)
	e.scim(400, "GET", "/Users?count=1e9", nil)

	// Bad and over-limit filters.
	for name, f := range map[string]string{
		"unknown attr": `password eq "x"`,
		"unsupported":  `userName gt "a"`,
		"not":          `not (userName eq "a")`,
		"long":         `userName eq "` + strings.Repeat("a", 1100) + `"`,
		"terms":        strings.TrimSuffix(strings.Repeat(`active eq true or `, 17), " or "),
		"deep":         strings.Repeat("(", 5) + `active eq true` + strings.Repeat(")", 5),
	} {
		m, _ := e.scim(400, "GET", "/Users?filter="+urlEscape(f), nil)
		if m["scimType"] != "invalidFilter" {
			t.Errorf("%s: %v", name, m)
		}
	}
	// Large count is capped at 100.
	m, _ := e.scim(200, "GET", "/Users?count=100000", nil)
	if len(m["Resources"].([]any)) != 5 {
		t.Fatal("count cap broke the listing")
	}
}

func TestSCIMScanCap(t *testing.T) {
	// A scan beyond the cap is refused, an index lookup still works.
	e := newSCIMEnv(t)
	ctx := context.Background()
	defer admin.SetSCIMScanCap(120)()
	for i := 0; i < 121; i++ {
		_ = e.st.CreateUser(ctx, core.User{Realm: scimRealm, Username: fmt.Sprintf("u%05d", i), Enabled: true})
	}
	m, _ := e.scim(400, "GET", "/Users?count=1", nil)
	if m["scimType"] != "tooMany" {
		t.Fatalf("scan cap: %v", m)
	}
	res, _ := e.scim(200, "GET", "/Users?filter="+urlEscape(`userName eq "u00042"`), nil)
	if res["totalResults"] != float64(1) {
		t.Fatalf("index lookup: %v", res)
	}
}

func TestSCIMHiddenUsers(t *testing.T) {
	e := newSCIMEnv(t)
	ctx := context.Background()
	mk := func(name string, roles ...string) string {
		u := core.User{ID: "id-" + name, Realm: scimRealm, Username: name, Enabled: true, Roles: roles}
		if err := e.st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	adm := mk("root", "haven-admin")
	svc := mk("service-account-ci")
	e.mkUser("visible", nil)

	m, _ := e.scim(200, "GET", "/Users", nil)
	if got := scimNames(m); len(got) != 1 || got[0] != "visible" || m["totalResults"] != float64(1) {
		t.Fatalf("list leaks hidden users: %v", got)
	}
	for _, f := range []string{`userName eq "root"`, `id eq "` + adm + `"`, `userName sw "service"`, `userName co "o"`} {
		r, _ := e.scim(200, "GET", "/Users?filter="+urlEscape(f), nil)
		for _, n := range scimNames(r) {
			if n == "root" || strings.HasPrefix(n, "service-account-") {
				t.Errorf("filter %s leaked %s", f, n)
			}
		}
	}
	for _, id := range []string{adm, svc} {
		e.scim(404, "GET", "/Users/"+id, nil)
		e.scim(404, "PATCH", "/Users/"+id, patch(map[string]any{"op": "replace", "path": "active", "value": false}))
		e.scim(404, "PUT", "/Users/"+id, map[string]any{"userName": "x"})
		e.scim(404, "DELETE", "/Users/"+id, nil)
		if u, err := e.st.GetUser(ctx, scimRealm, id); err != nil || !u.Enabled {
			t.Fatalf("hidden user %s was touched: %+v %v", id, u, err)
		}
	}
	// Cannot create a lookalike service account or add an admin to a group.
	e.scim(400, "POST", "/Users", map[string]any{"userName": "service-account-evil"})
	g, _ := e.scim(201, "POST", "/Groups", map[string]any{"displayName": "ops"})
	m, _ = e.scim(400, "PATCH", "/Groups/"+g["id"].(string), patch(map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": adm}}}))
	if m["scimType"] != "invalidValue" {
		t.Fatalf("admin as group member: %v", m)
	}
}

func TestSCIMGroups(t *testing.T) {
	e := newSCIMEnv(t)
	ctx := context.Background()
	a := e.mkUser("ann", nil)["id"].(string)
	b := e.mkUser("ben", nil)["id"].(string)
	c := e.mkUser("cat", nil)["id"].(string)
	mem := func(ids ...string) []any {
		var out []any
		for _, id := range ids {
			out = append(out, map[string]any{"value": id})
		}
		return out
	}

	g, h := e.scim(201, "POST", "/Groups", map[string]any{"schemas": []string{groupURN}, "displayName": "eng", "members": mem(a)})
	gid := g["id"].(string)
	if h.Get("ETag") == "" || len(g["members"].([]any)) != 1 {
		t.Fatalf("group: %v", g)
	}
	// Membership is visible on the user and in the user store as a group path.
	u, _ := e.scim(200, "GET", "/Users/"+a, nil)
	grp := u["groups"].([]any)
	if len(grp) != 1 || grp[0].(map[string]any)["display"] != "eng" {
		t.Fatalf("user groups: %v", u["groups"])
	}
	su, _ := e.st.GetUser(ctx, scimRealm, a)
	if len(su.Groups) != 1 || su.Groups[0] != "/eng" {
		t.Fatalf("stored groups: %v", su.Groups)
	}
	e.scim(409, "POST", "/Groups", map[string]any{"displayName": "eng"})
	e.scim(400, "POST", "/Groups", map[string]any{"displayName": "a/b"})
	e.scim(400, "POST", "/Groups", map[string]any{})
	e.scim(400, "POST", "/Groups", map[string]any{"displayName": "ghost", "members": mem("nope")})
	if gs, _ := e.st.ListGroups(ctx, scimRealm); len(gs) != 1 {
		t.Fatalf("a rejected group create left a group behind: %v", gs)
	}

	// PATCH add / remove / replace.
	e.scim(200, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "add", "path": "members", "value": mem(b, c)}))
	cur, _ := e.scim(200, "GET", "/Groups/"+gid, nil)
	if len(cur["members"].([]any)) != 3 {
		t.Fatalf("after add: %v", cur["members"])
	}
	cur, _ = e.scim(200, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "remove", "path": `members[value eq "` + b + `"]`}))
	if len(cur["members"].([]any)) != 2 {
		t.Fatalf("after filter remove: %v", cur["members"])
	}
	cur, _ = e.scim(200, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "remove", "path": "members", "value": mem(c)}))
	if len(cur["members"].([]any)) != 1 {
		t.Fatalf("after valued remove: %v", cur["members"])
	}
	cur, _ = e.scim(200, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "replace", "path": "members", "value": mem(b, c)}))
	if len(cur["members"].([]any)) != 2 {
		t.Fatalf("after replace: %v", cur["members"])
	}
	if su, _ := e.st.GetUser(ctx, scimRealm, a); len(su.Groups) != 0 {
		t.Fatalf("replace did not remove ann: %v", su.Groups)
	}
	cur, _ = e.scim(200, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "add", "value": map[string]any{"members": mem(a)}}))
	if len(cur["members"].([]any)) != 3 {
		t.Fatalf("no-path add: %v", cur["members"])
	}
	cur, _ = e.scim(200, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "remove", "path": "members"}))
	if len(cur["members"].([]any)) != 0 {
		t.Fatalf("remove all: %v", cur["members"])
	}

	// PUT: members replaced, name immutable.
	e.scim(200, "PUT", "/Groups/"+gid, map[string]any{"displayName": "eng", "members": mem(a, b)})
	m, _ := e.scim(400, "PUT", "/Groups/"+gid, map[string]any{"displayName": "renamed"})
	if m["scimType"] != "mutability" {
		t.Fatalf("rename: %v", m)
	}
	e.scim(400, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "replace", "path": "displayName", "value": "x"}))
	e.scim(200, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "replace", "path": "displayName", "value": "eng"}))
	e.scim(400, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "add", "path": "members", "value": mem("nope")}))

	// ETag precondition.
	_, gh := e.scim(200, "GET", "/Groups/"+gid, nil)
	e.scim(200, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "add", "path": "members", "value": mem(c)}), "If-Match", gh.Get("ETag"))
	e.scim(412, "PATCH", "/Groups/"+gid, patch(map[string]any{"op": "remove", "path": "members"}), "If-Match", gh.Get("ETag"))

	// List + filter.
	e.scim(201, "POST", "/Groups", map[string]any{"displayName": "ops"})
	l, _ := e.scim(200, "GET", "/Groups", nil)
	if l["totalResults"] != float64(2) {
		t.Fatalf("groups: %v", l)
	}
	l, _ = e.scim(200, "GET", "/Groups?filter="+urlEscape(`displayName eq "OPS"`)+"&excludedAttributes=members", nil)
	r0 := l["Resources"].([]any)
	if len(r0) != 1 || r0[0].(map[string]any)["displayName"] != "ops" || r0[0].(map[string]any)["members"] != nil {
		t.Fatalf("filtered groups: %v", l)
	}
	l, _ = e.scim(200, "GET", "/Groups?filter="+urlEscape(`members.value eq "`+c+`"`), nil)
	if l["totalResults"] != float64(1) {
		t.Fatalf("members.value filter: %v", l)
	}

	// Deleting a group is honestly unsupported.
	m, _ = e.scim(501, "DELETE", "/Groups/"+gid, nil)
	if m["status"] != "501" {
		t.Fatalf("group delete: %v", m)
	}
	e.scim(404, "GET", "/Groups/nope", nil)
}

func TestSCIMRequestSizeCap(t *testing.T) {
	e := newSCIMEnv(t)
	big := map[string]any{"userName": "big", "title": strings.Repeat("a", 300<<10)}
	m, _ := e.scim(413, "POST", "/Users", big)
	if m["status"] != "413" {
		t.Fatalf("413 body: %v", m)
	}
	if _, err := e.st.GetUserByUsername(context.Background(), scimRealm, "big"); err == nil {
		t.Fatal("oversized request created a user")
	}
	// Too many group members in one request.
	var mem []any
	for i := 0; i < 1001; i++ {
		mem = append(mem, map[string]any{"value": fmt.Sprint(i)})
	}
	e.scim(400, "POST", "/Groups", map[string]any{"displayName": "many", "members": mem})
}

func TestSCIMUnavailableWithoutStoreSupport(t *testing.T) {
	// The handler fails closed (501) on a store that lacks core.SCIMStore.
	e := newSCIMEnv(t)
	h := admin.SCIM(admin.Config{Store: plainStore{e.st}, Signer: e.signer, Hasher: e.hasher, BaseURL: e.srv.URL, AdminRealm: realm})
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/realms/corp/scim/v2/Users", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 501 && resp.StatusCode != 404 {
		t.Fatalf("got %d", resp.StatusCode)
	}
}
