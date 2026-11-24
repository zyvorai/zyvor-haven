// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

// offsetClock is the real time plus a settable offset, so tokens minted by the
// real OIDC provider stay valid while grant expiry can be crossed.
type offsetClock struct{ off atomic.Int64 }

func (c *offsetClock) now() time.Time { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *offsetClock) advance(d time.Duration) {
	c.off.Add(int64(d))
}

type gEnv struct {
	*env
	clk   *offsetClock
	r     string // realm path
	alice string // user id
}

// grantEnv has roles ops and dba, a user alice with a password and a public
// client "app". The admin token is long-lived so the clock can move.
func grantEnv(t *testing.T) *gEnv {
	t.Helper()
	clk := &offsetClock{}
	e := newEnvWith(t, func(cfg *admin.Config, _ *memstore.Store, _ string) { cfg.Clock = clk.now })
	ctx := context.Background()
	rl, err := e.st.GetRealm(ctx, realm)
	if err != nil {
		t.Fatal(err)
	}
	rl.AccessTokenTTL = 90 * 24 * time.Hour
	if err := e.st.UpdateRealm(ctx, rl); err != nil {
		t.Fatal(err)
	}
	e.token = e.clientToken(realm, "haven-admin", adminSecret)
	g := &gEnv{env: e, clk: clk, r: "/realms/" + realm}
	for _, n := range []string{"ops", "dba", "viewer"} {
		e.createID(g.r+"/roles", map[string]any{"name": n})
	}
	e.createID(g.r+"/clients", map[string]any{"clientId": "app", "enabled": true, "publicClient": true,
		"standardFlowEnabled": true, "redirectUris": []string{"http://localhost/cb"}})
	g.alice = g.user("alice")
	return g
}

func (g *gEnv) user(name string) string {
	id := g.createID(g.r+"/users", map[string]any{"username": name, "enabled": true})
	g.api(204, "PUT", g.r+"/users/"+id+"/password", map[string]any{"type": "password", "value": goodPW})
	return id
}

func (g *gEnv) grant(want int, uid string, body any) []byte {
	g.t.Helper()
	return g.api(want, "POST", g.r+"/users/"+uid+"/grants", body)
}

func (g *gEnv) grantID(uid string, body any) string {
	g.t.Helper()
	var out idp.RoleGrant
	if err := json.Unmarshal(g.grant(201, uid, body), &out); err != nil || out.ID == "" {
		g.t.Fatalf("grant response: %v", err)
	}
	return out.ID
}

func (g *gEnv) list(path string) []idp.RoleGrant {
	g.t.Helper()
	var out []idp.RoleGrant
	if err := json.Unmarshal(g.api(200, "GET", path, nil), &out); err != nil {
		g.t.Fatal(err)
	}
	return out
}

func (g *gEnv) active(uid string) []string {
	g.t.Helper()
	gs, ok := core.StoreAs[core.GrantStore](g.st)
	if !ok {
		g.t.Fatal("no grant store")
	}
	r, err := gs.ActiveRoles(context.Background(), realm, uid, g.clk.now())
	if err != nil {
		g.t.Fatal(err)
	}
	return r
}

func (g *gEnv) events(typ string) []core.Event {
	evs, _ := g.st.ListEvents(context.Background(), realm, 500)
	var out []core.Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func rolesOf(t *testing.T, access string) []string {
	t.Helper()
	parts := strings.Split(access, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		RA struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c.RA.Roles
}

func TestGrantLifecycle(t *testing.T) {
	g := grantEnv(t)
	start := g.clk.now()
	var created idp.RoleGrant
	raw := g.grant(201, g.alice, map[string]any{"role": "ops", "durationSeconds": 3600, "reason": "  on-call for INC-42 "})
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}
	if created.Role != "ops" || created.UserID != g.alice || created.State != "active" || created.Reason != "on-call for INC-42" ||
		created.GrantedBy != "client:haven-admin" || created.RevokedAt != nil {
		t.Fatalf("created: %+v", created)
	}
	if d := created.ExpiresAt.Sub(created.CreatedAt); d != time.Hour {
		t.Fatalf("expiry %v after creation, want 1h", d)
	}
	if created.CreatedAt.Before(start.Add(-2*time.Second)) || created.CreatedAt.After(g.clk.now()) {
		t.Fatalf("createdAt %v", created.CreatedAt)
	}
	// expiresAt form, with a non-UTC offset, truncated to the second.
	exp := g.clk.now().Add(2 * time.Hour).In(time.FixedZone("x", 5*3600+1800))
	id2 := g.grantID(g.alice, map[string]any{"role": "dba", "expiresAt": exp.Format(time.RFC3339), "reason": "migration"})

	if got := g.active(g.alice); fmt.Sprint(got) != "[dba ops]" {
		t.Fatalf("active roles %v", got)
	}
	if n := len(g.list(g.r + "/users/" + g.alice + "/grants")); n != 2 { // default state=active
		t.Fatalf("default list: %d", n)
	}
	if n := len(g.list(g.r + "/grants?state=active")); n != 2 {
		t.Fatalf("realm list: %d", n)
	}
	// Created event: names role and expiry, never the reason.
	evs := g.events("ROLE_GRANT_CREATED")
	if len(evs) != 2 {
		t.Fatalf("created events: %+v", evs)
	}
	for _, ev := range evs {
		if strings.Contains(ev.Detail, "INC-42") || strings.Contains(ev.Detail, "migration") || ev.UserID != g.alice ||
			!strings.HasPrefix(ev.Detail, "grant ") || !strings.Contains(ev.Detail, " until ") {
			t.Fatalf("event: %+v", ev)
		}
	}

	// 61 minutes later the first grant is over, the second is not.
	g.clk.advance(61 * time.Minute)
	if got := g.active(g.alice); fmt.Sprint(got) != "[dba]" {
		t.Fatalf("after 61m: %v", got)
	}
	act := g.list(g.r + "/users/" + g.alice + "/grants?state=active")
	all := g.list(g.r + "/users/" + g.alice + "/grants?state=all")
	if len(act) != 1 || act[0].ID != id2 || len(all) != 2 {
		t.Fatalf("active %d all %d", len(act), len(all))
	}
	states := map[string]string{}
	for _, x := range all {
		states[x.Role] = x.State
	}
	if states["ops"] != "expired" || states["dba"] != "active" {
		t.Fatalf("states %v", states)
	}
	if n := len(g.list(g.r + "/grants?state=active")); n != 1 {
		t.Fatalf("realm active after expiry: %d", n)
	}
	// An expired grant cannot be revoked; the live one can, once.
	g.api(409, "DELETE", g.r+"/users/"+g.alice+"/grants/"+created.ID, nil)
	g.api(204, "DELETE", g.r+"/users/"+g.alice+"/grants/"+id2, nil)
	g.api(409, "DELETE", g.r+"/users/"+g.alice+"/grants/"+id2, nil)
	if got := g.active(g.alice); len(got) != 0 {
		t.Fatalf("after revoke: %v", got)
	}
	all = g.list(g.r + "/users/" + g.alice + "/grants?state=all")
	for _, x := range all {
		if x.Role == "dba" && (x.State != "revoked" || x.RevokedAt == nil || x.RevokedBy != "client:haven-admin") {
			t.Fatalf("revoked row: %+v", x)
		}
	}
	if evs := g.events("ROLE_GRANT_REVOKED"); len(evs) != 1 || !strings.HasPrefix(evs[0].Detail, "grant dba until ") {
		t.Fatalf("revoked events: %+v", evs)
	}
	g.api(404, "DELETE", g.r+"/users/"+g.alice+"/grants/nope", nil)

	// The purge loop reports the expired one once (ROLE_GRANT_EXPIRED), keeps the rows.
	n, err := core.PurgeGrants(context.Background(), g.st, g.clk.now())
	if err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if n, _ := core.PurgeGrants(context.Background(), g.st, g.clk.now()); n != 0 {
		t.Fatalf("second purge reported %d", n)
	}
	if evs := g.events("ROLE_GRANT_EXPIRED"); len(evs) != 1 || !strings.HasPrefix(evs[0].Detail, "grant ops until ") || evs[0].UserID != g.alice {
		t.Fatalf("expired events: %+v", evs)
	}
	if n := len(g.list(g.r + "/users/" + g.alice + "/grants?state=all")); n != 2 {
		t.Fatalf("rows kept for audit: %d", n)
	}
}

func TestGrantRevokeEndSessions(t *testing.T) {
	g := grantEnv(t)
	id := g.grantID(g.alice, map[string]any{"role": "ops", "durationSeconds": 600, "reason": "x"})
	s := g.putSession(g.alice, time.Minute, time.Hour, 5*time.Hour, "app")
	// Without the flag the session survives.
	other := g.grantID(g.alice, map[string]any{"role": "dba", "durationSeconds": 600, "reason": "x"})
	g.api(204, "DELETE", g.r+"/users/"+g.alice+"/grants/"+other, nil)
	if _, err := g.st.GetSession(context.Background(), realm, s.ID); err != nil {
		t.Fatalf("session must survive a plain revoke: %v", err)
	}
	g.api(400, "DELETE", g.r+"/users/"+g.alice+"/grants/"+id+"?endSessions=maybe", nil)
	g.api(204, "DELETE", g.r+"/users/"+g.alice+"/grants/"+id+"?endSessions=true", nil)
	if _, err := g.st.GetSession(context.Background(), realm, s.ID); err == nil {
		t.Fatal("endSessions=true must end the user's sessions")
	}
}

func TestGrantValidation(t *testing.T) {
	g := grantEnv(t)
	other := g.user("bob")
	disabled := g.user("dis")
	g.api(204, "PUT", g.r+"/users/"+disabled, map[string]any{"username": "dis", "enabled": false})
	in := func(k string, v any) map[string]any { return map[string]any{k: v} }
	now := g.clk.now()
	ok := func(over map[string]any) map[string]any {
		m := map[string]any{"role": "ops", "durationSeconds": 60, "reason": "r"}
		for k, v := range over {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	long := strings.Repeat("é", 501)
	cases := []struct {
		name string
		uid  string
		body any
		want int
	}{
		{"ok duration", other, ok(nil), 201},
		{"unknown role", g.alice, ok(in("role", "ghost")), 400},
		{"empty role", g.alice, ok(in("role", "")), 400},
		{"bad role chars", g.alice, ok(in("role", "ops; drop")), 400},
		{"admin role refused", g.alice, ok(in("role", "haven-admin")), 400},
		{"missing reason", g.alice, ok(in("reason", nil)), 400},
		{"blank reason", g.alice, ok(in("reason", "   ")), 400},
		{"reason 501 chars", g.alice, ok(in("reason", long)), 400},
		{"reason 500 chars", g.alice, ok(in("reason", strings.Repeat("é", 500))), 201},
		{"reason control char", g.alice, ok(in("reason", "a\nb")), 400},
		{"neither time", g.alice, ok(in("durationSeconds", nil)), 400},
		{"both times", g.alice, ok(in("expiresAt", now.Add(time.Hour).Format(time.RFC3339))), 400},
		{"zero duration", g.alice, ok(in("durationSeconds", 0)), 400},
		{"negative duration", g.alice, ok(in("durationSeconds", -5)), 400},
		{"huge duration", g.alice, ok(in("durationSeconds", 1<<40)), 400},
		{"over max duration", g.alice, ok(in("durationSeconds", 8*3600+1)), 400},
		{"exactly max duration", g.alice, ok(in("durationSeconds", 8*3600)), 201},
		{"expiresAt past", g.alice, ok(map[string]any{"durationSeconds": nil, "expiresAt": now.Add(-time.Minute).Format(time.RFC3339)}), 400},
		{"expiresAt now", g.alice, ok(map[string]any{"durationSeconds": nil, "expiresAt": now.Format(time.RFC3339)}), 400},
		{"expiresAt over max", g.alice, ok(map[string]any{"durationSeconds": nil, "expiresAt": now.Add(9 * time.Hour).Format(time.RFC3339)}), 400},
		{"expiresAt not RFC3339", g.alice, ok(map[string]any{"durationSeconds": nil, "expiresAt": "tomorrow"}), 400},
		{"expiresAt ok", g.alice, ok(map[string]any{"durationSeconds": nil, "expiresAt": now.Add(2 * time.Hour).Format(time.RFC3339)}), 201},
		{"unknown field", g.alice, ok(in("userId", "x")), 400},
		{"not an object", g.alice, "[1]", 400},
		{"disabled user", disabled, ok(nil), 400},
		{"unknown user", "nope", ok(nil), 404},
	}
	for _, c := range cases {
		code, body, _ := g.call("POST", g.r+"/users/"+c.uid+"/grants", g.token, c.body)
		if code != c.want {
			t.Errorf("%s: got %d want %d: %s", c.name, code, c.want, body)
		}
	}
	g.api(404, "POST", "/realms/nope/users/"+g.alice+"/grants", ok(nil))
	// Nothing rejected left a row behind.
	if n := len(g.list(g.r + "/users/" + g.alice + "/grants?state=all")); n != 3 {
		t.Errorf("alice has %d grants, want 3 (the accepted cases)", n)
	}
}

func TestGrantPolicy(t *testing.T) {
	g := grantEnv(t)
	var p struct {
		MaxDurationSeconds int      `json:"maxDurationSeconds"`
		RequireReason      bool     `json:"requireReason"`
		AllowedRoles       []string `json:"allowedRoles"`
	}
	get := func() {
		p = struct {
			MaxDurationSeconds int      `json:"maxDurationSeconds"`
			RequireReason      bool     `json:"requireReason"`
			AllowedRoles       []string `json:"allowedRoles"`
		}{}
		if err := json.Unmarshal(g.api(200, "GET", g.r+"/grants-policy", nil), &p); err != nil {
			t.Fatal(err)
		}
	}
	get()
	if p.MaxDurationSeconds != 8*3600 || !p.RequireReason || p.AllowedRoles == nil || len(p.AllowedRoles) != 0 {
		t.Fatalf("defaults: %+v", p)
	}
	for name, body := range map[string]any{
		"max too small": map[string]any{"maxDurationSeconds": 59}, "max too large": map[string]any{"maxDurationSeconds": 30*24*3600 + 1},
		"unknown role": map[string]any{"allowedRoles": []string{"ghost"}}, "admin role": map[string]any{"allowedRoles": []string{"haven-admin"}},
		"unknown field": map[string]any{"nope": 1},
	} {
		if code, b, _ := g.call("PUT", g.r+"/grants-policy", g.token, body); code != 400 {
			t.Errorf("%s: got %d: %s", name, code, b)
		}
	}
	g.api(200, "PUT", g.r+"/grants-policy", map[string]any{"maxDurationSeconds": 900, "allowedRoles": []string{"ops", "ops"}})
	get()
	if p.MaxDurationSeconds != 900 || !p.RequireReason || fmt.Sprint(p.AllowedRoles) != "[ops]" {
		t.Fatalf("after put (omitted fields keep value, dupes dropped): %+v", p)
	}
	// Allowlist.
	g.grant(400, g.alice, map[string]any{"role": "dba", "durationSeconds": 60, "reason": "r"})
	g.grant(201, g.alice, map[string]any{"role": "ops", "durationSeconds": 60, "reason": "r"})
	// Max: boundary in seconds, for both forms.
	g.grant(400, g.alice, map[string]any{"role": "ops", "durationSeconds": 901, "reason": "r"})
	g.grant(201, g.alice, map[string]any{"role": "ops", "durationSeconds": 900, "reason": "r"})
	g.grant(400, g.alice, map[string]any{"role": "ops", "expiresAt": g.clk.now().Add(902 * time.Second).Format(time.RFC3339), "reason": "r"})
	// Reason optional when the policy says so, and an empty allowlist clears it.
	g.api(200, "PUT", g.r+"/grants-policy", map[string]any{"requireReason": false, "allowedRoles": []string{}})
	g.grant(201, g.alice, map[string]any{"role": "dba", "durationSeconds": 60})
	get()
	if p.RequireReason || len(p.AllowedRoles) != 0 || p.MaxDurationSeconds != 900 {
		t.Fatalf("final: %+v", p)
	}
	// Narrowing the policy does not touch grants that exist.
	g.api(200, "PUT", g.r+"/grants-policy", map[string]any{"allowedRoles": []string{"viewer"}})
	if got := g.active(g.alice); fmt.Sprint(got) != "[dba ops]" {
		t.Fatalf("existing grants after narrowing: %v", got)
	}
	// Policy is per realm.
	g.createID("/realms", map[string]any{"realm": "other", "enabled": true})
	var o struct{ MaxDurationSeconds int }
	if err := json.Unmarshal(g.api(200, "GET", "/realms/other/grants-policy", nil), &o); err != nil || o.MaxDurationSeconds != 8*3600 {
		t.Fatalf("other realm policy: %+v %v", o, err)
	}
	g.api(404, "GET", "/realms/nope/grants-policy", nil)
}

func TestGrantLimitConcurrent(t *testing.T) {
	g := grantEnv(t)
	var created, limited atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, b, _ := g.call("POST", g.r+"/users/"+g.alice+"/grants", g.token,
				map[string]any{"role": "ops", "durationSeconds": 600, "reason": "r"})
			switch code {
			case 201:
				created.Add(1)
			case 429:
				limited.Add(1)
			default:
				t.Errorf("unexpected %d: %s", code, b)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 20 || limited.Load() != 10 {
		t.Fatalf("created %d limited %d, want 20/10", created.Load(), limited.Load())
	}
	// Revoking one frees a slot; another user is not affected.
	first := g.list(g.r + "/users/" + g.alice + "/grants")[0]
	g.api(204, "DELETE", g.r+"/users/"+g.alice+"/grants/"+first.ID, nil)
	g.grant(201, g.alice, map[string]any{"role": "ops", "durationSeconds": 600, "reason": "r"})
	g.grant(429, g.alice, map[string]any{"role": "ops", "durationSeconds": 600, "reason": "r"})
	g.grant(201, g.user("bob"), map[string]any{"role": "ops", "durationSeconds": 600, "reason": "r"})
}

func TestGrantAuthorization(t *testing.T) {
	g := grantEnv(t)
	id := g.grantID(g.alice, map[string]any{"role": "ops", "durationSeconds": 600, "reason": "r"})
	pleb := g.user("pleb")
	plebTok := g.login("app", "pleb", goodPW)
	body := map[string]any{"role": "ops", "durationSeconds": 60, "reason": "r"}
	type rq struct{ method, path string }
	reqs := []rq{
		{"POST", g.r + "/users/" + g.alice + "/grants"}, {"GET", g.r + "/users/" + g.alice + "/grants"},
		{"GET", g.r + "/grants"}, {"DELETE", g.r + "/users/" + g.alice + "/grants/" + id},
		{"GET", g.r + "/grants-policy"}, {"PUT", g.r + "/grants-policy"},
	}
	for _, q := range reqs {
		if code, _, _ := g.call(q.method, q.path, "", body); code != 401 {
			t.Errorf("%s %s without token: %d", q.method, q.path, code)
		}
		if code, _, _ := g.call(q.method, q.path, "garbage", body); code != 401 {
			t.Errorf("%s %s garbage token: %d", q.method, q.path, code)
		}
		if code, _, _ := g.call(q.method, q.path, plebTok, body); code != 403 {
			t.Errorf("%s %s non-admin user: %d", q.method, q.path, code)
		}
	}
	// A user cannot lift themselves: a grant for pleb's own role set via the API needs admin too,
	// and nothing above changed state.
	if got := g.active(pleb); len(got) != 0 {
		t.Fatalf("pleb has %v", got)
	}
	if n := len(g.list(g.r + "/grants")); n != 1 {
		t.Fatalf("realm grants: %d", n)
	}
}

func TestGrantRealmIsolation(t *testing.T) {
	g := grantEnv(t)
	g.createID("/realms", map[string]any{"realm": "other", "enabled": true})
	g.createID("/realms/other/roles", map[string]any{"name": "ops"})
	oid := g.createID("/realms/other/users", map[string]any{"username": "alice", "enabled": true})
	gid := g.grantID(g.alice, map[string]any{"role": "ops", "durationSeconds": 600, "reason": "r"})
	// The other realm neither lists it, nor can revoke it, nor can it grant to a platform user.
	if n := len(g.list("/realms/other/grants")); n != 0 {
		t.Fatalf("leak into realm list: %d", n)
	}
	g.api(404, "GET", "/realms/other/users/"+g.alice+"/grants", nil)
	g.api(404, "DELETE", "/realms/other/users/"+g.alice+"/grants/"+gid, nil)
	g.api(404, "DELETE", "/realms/other/users/"+oid+"/grants/"+gid, nil)
	g.api(404, "POST", "/realms/other/users/"+g.alice+"/grants", map[string]any{"role": "ops", "durationSeconds": 60, "reason": "r"})
	if n := len(g.list("/realms/other/users/" + oid + "/grants?state=all")); n != 0 {
		t.Fatalf("leak into other realm's user: %d", n)
	}
	// Granting in the other realm does not show in platform.
	g.api(201, "POST", "/realms/other/users/"+oid+"/grants", map[string]any{"role": "ops", "durationSeconds": 60, "reason": "r"})
	if n := len(g.list(g.r + "/grants")); n != 1 {
		t.Fatalf("platform realm list: %d", n)
	}
	// A grant of another user's id: revoke must name the right user.
	bob := g.user("bob")
	g.api(404, "DELETE", g.r+"/users/"+bob+"/grants/"+gid, nil)
	if got := g.active(g.alice); fmt.Sprint(got) != "[ops]" {
		t.Fatalf("grant was revoked through the wrong user: %v", got)
	}
}

// Through the real OIDC provider: a grant shows in the next token, and a
// revoked one is gone from the refreshed token.
func TestGrantTokenRolesEndToEnd(t *testing.T) {
	g := grantEnv(t)
	tr := g.loginTokens("app", "alice", goodPW, "http://localhost/cb")
	if r := rolesOf(t, tr["access_token"].(string)); len(r) != 0 {
		t.Fatalf("before grant: %v", r)
	}
	id := g.grantID(g.alice, map[string]any{"role": "ops", "durationSeconds": 3600, "reason": "r"})
	tr2 := g.loginTokens("app", "alice", goodPW, "http://localhost/cb")
	if r := rolesOf(t, tr2["access_token"].(string)); fmt.Sprint(r) != "[ops]" {
		t.Fatalf("after grant: %v", r)
	}
	refresh := func(rt string) map[string]any {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"app"}}
		return g.tokenPost(form)
	}
	rt, _ := tr2["refresh_token"].(string)
	if rt == "" {
		t.Skip("no refresh token issued")
	}
	// Refresh while the grant is active keeps it; after revocation it is gone.
	tr3 := refresh(rt)
	if r := rolesOf(t, tr3["access_token"].(string)); fmt.Sprint(r) != "[ops]" {
		t.Fatalf("refresh with active grant: %v", r)
	}
	g.api(204, "DELETE", g.r+"/users/"+g.alice+"/grants/"+id, nil)
	tr4 := refresh(tr3["refresh_token"].(string))
	if r := rolesOf(t, tr4["access_token"].(string)); len(r) != 0 {
		t.Fatalf("refresh after revoke still has %v", r)
	}
}

func (e *env) tokenPost(form url.Values) map[string]any {
	e.t.Helper()
	resp, err := http.PostForm(e.srv.URL+"/realms/"+realm+"/protocol/openid-connect/token", form)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if resp.StatusCode != 200 || json.Unmarshal(b, &out) != nil {
		e.t.Fatalf("token: %d %s", resp.StatusCode, b)
	}
	return out
}

func TestGrantFeatureOffWithoutStoreSupport(t *testing.T) {
	e := newEnvWith(t, func(cfg *admin.Config, _ *memstore.Store, _ string) {
		cfg.Store = struct{ core.Store }{cfg.Store} // hides the GrantStore methods
	})
	r := "/realms/" + realm
	id := e.createID(r+"/users", map[string]any{"username": "alice", "enabled": true})
	for _, q := range [][2]string{{"GET", r + "/grants"}, {"GET", r + "/grants-policy"}, {"GET", r + "/users/" + id + "/grants"},
		{"PUT", r + "/grants-policy"}, {"POST", r + "/users/" + id + "/grants"}, {"DELETE", r + "/users/" + id + "/grants/x"}} {
		if code, b, _ := e.call(q[0], q[1], e.token, map[string]any{"role": "x", "durationSeconds": 60}); code != 501 {
			t.Errorf("%s %s: %d %s", q[0], q[1], code, b)
		}
	}
}
