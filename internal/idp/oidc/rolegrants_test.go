// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

// grantStoreFake is the oidc fake store plus a real in-memory GrantStore.
type grantStoreFake struct {
	*fakeStore
	core.GrantStore
}

// failingGrants makes every ActiveRoles call fail.
type failingGrants struct{ core.GrantStore }

func (failingGrants) ActiveRoles(context.Context, string, string, time.Time) ([]string, error) {
	return nil, errors.New("db down")
}

// grantEnv wires a grant store (a memstore holding realm "r" and "other") into
// the test provider, sharing the env's fake clock.
func grantEnv(t *testing.T) (*env, core.GrantStore) {
	t.Helper()
	e := newEnv(t, nil)
	ms := memstore.New()
	for _, n := range []string{"r", "other"} {
		if err := ms.CreateRealm(context.Background(), core.Realm{Name: n, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	e.useGrants(ms)
	return e, ms
}

func (e *env) useGrants(gs core.GrantStore) {
	clock := func() time.Time { return e.now }
	e.h = New(Config{Store: &grantStoreFake{e.st, gs}, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{},
		BaseURL: "https://idp.example", Clock: clock, CSRFKey: []byte("0123456789abcdef0123456789abcdef")})
}

func (e *env) grant(gs core.GrantStore, user, role string, ttl time.Duration) core.RoleGrant {
	e.t.Helper()
	g, err := gs.CreateRoleGrant(context.Background(), core.RoleGrant{Realm: "r", UserID: user, Role: role,
		Reason: "test", ExpiresAt: e.now.Add(ttl)}, 20, e.now)
	if err != nil {
		e.t.Fatal(err)
	}
	return g
}

func (e *env) accessRoles(tok map[string]any) string {
	e.t.Helper()
	at, _ := tok["access_token"].(string)
	if at == "" {
		e.t.Fatalf("no access token: %v", tok)
	}
	return fmt.Sprint(claimsOf(e.t, at)["realm_access"])
}

func (e *env) refreshReq(rt string) (int, map[string]any) {
	e.t.Helper()
	code, tok, _ := e.tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"app"}}, "", "")
	return code, tok
}

func (e *env) exchange() map[string]any {
	e.t.Helper()
	code, tok, _ := e.tokenReq(codeForm(e.getCode(authQuery(nil))), "", "")
	if code != 200 {
		e.t.Fatalf("token %d %v", code, tok)
	}
	return tok
}

func TestEffectiveRolesAtIssue(t *testing.T) {
	e, gs := grantEnv(t)
	if got := e.accessRoles(e.exchange()); got != "map[roles:[admin]]" {
		t.Fatalf("no grant: %s", got)
	}
	e.grant(gs, "u1", "ops", time.Hour)
	e.grant(gs, "u1", "ops", 2*time.Hour) // same role twice: once in the claim
	e.grant(gs, "u1", "admin", time.Hour) // permanent role: no change, no duplicate
	e.grant(gs, "u2", "other", time.Hour) // someone else's grant
	if got := e.accessRoles(e.exchange()); got != "map[roles:[admin ops]]" {
		t.Fatalf("with grants: %s", got)
	}
	// A realm the grant was not made in does not leak: same user id in "other".
	if _, err := gs.CreateRoleGrant(context.Background(), core.RoleGrant{Realm: "other", UserID: "u1", Role: "evil",
		Reason: "x", ExpiresAt: e.now.Add(time.Hour)}, 20, e.now); err != nil {
		t.Fatal(err)
	}
	if got := e.accessRoles(e.exchange()); strings.Contains(got, "evil") {
		t.Fatalf("cross-realm leak: %s", got)
	}
	// The id token carries no roles and userinfo reports none: only the access
	// token has realm_access, and it is computed at issue.
	tok := e.exchange()
	if _, has := claimsOf(t, tok["id_token"].(string))["realm_access"]; has {
		t.Fatal("id token must not carry roles")
	}
}

func TestEffectiveRolesOnRefreshExpiry(t *testing.T) {
	e, gs := grantEnv(t)
	e.grant(gs, "u1", "ops", 2*time.Minute)
	tok := e.exchange()
	if got := e.accessRoles(tok); got != "map[roles:[admin ops]]" {
		t.Fatalf("issue: %s", got)
	}
	rt := tok["refresh_token"].(string)

	// One second before expiry the refreshed token still has the role.
	e.now = e.now.Add(2*time.Minute - time.Second)
	code, tok := e.refreshReq(rt)
	if code != 200 || e.accessRoles(tok) != "map[roles:[admin ops]]" {
		t.Fatalf("refresh before expiry: %d %v", code, tok)
	}
	// At exactly the expiry second the role is gone; the refresh token keeps working.
	e.now = e.now.Add(time.Second)
	code, tok = e.refreshReq(tok["refresh_token"].(string))
	if code != 200 {
		t.Fatalf("refresh at expiry: %d %v", code, tok)
	}
	if got := e.accessRoles(tok); got != "map[roles:[admin]]" {
		t.Fatalf("refresh at expiry kept the role: %s", got)
	}
	// And it stays gone.
	e.now = e.now.Add(time.Minute)
	code, tok = e.refreshReq(tok["refresh_token"].(string))
	if code != 200 || e.accessRoles(tok) != "map[roles:[admin]]" {
		t.Fatalf("later refresh: %d %v", code, tok)
	}
}

func TestEffectiveRolesRevokedGrant(t *testing.T) {
	e, gs := grantEnv(t)
	g := e.grant(gs, "u1", "ops", time.Hour)
	tok := e.exchange()
	if _, err := gs.RevokeRoleGrant(context.Background(), "r", "u1", g.ID, "admin", e.now); err != nil {
		t.Fatal(err)
	}
	code, tok := e.refreshReq(tok["refresh_token"].(string))
	if code != 200 || e.accessRoles(tok) != "map[roles:[admin]]" {
		t.Fatalf("after revoke: %d %v", code, tok)
	}
	// A grant made after login shows up on the next refresh without re-login.
	e.grant(gs, "u1", "dba", time.Hour)
	code, tok = e.refreshReq(tok["refresh_token"].(string))
	if code != 200 || e.accessRoles(tok) != "map[roles:[admin dba]]" {
		t.Fatalf("grant after login: %d %v", code, tok)
	}
}

func TestEffectiveRolesDisabledUser(t *testing.T) {
	e, gs := grantEnv(t)
	e.grant(gs, "u1", "ops", time.Hour)
	tok := e.exchange()
	u := e.st.users["u1"]
	u.Enabled = false
	e.st.users["u1"] = u
	if code, out := e.refreshReq(tok["refresh_token"].(string)); code != 400 || out["access_token"] != nil {
		t.Fatalf("disabled user refreshed: %d %v", code, out)
	}
}

func TestEffectiveRolesFailClosed(t *testing.T) {
	e, gs := grantEnv(t)
	e.grant(gs, "u1", "ops", time.Hour)
	e.useGrants(failingGrants{gs})
	// A failing grant lookup never widens access: permanent roles only.
	if got := e.accessRoles(e.exchange()); got != "map[roles:[admin]]" {
		t.Fatalf("lookup error: %s", got)
	}
	// A store without grant support (all the other tests) works as before.
	plain := newEnv(t, nil)
	if got := plain.accessRoles(plain.exchange()); got != "map[roles:[admin]]" {
		t.Fatalf("no grant store: %s", got)
	}
}

func TestEffectiveRolesUserinfoCarriesNoRoles(t *testing.T) {
	e, gs := grantEnv(t)
	e.grant(gs, "u1", "ops", time.Hour)
	tok := e.exchange()
	req := httptest.NewRequest("GET", base+"userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	w := e.do(req)
	if w.Code != 200 || strings.Contains(w.Body.String(), "ops") || strings.Contains(w.Body.String(), "roles") {
		t.Fatalf("userinfo %d %s", w.Code, w.Body)
	}
}

func TestEffectiveRolesHelperNeverNil(t *testing.T) {
	e, _ := grantEnv(t)
	got := e.h.effectiveRoles(context.Background(), core.Realm{Name: "r"}, core.User{ID: "nobody"})
	if got == nil || len(got) != 0 {
		t.Fatalf("got %#v", got)
	}
	u := core.User{ID: "u1", Roles: []string{"a"}}
	got = e.h.effectiveRoles(context.Background(), core.Realm{Name: "r"}, u)
	got[0] = "mutated"
	if u.Roles[0] != "a" {
		t.Fatal("effectiveRoles aliased the user's role slice")
	}
}
