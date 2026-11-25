// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseGroupsClaimClients(t *testing.T) {
	for _, empty := range []string{"", " ", ",", " , "} {
		if p, err := ParseGroupsClaimClients(empty); err != nil || p != nil {
			t.Errorf("%q: want off, got %v %v", empty, p, err)
		}
	}
	p, err := ParseGroupsClaimClients(" platform/kubernetes, platform/argo ,dev/https://app.example/meta.json,")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		realm, id string
		want      bool
	}{
		{"platform", "kubernetes", true}, {"platform", "argo", true}, {"dev", "https://app.example/meta.json", true},
		{"dev", "kubernetes", false}, {"platform", "Kubernetes", false}, {"platform", "kube", false}, {"", "", false},
	} {
		if got := p.Allowed(c.realm, c.id); got != c.want {
			t.Errorf("Allowed(%q,%q)=%v", c.realm, c.id, got)
		}
	}
	var nilp *GroupsClaimPolicy
	if nilp.Allowed("platform", "kubernetes") || nilp.anyIn("platform") {
		t.Error("nil policy allows")
	}
	for _, bad := range []string{"kubernetes", "platform/", "/kubernetes", "Platform/kubernetes", "platform/a b", "*/kubernetes", "platform/*",
		"platform/kubernetes,oops"} {
		if _, err := ParseGroupsClaimClients(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// groupsEnv is the device-flow environment with alice in some groups.
func groupsEnv(t *testing.T, policy string, groups []string) *denv {
	t.Helper()
	e := newDEnv(t, devOpts{})
	p, err := ParseGroupsClaimClients(policy)
	if err != nil {
		t.Fatal(err)
	}
	e.h.cfg.GroupsClaim = p
	setGroups(t, e, groups)
	return e
}

func setGroups(t *testing.T, e *denv, groups []string) {
	t.Helper()
	u, err := e.st.GetUser(context.Background(), "r", "u1")
	if err != nil {
		t.Fatal(err)
	}
	u.Groups = groups
	if err := e.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
}

func deviceTokens(t *testing.T, e *denv, scope string) map[string]any {
	t.Helper()
	g := e.start("cli", scope)
	b := e.browser()
	page := b.openAndLogin(g, "alice", "pw")
	// The person approving is told that group membership is shared.
	if told := strings.Contains(page.Body.String(), "See which groups you belong to"); told != strings.Contains(scope, "groups") {
		t.Fatalf("approval page mentions groups=%v for scope %q", told, scope)
	}
	if w := b.decide(g.UserCode, "approve"); w.Code != 200 {
		t.Fatalf("approve: %d", w.Code)
	}
	e.advance(10 * time.Second)
	c, out := e.poll("cli", g.DeviceCode)
	if c != 200 {
		t.Fatalf("token: %d %v", c, out)
	}
	return out
}

func TestGroupsClaimNeedsOptInAndScope(t *testing.T) {
	groups := []string{"/ops", "/eng/dev"}
	for _, c := range []struct {
		name, policy, scope string
		want                bool
	}{
		{"opted in with scope", "r/cli", "openid groups", true},
		{"opted in, scope not requested", "r/cli", "openid profile email roles offline_access", false},
		{"no policy", "", "openid groups", false},
		{"another client opted in", "r/app", "openid groups", false},
		{"same client id in another realm", "other/cli", "openid groups", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := groupsEnv(t, c.policy, groups)
			out := deviceTokens(t, e, c.scope)
			id := claimsOf(t, out["id_token"].(string))
			got, present := id["groups"]
			if present != c.want {
				t.Fatalf("groups present=%v want %v (%v)", present, c.want, got)
			}
			if c.want && !reflect.DeepEqual(got, []any{"eng/dev", "ops"}) {
				t.Fatalf("groups %v", got)
			}
			// Never in the access token: the cluster only accepts ID tokens.
			if _, ok := claimsOf(t, out["access_token"].(string))["groups"]; ok {
				t.Fatal("groups in the access token")
			}
		})
	}
}

func TestGroupsClaimNeverEmitsReservedOrMalformedNames(t *testing.T) {
	e := groupsEnv(t, "r/cli", []string{"/system:masters", "/System:Admins", "system:nodes", "noslash", "/", "//system:masters",
		"/ padded", "/ctl\x00x", "/zero\u200bwidth", "/trailing/", "/b", "/a", "/b", "/team/system:masters"})
	id := claimsOf(t, deviceTokens(t, e, "openid groups")["id_token"].(string))
	if want := []any{"a", "b", "team/system:masters"}; !reflect.DeepEqual(id["groups"], want) {
		t.Fatalf("groups %#v want %#v", id["groups"], want)
	}
}

func TestGroupsClaimEmptyAndRefreshed(t *testing.T) {
	e := groupsEnv(t, "r/cli", nil)
	out := deviceTokens(t, e, "openid offline_access groups")
	id := claimsOf(t, out["id_token"].(string))
	if g, ok := id["groups"].([]any); !ok || len(g) != 0 {
		t.Fatalf("want an empty list, got %#v", id["groups"])
	}
	refresh := func(tok, scope string) map[string]any {
		f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {"cli"}}
		if scope != "" {
			f.Set("scope", scope)
		}
		c, out, _ := e.post(base+"token", f, "", "", "")
		if c != 200 {
			t.Fatalf("refresh: %d %v", c, out)
		}
		return out
	}
	// Membership is read again at every refresh: joining and leaving show up.
	setGroups(t, e, []string{"/ops"})
	out = refresh(out["refresh_token"].(string), "")
	if g := claimsOf(t, out["id_token"].(string))["groups"]; !reflect.DeepEqual(g, []any{"ops"}) {
		t.Fatalf("after join: %v", g)
	}
	setGroups(t, e, nil)
	out = refresh(out["refresh_token"].(string), "")
	if g := claimsOf(t, out["id_token"].(string))["groups"]; !reflect.DeepEqual(g, []any{}) {
		t.Fatalf("after leave: %v", g)
	}
	// A narrowed refresh without the scope carries no claim.
	setGroups(t, e, []string{"/ops"})
	out = refresh(out["refresh_token"].(string), "openid")
	if g, ok := claimsOf(t, out["id_token"].(string))["groups"]; ok {
		t.Fatalf("narrowed scope still has groups: %v", g)
	}
	// Opting the client out stops the claim for an existing grant.
	e2 := groupsEnv(t, "r/cli", []string{"/ops"})
	out = deviceTokens(t, e2, "openid offline_access groups")
	e2.h.cfg.GroupsClaim = nil
	c, ref, _ := e2.post(base+"token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {out["refresh_token"].(string)}, "client_id": {"cli"}}, "", "", "")
	if c != 200 {
		t.Fatalf("refresh: %d %v", c, ref)
	}
	if _, ok := claimsOf(t, ref["id_token"].(string))["groups"]; ok {
		t.Fatal("opted-out client still gets groups")
	}
}

func TestGroupsScopeCannotBeAddedOnRefresh(t *testing.T) {
	e := groupsEnv(t, "r/cli", []string{"/ops"})
	out := deviceTokens(t, e, "openid offline_access")
	c, res, _ := e.post(base+"token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {out["refresh_token"].(string)},
		"client_id": {"cli"}, "scope": {"openid groups"}}, "", "", "")
	if c != 400 || errOf(res) != "invalid_scope" {
		t.Fatalf("scope escalation: %d %v", c, res)
	}
}

func TestGroupsDiscovery(t *testing.T) {
	e := groupsEnv(t, "r/cli", nil)
	get := func(realm string) string {
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/realms/"+realm+"/.well-known/openid-configuration", nil))
		return w.Body.String()
	}
	if d := get("r"); strings.Count(d, `"groups"`) != 2 { // scopes_supported and claims_supported
		t.Errorf("opted-in realm: %s", d)
	}
	if d := get("other"); strings.Contains(d, `"groups"`) {
		t.Errorf("realm without opt-in advertises groups: %s", d)
	}
	if !slices.Contains(knownScopes, "groups") {
		t.Error("groups is not a known scope")
	}
}
