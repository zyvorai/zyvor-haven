// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

func TestRoleGranterAgainstRealAdmin(t *testing.T) {
	const rlm, secret = "platform", "admin-secret-for-tests-0123456789abcdef"
	st := memstore.New()
	h := password.New(password.TestParams)
	sg := keys.New(st, keys.Options{})
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	if _, err := bootstrap.Run(context.Background(), st, h, sg, bootstrap.Options{Realm: rlm, AdminClientSecret: secret}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: st, Signer: sg, Hasher: h, BaseURL: srv.URL}))
	mux.Handle("/admin/v1/", admin.New(admin.Config{Store: st, Signer: sg, Hasher: h, BaseURL: srv.URL, AdminRealm: rlm}))
	handler = mux
	c := New(Config{BaseURL: srv.URL, Realm: rlm, ClientID: "haven-admin", ClientSecret: secret, HTTP: srv.Client()})
	var rg idp.RoleGranter = c // optional interface, not part of Provider

	if err := c.CreateUser(ctx(), rlm, idp.User{Username: "dana", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateRole(ctx(), rlm, idp.Role{Name: "ops"}); err != nil {
		t.Fatal(err)
	}
	dana := userID(t, c, "dana")

	g, err := rg.CreateRoleGrant(ctx(), rlm, dana, idp.RoleGrantRequest{Role: "ops", DurationSeconds: 600, Reason: "on-call"})
	if err != nil || g.ID == "" || g.Role != "ops" || g.State != "active" || g.UserID != dana {
		t.Fatalf("create: %v %+v", err, g)
	}
	exp := time.Now().Add(time.Hour)
	if _, err := rg.CreateRoleGrant(ctx(), rlm, dana, idp.RoleGrantRequest{Role: "ops", ExpiresAt: &exp, Reason: "again"}); err != nil {
		t.Fatalf("create with expiresAt: %v", err)
	}
	// Rejections come back as *StatusError with the API's status.
	for name, tc := range map[string]struct {
		req  idp.RoleGrantRequest
		user string
		code int
	}{
		"unknown role": {idp.RoleGrantRequest{Role: "ghost", DurationSeconds: 60, Reason: "r"}, dana, 400},
		"no reason":    {idp.RoleGrantRequest{Role: "ops", DurationSeconds: 60}, dana, 400},
		"too long":     {idp.RoleGrantRequest{Role: "ops", DurationSeconds: 99999, Reason: "r"}, dana, 400},
		"unknown user": {idp.RoleGrantRequest{Role: "ops", DurationSeconds: 60, Reason: "r"}, "nope", 404},
	} {
		_, err := rg.CreateRoleGrant(ctx(), rlm, tc.user, tc.req)
		if se := idp.AsStatus(err); se == nil || se.Code != tc.code {
			t.Errorf("%s: %v", name, err)
		}
	}

	act, err := rg.ListRoleGrants(ctx(), rlm, dana, true)
	if err != nil || len(act) != 2 {
		t.Fatalf("list: %v %+v", err, act)
	}
	realmWide, err := rg.ListRoleGrants(ctx(), rlm, "", true)
	if err != nil || len(realmWide) != 2 {
		t.Fatalf("realm list: %v %+v", err, realmWide)
	}
	if err := rg.RevokeRoleGrant(ctx(), rlm, dana, g.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := rg.RevokeRoleGrant(ctx(), rlm, dana, g.ID, true); !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("second revoke: %v", err)
	}
	if err := rg.RevokeRoleGrant(ctx(), rlm, dana, "nope", false); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("unknown grant: %v", err)
	}
	act, _ = rg.ListRoleGrants(ctx(), rlm, dana, true)
	all, _ := rg.ListRoleGrants(ctx(), rlm, dana, false)
	if len(act) != 1 || len(all) != 2 {
		t.Fatalf("active %d all %d", len(act), len(all))
	}
	var revoked *idp.RoleGrant
	for i := range all {
		if all[i].ID == g.ID {
			revoked = &all[i]
		}
	}
	if revoked == nil || revoked.State != "revoked" || revoked.RevokedAt == nil {
		t.Fatalf("revoked row: %+v", revoked)
	}
	// endSessions=true ends the user's SSO sessions too.
	now := time.Now().UTC()
	if err := st.PutSession(context.Background(), core.Session{ID: "s1", CookieHash: "h1", Realm: rlm, UserID: dana,
		LastSeen: now, IdleExpires: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	g3, err := rg.CreateRoleGrant(ctx(), rlm, dana, idp.RoleGrantRequest{Role: "ops", DurationSeconds: 60, Reason: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if err := rg.RevokeRoleGrant(ctx(), rlm, dana, g3.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(context.Background(), rlm, "s1"); err == nil {
		t.Fatal("endSessions did not end the session")
	}
}
