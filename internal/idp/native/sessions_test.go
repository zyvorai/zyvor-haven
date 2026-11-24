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

func TestSessionManagerAgainstRealAdmin(t *testing.T) {
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
	var m idp.SessionManager = c // optional interface, not part of Provider

	for _, name := range []string{"dana", "eve"} {
		if err := c.CreateUser(ctx(), rlm, idp.User{Username: name, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	dana, eve := userID(t, c, "dana"), userID(t, c, "eve")
	now := time.Now().UTC()
	put := func(id, user string) {
		t.Helper()
		err := st.PutSession(context.Background(), core.Session{ID: id, CookieHash: "h-" + id, Realm: rlm, UserID: user,
			LastSeen: now, IdleExpires: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), Clients: []string{"app"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	put("s1", dana)
	put("s2", dana)
	put("s3", eve)

	all, err := m.ListSessions(ctx(), rlm, "")
	if err != nil || len(all) != 3 {
		t.Fatalf("all: %v %+v", err, all)
	}
	mine, err := m.ListSessions(ctx(), rlm, dana)
	if err != nil || len(mine) != 2 || mine[0].Username != "dana" || len(mine[0].Clients) != 1 {
		t.Fatalf("user: %v %+v", err, mine)
	}
	if err := m.EndSession(ctx(), rlm, "s1"); err != nil {
		t.Fatal(err)
	}
	if err := m.EndSession(ctx(), rlm, "s1"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("second end: %v", err)
	}
	n, err := m.EndUserSessions(ctx(), rlm, dana)
	if err != nil || n != 1 {
		t.Fatalf("end user: %d %v", n, err)
	}
	if _, err := m.EndUserSessions(ctx(), rlm, "nope"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if left, _ := m.ListSessions(ctx(), rlm, ""); len(left) != 1 || left[0].ID != "s3" {
		t.Fatalf("left: %+v", left)
	}
}
