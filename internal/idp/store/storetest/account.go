// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"AccountUserEvents", accountUserEvents},
		Case{"AccountRotateSessionCookie", accountRotateCookie},
	)
}

func accountStore(t *testing.T, s core.Store) core.AccountStore {
	t.Helper()
	m, found := core.StoreAs[core.AccountStore](s)
	if !found {
		t.Skip("store does not implement core.AccountStore")
	}
	return m
}

func accountUserEvents(t *testing.T, s core.Store) {
	m := accountStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	add := func(realm, user, typ string, sec int) {
		t.Helper()
		ok(t, s.AppendEvent(ctx, core.Event{Time: t0.Add(time.Duration(sec) * time.Second), Realm: realm,
			Type: typ, UserID: user, ClientID: "c", IP: "192.0.2.1", Detail: "d"}))
	}
	add("acme", "u1", "LOGIN", 1)
	add("acme", "u1", "LOGOUT", 2)
	add("acme", "u1", "ADMIN_CREATE", 3) // type not asked for
	add("acme", "u2", "LOGIN", 4)        // another user
	add("beta", "u1", "LOGIN", 5)        // same id, another realm
	add("acme", "", "LOGIN", 6)          // no user
	add("acme", "u1", "LOGIN", 7)
	add("acme", "u1", "LOGOUT", 7) // equal time: later append first
	types := []string{"LOGIN", "LOGOUT"}

	got, err := m.ListUserEvents(ctx, "acme", "u1", types, 10)
	ok(t, err)
	var seen []string
	for _, e := range got {
		if e.UserID != "u1" || e.Realm != "acme" {
			t.Fatalf("leaked event %+v", e)
		}
		seen = append(seen, e.Type+"@"+e.Time.Sub(t0).String())
	}
	eq(t, seen, []string{"LOGOUT@7s", "LOGIN@7s", "LOGOUT@2s", "LOGIN@1s"})
	eq(t, got[3], core.Event{Time: t0.Add(time.Second), Realm: "acme", Type: "LOGIN", UserID: "u1",
		ClientID: "c", IP: "192.0.2.1", Detail: "d"})

	got, err = m.ListUserEvents(ctx, "acme", "u1", types, 2)
	ok(t, err)
	if len(got) != 2 {
		t.Fatalf("limit ignored: %d", len(got))
	}
	// Empty user or empty type list must return nothing, never everything.
	for _, c := range []struct {
		user  string
		types []string
	}{{"", types}, {"u1", nil}, {"u1", []string{}}, {"nobody", types}, {"u1' OR '1'='1", types}} {
		got, err = m.ListUserEvents(ctx, "acme", c.user, c.types, 10)
		ok(t, err)
		if len(got) != 0 {
			t.Fatalf("user %q types %v: got %d events", c.user, c.types, len(got))
		}
	}
	got, err = m.ListUserEvents(ctx, "nope", "u1", types, 10)
	ok(t, err)
	if len(got) != 0 {
		t.Fatal("unknown realm returned events")
	}
}

func accountRotateCookie(t *testing.T, s core.Store) {
	m := accountStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	put := func(id, user, hash string) {
		t.Helper()
		ok(t, s.PutSession(ctx, core.Session{ID: id, CookieHash: hash, Realm: "acme", UserID: user,
			AuthTime: t0, LastSeen: t0, IdleExpires: t0.Add(time.Hour), ExpiresAt: t0.Add(2 * time.Hour),
			Clients: []string{"app"}, CreatedAt: t0}))
	}
	put("s1", "u1", "h1")
	put("s2", "u2", "h2")

	// Somebody else's session, another realm, or a missing one: not found.
	is(t, m.RotateSessionCookie(ctx, "acme", "u1", "s2", "new"), idp.ErrNotFound)
	is(t, m.RotateSessionCookie(ctx, "beta", "u1", "s1", "new"), idp.ErrNotFound)
	is(t, m.RotateSessionCookie(ctx, "acme", "u1", "missing", "new"), idp.ErrNotFound)
	is(t, m.RotateSessionCookie(ctx, "acme", "", "s1", "new"), idp.ErrNotFound)
	is(t, m.RotateSessionCookie(ctx, "acme", "u1", "s2", ""), idp.ErrNotFound)
	is(t, m.RotateSessionCookie(ctx, "acme", "u1", "s1", ""), idp.ErrConflict)
	is(t, m.RotateSessionCookie(ctx, "acme", "u1", "s1", "h2"), idp.ErrConflict)
	if x, err := s.GetSessionByCookie(ctx, "acme", "h2"); err != nil || x.ID != "s2" {
		t.Fatalf("the other session changed: %v %v", x.ID, err)
	}

	before, err := s.GetSession(ctx, "acme", "s1")
	ok(t, err)
	ok(t, m.RotateSessionCookie(ctx, "acme", "u1", "s1", "h1new"))
	_, err = s.GetSessionByCookie(ctx, "acme", "h1")
	is(t, err, idp.ErrNotFound)
	after, err := s.GetSessionByCookie(ctx, "acme", "h1new")
	ok(t, err)
	before.CookieHash = "h1new"
	eq(t, after, before) // only the cookie hash changed
}
