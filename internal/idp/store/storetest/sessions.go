// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func mkSession(id, user string) core.Session {
	return core.Session{
		ID: id, CookieHash: "ck-" + id, Realm: "acme", UserID: user,
		AuthTime: t0, LastSeen: t0.Add(time.Minute), IdleExpires: t0.Add(time.Hour),
		ExpiresAt: t0.Add(10 * time.Hour), IP: "203.0.113.7", UserAgent: "UA/1.0",
		Clients: []string{"web", "cli"}, CreatedAt: t0,
	}
}

func sessionRoundtrip(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	in := mkSession("s-1", "u-1")
	ok(t, s.PutSession(ctx, in))
	got, err := s.GetSession(ctx, "acme", "s-1")
	ok(t, err)
	eq(t, got, in)
	got, err = s.GetSessionByCookie(ctx, "acme", "ck-s-1")
	ok(t, err)
	eq(t, got, in)

	// Empty clients and zero CreatedAt (filled by the store).
	e := mkSession("s-2", "u-1")
	e.Clients, e.CreatedAt = nil, time.Time{}
	ok(t, s.PutSession(ctx, e))
	got, err = s.GetSession(ctx, "acme", "s-2")
	ok(t, err)
	if len(got.Clients) != 0 || got.CreatedAt.IsZero() {
		t.Fatalf("defaults not applied: %+v", got)
	}

	_, err = s.GetSession(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetSessionByCookie(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)
}

func sessionConflict(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	ok(t, s.PutSession(ctx, mkSession("s-1", "u-1")))
	is(t, s.PutSession(ctx, mkSession("s-1", "u-2")), idp.ErrConflict)
	dupCookie := mkSession("s-2", "u-1")
	dupCookie.CookieHash = "ck-s-1"
	is(t, s.PutSession(ctx, dupCookie), idp.ErrConflict)
	if l, _ := s.ListSessions(ctx, "acme", "", 10); len(l) != 1 {
		t.Fatalf("sessions after conflicts = %d, want 1", len(l))
	}
	bad := mkSession("s-3", "u-1")
	bad.Realm = "ghost"
	is(t, s.PutSession(ctx, bad), idp.ErrNotFound)
}

func sessionIsolation(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, s.PutSession(ctx, mkSession("s-1", "u-1")))
	_, err := s.GetSession(ctx, "other", "s-1")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetSessionByCookie(ctx, "other", "ck-s-1")
	is(t, err, idp.ErrNotFound)
	is(t, s.TouchSession(ctx, "other", "s-1", t0, t0), idp.ErrNotFound)
	is(t, s.AddSessionClient(ctx, "other", "s-1", "x"), idp.ErrNotFound)
	_, err = s.TakeSession(ctx, "other", "s-1")
	is(t, err, idp.ErrNotFound)
	tk, err := s.TakeUserSessions(ctx, "other", "u-1")
	ok(t, err)
	if len(tk) != 0 {
		t.Fatalf("took %d sessions across realms", len(tk))
	}
	if l, _ := s.ListSessions(ctx, "other", "", 10); len(l) != 0 {
		t.Fatalf("list leaked across realms: %v", l)
	}
	got, err := s.GetSession(ctx, "acme", "s-1")
	ok(t, err)
	eq(t, got, mkSession("s-1", "u-1"))
}

func sessionTouch(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	ok(t, s.PutSession(ctx, mkSession("s-1", "u-1")))
	ls, idle := t0.Add(5*time.Minute), t0.Add(2*time.Hour)
	ok(t, s.TouchSession(ctx, "acme", "s-1", ls, idle))
	got, err := s.GetSession(ctx, "acme", "s-1")
	ok(t, err)
	eq(t, got.LastSeen, ls)
	eq(t, got.IdleExpires, idle)
	eq(t, got.ExpiresAt, t0.Add(10*time.Hour)) // absolute cap untouched
	is(t, s.TouchSession(ctx, "acme", "nope", ls, idle), idp.ErrNotFound)
}

func sessionAddClient(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	in := mkSession("s-1", "u-1")
	in.Clients = nil
	ok(t, s.PutSession(ctx, in))
	ok(t, s.AddSessionClient(ctx, "acme", "s-1", "web"))
	ok(t, s.AddSessionClient(ctx, "acme", "s-1", "web"))
	ok(t, s.AddSessionClient(ctx, "acme", "s-1", "cli"))
	got, err := s.GetSession(ctx, "acme", "s-1")
	ok(t, err)
	eq(t, got.Clients, []string{"web", "cli"})
	is(t, s.AddSessionClient(ctx, "acme", "nope", "web"), idp.ErrNotFound)

	// Concurrent: same and different clients, no duplicates, none lost.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for _, c := range []string{"same", fmt.Sprintf("c-%d", i%10)} {
				if err := s.AddSessionClient(ctx, "acme", "s-1", c); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
	got, err = s.GetSession(ctx, "acme", "s-1")
	ok(t, err)
	want := []string{"cli", "same", "web"}
	for i := 0; i < 10; i++ {
		want = append(want, fmt.Sprintf("c-%d", i))
	}
	have := append([]string(nil), got.Clients...)
	sort.Strings(have)
	sort.Strings(want)
	eq(t, have, want)
}

func sessionList(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	for i, u := range []string{"u-1", "u-2", "u-1", "u-1"} {
		x := mkSession(fmt.Sprintf("s-%d", i), u)
		x.CreatedAt = t0.Add(time.Duration(i) * time.Minute)
		ok(t, s.PutSession(ctx, x))
	}
	ids := func(l []core.Session) []string {
		out := []string{}
		for _, x := range l {
			out = append(out, x.ID)
		}
		return out
	}
	l, err := s.ListSessions(ctx, "acme", "u-1", 10)
	ok(t, err)
	eq(t, ids(l), []string{"s-3", "s-2", "s-0"})
	l, err = s.ListSessions(ctx, "acme", "", 10)
	ok(t, err)
	eq(t, ids(l), []string{"s-3", "s-2", "s-1", "s-0"})
	l, err = s.ListSessions(ctx, "acme", "", 2)
	ok(t, err)
	eq(t, ids(l), []string{"s-3", "s-2"})
	l, err = s.ListSessions(ctx, "acme", "nobody", 10)
	ok(t, err)
	eq(t, len(l), 0)
}

func sessionTakeOnce(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	in := mkSession("s-1", "u-1")
	ok(t, s.PutSession(ctx, in))
	var wins, misses atomic.Int32
	var mu sync.Mutex
	var won core.Session
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x, err := s.TakeSession(ctx, "acme", "s-1")
			switch {
			case err == nil:
				wins.Add(1)
				mu.Lock()
				won = x
				mu.Unlock()
			case errors.Is(err, idp.ErrNotFound):
				misses.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || misses.Load() != 19 {
		t.Fatalf("wins=%d misses=%d, want 1/19", wins.Load(), misses.Load())
	}
	eq(t, won, in)
	_, err := s.GetSession(ctx, "acme", "s-1")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetSessionByCookie(ctx, "acme", "ck-s-1")
	is(t, err, idp.ErrNotFound)
}

func sessionTakeUser(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	for _, p := range [][2]string{{"s-1", "u-1"}, {"s-2", "u-1"}, {"s-3", "u-2"}} {
		ok(t, s.PutSession(ctx, mkSession(p[0], p[1])))
	}
	got, err := s.TakeUserSessions(ctx, "acme", "u-1")
	ok(t, err)
	var ids []string
	for _, x := range got {
		ids = append(ids, x.ID)
		eq(t, x, mkSession(x.ID, "u-1"))
	}
	sort.Strings(ids)
	eq(t, ids, []string{"s-1", "s-2"})
	_, err = s.GetSession(ctx, "acme", "s-3")
	ok(t, err)
	got, err = s.TakeUserSessions(ctx, "acme", "u-1")
	ok(t, err)
	eq(t, len(got), 0)
}

func sessionRevokeRefresh(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	put := func(hash, session, scope string) {
		r := mkRefresh(hash, "fam-"+hash)
		r.SessionID, r.Scope = session, scope
		ok(t, s.PutRefreshToken(ctx, r))
	}
	put("a1", "s-1", "openid")
	put("a2", "s-1", "openid profile")
	put("a3", "s-1", "openid offline_access")
	put("a4", "s-1", "offline_access")
	put("a5", "s-1", "x_offline_accessy")
	put("a6", "s-1", "openid offline_access_not")
	put("a7", "s-1", "")
	put("b1", "s-2", "openid")
	ok(t, s.PutRefreshToken(ctx, mkRefresh("o1", "fam-o1"))) // no session

	n, err := s.RevokeSessionRefreshTokens(ctx, "acme", "s-1")
	ok(t, err)
	eq(t, n, 5)
	revoked := func(h string) bool {
		r, err := s.GetRefreshToken(ctx, h)
		ok(t, err)
		return r.Revoked
	}
	for h, want := range map[string]bool{"a1": true, "a2": true, "a3": false, "a4": false,
		"a5": true, "a6": true, "a7": true, "b1": false, "o1": false} {
		if got := revoked(h); got != want {
			t.Errorf("token %s revoked=%v, want %v", h, got, want)
		}
	}
	n, err = s.RevokeSessionRefreshTokens(ctx, "acme", "s-1")
	ok(t, err)
	eq(t, n, 0)
	// Another realm's lookup of the same session id touches nothing.
	n, err = s.RevokeSessionRefreshTokens(ctx, "other-realm", "s-2")
	ok(t, err)
	eq(t, n, 0)
	if revoked("b1") {
		t.Error("b1 revoked by a call for another realm")
	}
}

func sessionIDRoundtrip(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	c := mkCode("h1")
	c.SessionID = "s-1"
	ok(t, s.PutAuthCode(ctx, c))
	got, err := s.ConsumeAuthCode(ctx, "h1")
	ok(t, err)
	eq(t, got, c)

	r := mkRefresh("r1", "f1")
	r.SessionID = "s-1"
	ok(t, s.PutRefreshToken(ctx, r))
	gr, err := s.GetRefreshToken(ctx, "r1")
	ok(t, err)
	eq(t, gr, r)
}

func sessionDeleteUser(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	ok(t, s.CreateUser(ctx, core.User{ID: "u-1", Realm: "acme", Username: "alice"}))
	ok(t, s.CreateUser(ctx, core.User{ID: "u-2", Realm: "acme", Username: "bob"}))
	ok(t, s.PutSession(ctx, mkSession("s-1", "u-1")))
	ok(t, s.PutSession(ctx, mkSession("s-2", "u-1")))
	ok(t, s.PutSession(ctx, mkSession("s-3", "u-2")))
	ok(t, s.DeleteUser(ctx, "acme", "u-1"))
	l, err := s.ListSessions(ctx, "acme", "", 10)
	ok(t, err)
	if len(l) != 1 || l[0].ID != "s-3" {
		t.Fatalf("sessions after DeleteUser = %+v", l)
	}
	is(t, s.DeleteUser(ctx, "acme", "u-1"), idp.ErrNotFound)
}

func sessionCascade(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "keep")
	ok(t, s.PutSession(ctx, mkSession("s-1", "u-1")))
	k := mkSession("s-2", "u-1")
	k.Realm = "keep"
	ok(t, s.PutSession(ctx, k))
	ok(t, s.DeleteRealm(ctx, "acme"))
	_, err := s.GetSession(ctx, "acme", "s-1")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetSession(ctx, "keep", "s-2")
	ok(t, err)
	// The id and cookie hash are free again once the realm is gone.
	mkRealm(t, s, "acme")
	ok(t, s.PutSession(ctx, mkSession("s-1", "u-1")))
}

func sessionPurge(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	now := t0.Add(time.Hour)
	mk := func(id string, idle, abs time.Time) {
		x := mkSession(id, "u-1")
		x.IdleExpires, x.ExpiresAt = idle, abs
		ok(t, s.PutSession(ctx, x))
	}
	mk("live", now.Add(time.Minute), now.Add(time.Hour))
	mk("abs", now.Add(time.Minute), now)                     // absolute cap reached
	mk("idle", now, now.Add(time.Hour))                      // idle expired
	mk("both", now.Add(-time.Minute), now.Add(-time.Second)) // both
	n, err := s.PurgeExpired(ctx, now)
	ok(t, err)
	eq(t, n, 3)
	l, err := s.ListSessions(ctx, "acme", "", 10)
	ok(t, err)
	if len(l) != 1 || l[0].ID != "live" {
		t.Fatalf("after purge: %+v", l)
	}
	n, err = s.PurgeExpired(ctx, now)
	ok(t, err)
	eq(t, n, 0)
}
