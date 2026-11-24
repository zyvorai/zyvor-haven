// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	cases := []Case{
		{"GrantLifecycle", grantLifecycle},
		{"GrantExpiryBoundary", grantBoundary},
		{"GrantLimitConcurrent", grantLimitConcurrent},
		{"GrantRealmIsolation", grantIsolation},
		{"GrantPurgeRetention", grantPurge},
		{"GrantPolicy", grantPolicy},
	}
	Register(cases...)
}

func grantStore(t *testing.T, s core.Store) core.GrantStore {
	t.Helper()
	gs, found := core.StoreAs[core.GrantStore](s)
	if !found {
		t.Skip("store has no GrantStore")
	}
	return gs
}

func mkGrant(user, role string, ttl time.Duration) core.RoleGrant {
	return core.RoleGrant{Realm: "acme", UserID: user, Role: role, GrantedBy: "client:haven-admin",
		Reason: "on-call", ExpiresAt: t0.Add(ttl)}
}

func grantLifecycle(t *testing.T, s core.Store) {
	gs := grantStore(t, s)
	mkRealm(t, s, "acme")
	g, err := gs.CreateRoleGrant(ctx, mkGrant("u1", "ops", time.Hour), 20, t0)
	ok(t, err)
	if g.ID == "" || !g.CreatedAt.Equal(t0) || !g.RevokedAt.IsZero() {
		t.Fatalf("created: %+v", g)
	}
	_, err = gs.CreateRoleGrant(ctx, mkGrant("u1", "ops", 2*time.Hour), 20, t0) // second grant, same role
	ok(t, err)
	_, err = gs.CreateRoleGrant(ctx, mkGrant("u1", "dba", time.Hour), 20, t0)
	ok(t, err)
	roles, err := gs.ActiveRoles(ctx, "acme", "u1", t0.Add(time.Minute))
	ok(t, err)
	eq(t, roles, []string{"dba", "ops"})

	got, err := gs.ListRoleGrants(ctx, "acme", "u1", true, t0, 0)
	ok(t, err)
	if len(got) != 3 {
		t.Fatalf("list: %+v", got)
	}
	var found core.RoleGrant
	for _, x := range got {
		if x.ID == g.ID {
			found = x
		}
	}
	eq(t, found, g)

	rv, err := gs.RevokeRoleGrant(ctx, "acme", "u1", g.ID, "user:admin", t0.Add(time.Minute))
	ok(t, err)
	if !rv.RevokedAt.Equal(t0.Add(time.Minute)) || rv.RevokedBy != "user:admin" {
		t.Fatalf("revoked: %+v", rv)
	}
	is(t, func() error {
		_, e := gs.RevokeRoleGrant(ctx, "acme", "u1", g.ID, "x", t0.Add(2*time.Minute))
		return e
	}(), idp.ErrConflict)
	is(t, func() error { _, e := gs.RevokeRoleGrant(ctx, "acme", "u2", g.ID, "x", t0); return e }(), idp.ErrNotFound)
	is(t, func() error { _, e := gs.RevokeRoleGrant(ctx, "acme", "u1", "nope", "x", t0); return e }(), idp.ErrNotFound)
	act, _ := gs.ListRoleGrants(ctx, "acme", "u1", true, t0.Add(2*time.Minute), 0)
	all, _ := gs.ListRoleGrants(ctx, "acme", "u1", false, t0.Add(2*time.Minute), 0)
	if len(act) != 2 || len(all) != 3 {
		t.Fatalf("active %d all %d", len(act), len(all))
	}
	// A grant that has expired cannot be revoked (conflict) and is not effective.
	is(t, func() error {
		_, e := gs.RevokeRoleGrant(ctx, "acme", "u1", found.ID, "x", t0.Add(3*time.Hour))
		return e
	}(), idp.ErrConflict)

	_, err = gs.CreateRoleGrant(ctx, core.RoleGrant{Realm: "ghost", UserID: "u1", Role: "ops", ExpiresAt: t0.Add(time.Hour)}, 20, t0)
	is(t, err, idp.ErrNotFound)
}

func grantBoundary(t *testing.T, s core.Store) {
	gs := grantStore(t, s)
	mkRealm(t, s, "acme")
	_, err := gs.CreateRoleGrant(ctx, mkGrant("u1", "ops", 2*time.Minute), 20, t0)
	ok(t, err)
	for _, c := range []struct {
		at   time.Duration
		want int
	}{{0, 1}, {2*time.Minute - time.Second, 1}, {2 * time.Minute, 0}, {2*time.Minute + time.Second, 0}} {
		r, err := gs.ActiveRoles(ctx, "acme", "u1", t0.Add(c.at))
		ok(t, err)
		l, _ := gs.ListRoleGrants(ctx, "acme", "u1", true, t0.Add(c.at), 0)
		if len(r) != c.want || len(l) != c.want {
			t.Fatalf("at +%v: roles %v list %d, want %d", c.at, r, len(l), c.want)
		}
	}
}

func grantLimitConcurrent(t *testing.T, s core.Store) {
	gs := grantStore(t, s)
	mkRealm(t, s, "acme")
	var okN, lim atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := gs.CreateRoleGrant(ctx, mkGrant("u1", "ops", time.Hour), 20, t0)
			switch {
			case err == nil:
				okN.Add(1)
			case err == core.ErrGrantLimit:
				lim.Add(1)
			default:
				t.Errorf("create: %v", err)
			}
		}()
	}
	wg.Wait()
	if okN.Load() != 20 || lim.Load() != 20 {
		t.Fatalf("created %d limited %d, want 20/20", okN.Load(), lim.Load())
	}
	// Another user is not affected; expired grants do not count.
	_, err := gs.CreateRoleGrant(ctx, mkGrant("u2", "ops", time.Hour), 20, t0)
	ok(t, err)
	_, err = gs.CreateRoleGrant(ctx, mkGrant("u1", "ops", time.Hour), 20, t0.Add(2*time.Hour))
	ok(t, err)
}

func grantIsolation(t *testing.T, s core.Store) {
	gs := grantStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	g, err := gs.CreateRoleGrant(ctx, mkGrant("u1", "ops", time.Hour), 20, t0)
	ok(t, err)
	r, err := gs.ActiveRoles(ctx, "other", "u1", t0)
	ok(t, err)
	l, _ := gs.ListRoleGrants(ctx, "other", "", false, t0, 0)
	if len(r) != 0 || len(l) != 0 {
		t.Fatalf("leak: %v %v", r, l)
	}
	_, err = gs.RevokeRoleGrant(ctx, "other", "u1", g.ID, "x", t0)
	is(t, err, idp.ErrNotFound)
	ok(t, gs.PutGrantPolicy(ctx, "acme", core.GrantPolicy{MaxDurationSeconds: 60, RequireReason: false, AllowedRoles: []string{"ops"}}))
	p, err := gs.GetGrantPolicy(ctx, "other")
	ok(t, err)
	eq(t, p, core.DefaultGrantPolicy())

	// Deleting the realm removes its grants and policy (a re-created realm starts clean).
	ok(t, s.DeleteRealm(ctx, "acme"))
	mkRealm(t, s, "acme")
	l, _ = gs.ListRoleGrants(ctx, "acme", "", false, t0, 0)
	p, _ = gs.GetGrantPolicy(ctx, "acme")
	if len(l) != 0 {
		t.Fatalf("grants survived realm delete: %+v", l)
	}
	eq(t, p, core.DefaultGrantPolicy())
}

func grantPurge(t *testing.T, s core.Store) {
	gs := grantStore(t, s)
	mkRealm(t, s, "acme")
	exp, _ := gs.CreateRoleGrant(ctx, mkGrant("u1", "ops", time.Hour), 20, t0)
	rev, _ := gs.CreateRoleGrant(ctx, mkGrant("u1", "dba", 100*time.Hour), 20, t0)
	_, err := gs.RevokeRoleGrant(ctx, "acme", "u1", rev.ID, "a", t0.Add(time.Minute))
	ok(t, err)
	live, _ := gs.CreateRoleGrant(ctx, mkGrant("u1", "qa", 10000*time.Hour), 20, t0)

	// Before expiry nothing is reported.
	res, err := gs.PurgeExpiredGrants(ctx, t0.Add(30*time.Minute))
	ok(t, err)
	if len(res.Expired) != 0 || res.Deleted != 0 {
		t.Fatalf("early purge: %+v", res)
	}
	// After expiry: reported once, kept (audit) and still not effective.
	at := t0.Add(2 * time.Hour)
	res, err = gs.PurgeExpiredGrants(ctx, at)
	ok(t, err)
	if len(res.Expired) != 1 || res.Expired[0].ID != exp.ID || res.Deleted != 0 {
		t.Fatalf("first purge: %+v", res)
	}
	res, _ = gs.PurgeExpiredGrants(ctx, at.Add(time.Minute))
	if len(res.Expired) != 0 {
		t.Fatalf("reported twice: %+v", res)
	}
	all, _ := gs.ListRoleGrants(ctx, "acme", "", false, at, 0)
	if len(all) != 3 {
		t.Fatalf("rows kept for audit: %d", len(all))
	}
	// Past retention the ended rows go; the live one stays.
	res, err = gs.PurgeExpiredGrants(ctx, t0.Add(core.GrantRetention+2*time.Hour))
	ok(t, err)
	if res.Deleted != 2 { // the expired one (ended +1h) and the revoked one (ended +1m)
		t.Fatalf("deleted %d, want 2", res.Deleted)
	}
	rest, _ := gs.ListRoleGrants(ctx, "acme", "", false, t0.Add(core.GrantRetention+2*time.Hour), 0)
	if len(rest) != 1 || rest[0].ID != live.ID {
		t.Fatalf("rest: %+v", rest)
	}
}

func grantPolicy(t *testing.T, s core.Store) {
	gs := grantStore(t, s)
	mkRealm(t, s, "acme")
	p, err := gs.GetGrantPolicy(ctx, "acme")
	ok(t, err)
	eq(t, p, core.DefaultGrantPolicy())
	in := core.GrantPolicy{MaxDurationSeconds: 900, RequireReason: false, AllowedRoles: []string{"ops", "dba"}}
	ok(t, gs.PutGrantPolicy(ctx, "acme", in))
	p, _ = gs.GetGrantPolicy(ctx, "acme")
	eq(t, p, in)
	in.AllowedRoles = nil
	ok(t, gs.PutGrantPolicy(ctx, "acme", in))
	p, _ = gs.GetGrantPolicy(ctx, "acme")
	if len(p.AllowedRoles) != 0 || p.MaxDurationSeconds != 900 {
		t.Fatalf("updated: %+v", p)
	}
	is(t, gs.PutGrantPolicy(ctx, "ghost", in), idp.ErrNotFound)
	_, err = gs.GetGrantPolicy(ctx, "ghost")
	is(t, err, idp.ErrNotFound)
}
