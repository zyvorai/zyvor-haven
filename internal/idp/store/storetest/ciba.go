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
	Register(
		Case{"CIBAClientOptIn", cibaClientOptIn},
		Case{"CIBARoundtripAndConflict", cibaRoundtrip},
		Case{"CIBADecideOnlyAddressee", cibaDecideAddressee},
		Case{"CIBADecideConcurrent", cibaDecideConcurrent},
		Case{"CIBAPollSlowDown", cibaPoll},
		Case{"CIBAConsume", cibaConsume},
		Case{"CIBAConsumeConcurrent", cibaConsumeConcurrent},
		Case{"CIBAPurge", cibaPurge},
	)
}

func cibaStore(t *testing.T, s core.Store) core.CIBAStore {
	t.Helper()
	cs, ok := core.StoreAs[core.CIBAStore](s)
	if !ok {
		t.Skip("store does not implement core.CIBAStore")
	}
	return cs
}

func mkCIBA(n string) core.CIBARequest {
	return core.CIBARequest{
		AuthReqHash: "ar-" + n, ApprovalHash: "ap-" + n, Realm: "acme", ClientID: "agent", UserID: "u-1",
		Scope: "openid profile", Binding: "Pay 5 EUR to Bob", Resources: []string{"https://api.example/a", "https://api.example/b"},
		Status: core.CIBAPending, RequestIP: "203.0.113.9", Interval: 5,
		CreatedAt: t0, ExpiresAt: t0.Add(2 * time.Minute),
	}
}

func cibaClientOptIn(t *testing.T, s core.Store) {
	cs := cibaStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, s.CreateClient(ctx, core.Client{ID: "c-1", Realm: "acme", ClientID: "agent", Enabled: true, CreatedAt: t0}))
	on, err := cs.CIBAClientEnabled(ctx, "acme", "c-1")
	ok(t, err)
	eq(t, on, false) // default off
	is(t, cs.SetCIBAClient(ctx, "acme", "missing", true), idp.ErrNotFound)
	is(t, cs.SetCIBAClient(ctx, "other", "c-1", true), idp.ErrNotFound) // realm scoped
	ok(t, cs.SetCIBAClient(ctx, "acme", "c-1", true))
	on, err = cs.CIBAClientEnabled(ctx, "acme", "c-1")
	ok(t, err)
	eq(t, on, true)
	on, err = cs.CIBAClientEnabled(ctx, "other", "c-1")
	ok(t, err)
	eq(t, on, false)
	ok(t, cs.SetCIBAClient(ctx, "acme", "c-1", false))
	on, err = cs.CIBAClientEnabled(ctx, "acme", "c-1")
	ok(t, err)
	eq(t, on, false)
}

func cibaRoundtrip(t *testing.T, s core.Store) {
	cs := cibaStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	in := mkCIBA("1")
	ok(t, cs.PutCIBARequest(ctx, in))
	got, err := cs.GetCIBAByApproval(ctx, "acme", "ap-1")
	ok(t, err)
	eq(t, got, in)
	_, err = cs.GetCIBAByApproval(ctx, "other", "ap-1") // realm scoped
	is(t, err, idp.ErrNotFound)
	_, err = cs.GetCIBAByApproval(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)

	is(t, cs.PutCIBARequest(ctx, mkCIBA("1")), idp.ErrConflict) // same auth_req hash
	dup := mkCIBA("2")
	dup.ApprovalHash = "ap-1"
	is(t, cs.PutCIBARequest(ctx, dup), idp.ErrConflict) // same approval hash, same realm
	o := mkCIBA("3")
	o.ApprovalHash, o.Realm = "ap-1", "other"
	ok(t, cs.PutCIBARequest(ctx, o))

	// No resources round-trips as empty, an unresolved user as "".
	bare := mkCIBA("4")
	bare.Resources, bare.UserID = nil, ""
	ok(t, cs.PutCIBARequest(ctx, bare))
	got, err = cs.GetCIBAByApproval(ctx, "acme", "ap-4")
	ok(t, err)
	eq(t, len(got.Resources), 0)
	eq(t, got.UserID, "")
}

func cibaDecideAddressee(t *testing.T, s core.Store) {
	cs := cibaStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	for _, n := range []string{"1", "2", "3", "4"} {
		ok(t, cs.PutCIBARequest(ctx, mkCIBA(n)))
	}
	unresolved := mkCIBA("5")
	unresolved.UserID = ""
	ok(t, cs.PutCIBARequest(ctx, unresolved))
	now := t0.Add(time.Minute)
	app := core.CIBADecision{Approve: true, SessionID: "s-1", AuthTime: t0.Add(-time.Minute)}

	// Other realm, another user, empty user: none may decide, none burn it.
	_, err := cs.DecideCIBA(ctx, "other", "ap-1", "u-1", now, app)
	is(t, err, idp.ErrNotFound)
	_, err = cs.DecideCIBA(ctx, "acme", "ap-1", "u-2", now, app)
	is(t, err, idp.ErrNotFound)
	_, err = cs.DecideCIBA(ctx, "acme", "ap-1", "", now, app)
	is(t, err, idp.ErrNotFound)
	// An unresolved request is never decidable, even by a user named "".
	_, err = cs.DecideCIBA(ctx, "acme", "ap-5", "", now, app)
	is(t, err, idp.ErrNotFound)
	_, err = cs.DecideCIBA(ctx, "acme", "ap-5", "u-1", now, app)
	is(t, err, idp.ErrNotFound)

	got, err := cs.DecideCIBA(ctx, "acme", "ap-1", "u-1", now, app)
	ok(t, err)
	eq(t, got.Status, core.CIBAApproved)
	eq(t, got.SessionID, "s-1")
	eq(t, got.UserID, "u-1")
	if !got.AuthTime.Equal(app.AuthTime) {
		t.Fatalf("AuthTime %v", got.AuthTime)
	}
	// Decided once, either way.
	_, err = cs.DecideCIBA(ctx, "acme", "ap-1", "u-1", now, core.CIBADecision{})
	is(t, err, idp.ErrNotFound)
	got, err = cs.DecideCIBA(ctx, "acme", "ap-2", "u-1", now, core.CIBADecision{SessionID: "ignored"})
	ok(t, err)
	eq(t, got.Status, core.CIBADenied)
	eq(t, got.SessionID, "")
	_, err = cs.DecideCIBA(ctx, "acme", "ap-2", "u-1", now, app)
	is(t, err, idp.ErrNotFound)
	// Expiry itself is expired.
	_, err = cs.DecideCIBA(ctx, "acme", "ap-3", "u-1", t0.Add(2*time.Minute), app)
	is(t, err, idp.ErrNotFound)
	_, err = cs.DecideCIBA(ctx, "acme", "missing", "u-1", now, app)
	is(t, err, idp.ErrNotFound)
}

func cibaDecideConcurrent(t *testing.T, s core.Store) {
	cs := cibaStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, cs.PutCIBARequest(ctx, mkCIBA("1")))
	var wins, approves atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := core.CIBADecision{Approve: i%2 == 0, SessionID: "s"}
			if _, err := cs.DecideCIBA(ctx, "acme", "ap-1", "u-1", t0.Add(time.Second), d); err == nil {
				wins.Add(1)
				if d.Approve {
					approves.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	eq(t, wins.Load(), int32(1))
	got, err := cs.GetCIBAByApproval(ctx, "acme", "ap-1")
	ok(t, err)
	want := core.CIBADenied
	if approves.Load() == 1 {
		want = core.CIBAApproved
	}
	eq(t, got.Status, want)
}

func cibaPoll(t *testing.T, s core.Store) {
	cs := cibaStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, cs.PutCIBARequest(ctx, mkCIBA("1")))
	_, _, err := cs.PollCIBA(ctx, "acme", "someone-else", "ar-1", t0)
	is(t, err, idp.ErrNotFound)
	_, _, err = cs.PollCIBA(ctx, "other", "agent", "ar-1", t0)
	is(t, err, idp.ErrNotFound)
	_, _, err = cs.PollCIBA(ctx, "acme", "agent", "nope", t0)
	is(t, err, idp.ErrNotFound)

	d, fast, err := cs.PollCIBA(ctx, "acme", "agent", "ar-1", t0.Add(time.Second))
	ok(t, err)
	eq(t, fast, false)
	eq(t, d.Interval, 5)
	d, fast, err = cs.PollCIBA(ctx, "acme", "agent", "ar-1", t0.Add(3*time.Second))
	ok(t, err)
	eq(t, fast, true)
	eq(t, d.Interval, 10)
	d, fast, err = cs.PollCIBA(ctx, "acme", "agent", "ar-1", t0.Add(12*time.Second))
	ok(t, err)
	eq(t, fast, true)
	eq(t, d.Interval, 15)
	d, fast, err = cs.PollCIBA(ctx, "acme", "agent", "ar-1", t0.Add(27*time.Second))
	ok(t, err)
	eq(t, fast, false)
	eq(t, d.Interval, 15)
	now := t0.Add(27 * time.Second)
	for i := 0; i < 100; i++ {
		d, _, err = cs.PollCIBA(ctx, "acme", "agent", "ar-1", now)
		ok(t, err)
	}
	eq(t, d.Interval, core.CIBAMaxInterval)
}

func cibaConsume(t *testing.T, s core.Store) {
	cs := cibaStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, cs.PutCIBARequest(ctx, mkCIBA("1")))
	now := t0.Add(time.Minute)
	_, err := cs.ConsumeCIBA(ctx, "acme", "agent", "ar-1", now) // pending
	is(t, err, idp.ErrNotFound)
	_, err = cs.DecideCIBA(ctx, "acme", "ap-1", "u-1", now, core.CIBADecision{Approve: true, SessionID: "s-1", AuthTime: t0})
	ok(t, err)
	_, err = cs.ConsumeCIBA(ctx, "acme", "other-client", "ar-1", now)
	is(t, err, idp.ErrNotFound)
	_, err = cs.ConsumeCIBA(ctx, "other", "agent", "ar-1", now)
	is(t, err, idp.ErrNotFound)
	got, err := cs.ConsumeCIBA(ctx, "acme", "agent", "ar-1", now)
	ok(t, err)
	eq(t, got.UserID, "u-1")
	eq(t, got.SessionID, "s-1")
	eq(t, got.Binding, "Pay 5 EUR to Bob")
	_, err = cs.ConsumeCIBA(ctx, "acme", "agent", "ar-1", now) // single use
	is(t, err, idp.ErrNotFound)

	ok(t, cs.PutCIBARequest(ctx, mkCIBA("2")))
	_, err = cs.DecideCIBA(ctx, "acme", "ap-2", "u-1", now, core.CIBADecision{})
	ok(t, err)
	_, err = cs.ConsumeCIBA(ctx, "acme", "agent", "ar-2", now) // denied
	is(t, err, idp.ErrNotFound)
	ok(t, cs.PutCIBARequest(ctx, mkCIBA("3")))
	_, err = cs.DecideCIBA(ctx, "acme", "ap-3", "u-1", now, core.CIBADecision{Approve: true, SessionID: "s"})
	ok(t, err)
	_, err = cs.ConsumeCIBA(ctx, "acme", "agent", "ar-3", t0.Add(2*time.Minute)) // expired
	is(t, err, idp.ErrNotFound)
}

func cibaConsumeConcurrent(t *testing.T, s core.Store) {
	cs := cibaStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, cs.PutCIBARequest(ctx, mkCIBA("1")))
	_, err := cs.DecideCIBA(ctx, "acme", "ap-1", "u-1", t0, core.CIBADecision{Approve: true, SessionID: "s"})
	ok(t, err)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cs.ConsumeCIBA(ctx, "acme", "agent", "ar-1", t0.Add(time.Second)); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	eq(t, wins.Load(), int32(1))
}

func cibaPurge(t *testing.T, s core.Store) {
	cs := cibaStore(t, s)
	mkRealm(t, s, "acme")
	old, fresh := mkCIBA("1"), mkCIBA("2")
	fresh.ExpiresAt = t0.Add(time.Hour)
	ok(t, cs.PutCIBARequest(ctx, old))
	ok(t, cs.PutCIBARequest(ctx, fresh))
	n, err := cs.PurgeExpiredCIBA(ctx, t0.Add(time.Minute))
	ok(t, err)
	eq(t, n, 0)
	n, err = cs.PurgeExpiredCIBA(ctx, t0.Add(2*time.Minute))
	ok(t, err)
	eq(t, n, 1)
	_, err = cs.GetCIBAByApproval(ctx, "acme", "ap-1")
	is(t, err, idp.ErrNotFound)
	_, err = cs.GetCIBAByApproval(ctx, "acme", "ap-2")
	ok(t, err)
}
