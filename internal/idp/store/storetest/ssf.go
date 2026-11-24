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
		Case{"SSFReceiverLifecycle", ssfReceiverLifecycle},
		Case{"SSFStreamLimitAndOwnership", ssfStreamLimit},
		Case{"SSFStreamsForSubjects", ssfStreamsFor},
		Case{"SSFOutboxClaimLease", ssfOutboxLease},
		Case{"SSFOutboxClaimConcurrent", ssfOutboxConcurrent},
		Case{"SSFOutboxFinishPrune", ssfOutboxFinish},
		Case{"SSFRealmIsolationCascade", ssfIsolation},
	)
}

func ssfStore(t *testing.T, s core.Store) core.SSFStore {
	t.Helper()
	x, found := core.StoreAs[core.SSFStore](s)
	if !found {
		t.Skip("store has no SSFStore")
	}
	return x
}

func ssfRecv(t *testing.T, x core.SSFStore, realm, name, hash string, all bool) core.SSFReceiver {
	t.Helper()
	r, err := x.CreateSSFReceiver(ctx, core.SSFReceiver{Realm: realm, Name: name, Audience: "aud-" + name,
		TokenHash: hash, AllSubjects: all, Events: []string{"e1"}, CreatedAt: t0})
	ok(t, err)
	return r
}

func ssfStream(t *testing.T, x core.SSFStore, r core.SSFReceiver, status string) core.SSFStream {
	t.Helper()
	st, err := x.CreateSSFStream(ctx, core.SSFStream{Realm: r.Realm, ReceiverID: r.ID, Status: status,
		EndpointURL: "https://rx.example/push", SealedAuth: "sealed", EventsRequested: []string{"a"}, EventsDelivered: []string{"a", "b"},
		Description: "d", SubjectFormat: "opaque", CreatedAt: t0, UpdatedAt: t0}, 5)
	ok(t, err)
	return st
}

func ssfReceiverLifecycle(t *testing.T, s core.Store) {
	x := ssfStore(t, s)
	mkRealm(t, s, "acme")
	r := ssfRecv(t, x, "acme", "Okta", "h1", true)
	if r.ID == "" {
		t.Fatal("no id")
	}
	got, err := x.GetSSFReceiver(ctx, "acme", r.ID)
	ok(t, err)
	eq(t, got, r)
	byTok, err := x.GetSSFReceiverByTokenHash(ctx, "h1")
	ok(t, err)
	eq(t, byTok, r)
	_, err = x.GetSSFReceiverByTokenHash(ctx, "")
	is(t, err, idp.ErrNotFound)
	_, err = x.GetSSFReceiverByTokenHash(ctx, "nope")
	is(t, err, idp.ErrNotFound)
	_, err = x.GetSSFReceiver(ctx, "acme", "missing")
	is(t, err, idp.ErrNotFound)

	_, err = x.CreateSSFReceiver(ctx, core.SSFReceiver{Realm: "acme", Name: "okta", Audience: "a", TokenHash: "h2", CreatedAt: t0})
	is(t, err, idp.ErrConflict) // name is case-insensitive
	_, err = x.CreateSSFReceiver(ctx, core.SSFReceiver{Realm: "acme", Name: "other", Audience: "a", TokenHash: "h1", CreatedAt: t0})
	is(t, err, idp.ErrConflict) // token hash unique

	ok(t, x.SetSSFReceiverToken(ctx, "acme", r.ID, "h3"))
	_, err = x.GetSSFReceiverByTokenHash(ctx, "h1")
	is(t, err, idp.ErrNotFound) // old token dead
	r2 := ssfRecv(t, x, "acme", "Two", "h4", false)
	is(t, x.SetSSFReceiverToken(ctx, "acme", r.ID, "h4"), idp.ErrConflict)
	ok(t, x.SetSSFReceiverDisabled(ctx, "acme", r.ID, true))
	got, _ = x.GetSSFReceiver(ctx, "acme", r.ID)
	if !got.Disabled || got.TokenHash != "h3" {
		t.Fatalf("%+v", got)
	}
	list, err := x.ListSSFReceivers(ctx, "acme")
	ok(t, err)
	if len(list) != 2 || list[0].Name != "Okta" || list[1].ID != r2.ID {
		t.Fatalf("%+v", list)
	}
	ok(t, x.DeleteSSFReceiver(ctx, "acme", r.ID))
	is(t, x.DeleteSSFReceiver(ctx, "acme", r.ID), idp.ErrNotFound)
}

func ssfStreamLimit(t *testing.T, s core.Store) {
	x := ssfStore(t, s)
	mkRealm(t, s, "acme")
	r := ssfRecv(t, x, "acme", "a", "h1", true)
	st := ssfStream(t, x, r, core.SSFStatusEnabled)
	if st.Audience != "aud-a" || !st.AllSubjects || st.ReceiverOff || st.SealedAuth != "sealed" {
		t.Fatalf("%+v", st)
	}
	got, err := x.GetSSFStream(ctx, "acme", st.ID)
	ok(t, err)
	eq(t, got, st)

	st.Status, st.EndpointURL, st.UpdatedAt = core.SSFStatusPaused, "https://other.example/x", t0.Add(time.Minute)
	st.EventsDelivered = []string{"z"}
	ok(t, x.UpdateSSFStream(ctx, st))
	got, _ = x.GetSSFStream(ctx, "acme", st.ID)
	if got.Status != "paused" || got.EndpointURL != "https://other.example/x" || len(got.EventsDelivered) != 1 || !got.UpdatedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("%+v", got)
	}
	is(t, x.UpdateSSFStream(ctx, core.SSFStream{Realm: "acme", ID: "missing"}), idp.ErrNotFound)

	for i := 1; i < 5; i++ {
		ssfStream(t, x, r, core.SSFStatusEnabled)
	}
	plain := core.SSFStream{Realm: "acme", ReceiverID: r.ID, Status: "enabled", EndpointURL: "https://x.example", SubjectFormat: "opaque", CreatedAt: t0, UpdatedAt: t0}
	_, err = x.CreateSSFStream(ctx, plain, 5)
	is(t, err, core.ErrSSFStreamLimit)
	plain.ReceiverID = "missing"
	_, err = x.CreateSSFStream(ctx, plain, 5)
	is(t, err, idp.ErrNotFound)
	all, err := x.ListSSFStreams(ctx, "acme", r.ID)
	ok(t, err)
	if len(all) != 5 {
		t.Fatalf("%d", len(all))
	}
	none, _ := x.ListSSFStreams(ctx, "acme", "other")
	if len(none) != 0 {
		t.Fatal("receiver filter")
	}
	ok(t, x.DeleteSSFStream(ctx, "acme", st.ID))
	is(t, x.DeleteSSFStream(ctx, "acme", st.ID), idp.ErrNotFound)

	// Concurrent creates cannot exceed the limit.
	r2 := ssfRecv(t, x, "acme", "b", "h2", false)
	plain.ReceiverID = r2.ID
	var wg sync.WaitGroup
	var okN atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := x.CreateSSFStream(ctx, plain, 5); err == nil {
				okN.Add(1)
			}
		}()
	}
	wg.Wait()
	if okN.Load() != 5 {
		t.Fatalf("created %d streams, want 5", okN.Load())
	}
}

func ssfStreamsFor(t *testing.T, s core.Store) {
	x := ssfStore(t, s)
	mkRealm(t, s, "acme")
	all := ssfRecv(t, x, "acme", "all", "h1", true)
	some := ssfRecv(t, x, "acme", "some", "h2", false)
	sAll := ssfStream(t, x, all, core.SSFStatusEnabled)
	sSome := ssfStream(t, x, some, core.SSFStatusPaused)

	ids := func(user string) map[string]bool {
		l, err := x.SSFStreamsFor(ctx, "acme", user)
		ok(t, err)
		m := map[string]bool{}
		for _, st := range l {
			m[st.ID] = true
		}
		return m
	}
	if m := ids("u1"); len(m) != 1 || !m[sAll.ID] {
		t.Fatalf("before add: %v", m)
	}
	ok(t, x.AddSSFSubject(ctx, "acme", sSome.ID, "u1", t0))
	ok(t, x.AddSSFSubject(ctx, "acme", sSome.ID, "u1", t0)) // idempotent
	if m := ids("u1"); len(m) != 2 || !m[sSome.ID] {        // paused streams are still listed (events are held)
		t.Fatalf("after add: %v", m)
	}
	if m := ids("u2"); len(m) != 1 {
		t.Fatalf("other user: %v", m)
	}
	if m := ids(""); len(m) != 0 {
		t.Fatalf("empty user: %v", m)
	}
	ok(t, x.RemoveSSFSubject(ctx, "acme", sSome.ID, "u1"))
	ok(t, x.RemoveSSFSubject(ctx, "acme", sSome.ID, "u1")) // no-op
	if m := ids("u1"); len(m) != 1 {
		t.Fatalf("after remove: %v", m)
	}
	is(t, x.AddSSFSubject(ctx, "acme", "missing", "u1", t0), idp.ErrNotFound)
	is(t, x.RemoveSSFSubject(ctx, "acme", "missing", "u1"), idp.ErrNotFound)

	// disabled stream and disabled receiver are never returned
	sAll.Status = core.SSFStatusDisabled
	ok(t, x.UpdateSSFStream(ctx, sAll))
	if m := ids("u1"); len(m) != 0 {
		t.Fatalf("disabled stream: %v", m)
	}
	sAll.Status = core.SSFStatusEnabled
	ok(t, x.UpdateSSFStream(ctx, sAll))
	ok(t, x.SetSSFReceiverDisabled(ctx, "acme", all.ID, true))
	if m := ids("u1"); len(m) != 0 {
		t.Fatalf("disabled receiver: %v", m)
	}
	// Stream is deleted: its subjects go with it.
	ok(t, x.AddSSFSubject(ctx, "acme", sSome.ID, "u1", t0))
	ok(t, x.DeleteSSFStream(ctx, "acme", sSome.ID))
	if m := ids("u1"); len(m) != 0 {
		t.Fatalf("deleted stream: %v", m)
	}
}

func ssfRow(stream core.SSFStream, jti string, at time.Time) core.SSFOutbox {
	return core.SSFOutbox{Realm: stream.Realm, StreamID: stream.ID, JTI: jti, EventType: "e", SET: "tok-" + jti, NextAttempt: at, CreatedAt: at}
}

func ssfOutboxLease(t *testing.T, s core.Store) {
	x := ssfStore(t, s)
	mkRealm(t, s, "acme")
	r := ssfRecv(t, x, "acme", "a", "h1", true)
	en := ssfStream(t, x, r, core.SSFStatusEnabled)
	pa := ssfStream(t, x, r, core.SSFStatusPaused)
	ok(t, x.EnqueueSSF(ctx, []core.SSFOutbox{ssfRow(en, "j1", t0), ssfRow(pa, "j2", t0), ssfRow(en, "j3", t0.Add(time.Hour))}))
	is(t, x.EnqueueSSF(ctx, []core.SSFOutbox{ssfRow(core.SSFStream{Realm: "acme", ID: "missing"}, "jx", t0)}), idp.ErrNotFound)

	got, err := x.ClaimSSFOutbox(ctx, t0, time.Minute, 10)
	ok(t, err)
	if len(got) != 1 || got[0].JTI != "j1" || got[0].State != core.SSFOutboxPending || got[0].SET != "tok-j1" {
		t.Fatalf("claim: %+v", got) // paused stream and future row are not claimed
	}
	again, _ := x.ClaimSSFOutbox(ctx, t0.Add(30*time.Second), time.Minute, 10)
	if len(again) != 0 {
		t.Fatalf("leased row claimed twice: %+v", again)
	}
	again, _ = x.ClaimSSFOutbox(ctx, t0.Add(2*time.Minute), time.Minute, 10)
	if len(again) != 1 || again[0].JTI != "j1" {
		t.Fatalf("lease did not expire: %+v", again)
	}
	// resuming the paused stream releases the held event
	pa.Status = core.SSFStatusEnabled
	ok(t, x.UpdateSSFStream(ctx, pa))
	held, _ := x.ClaimSSFOutbox(ctx, t0.Add(2*time.Minute), time.Minute, 10)
	if len(held) != 1 || held[0].JTI != "j2" {
		t.Fatalf("held: %+v", held)
	}
	// a disabled receiver is not delivered to
	ok(t, x.SetSSFReceiverDisabled(ctx, "acme", r.ID, true))
	off, _ := x.ClaimSSFOutbox(ctx, t0.Add(3*time.Hour), time.Minute, 10)
	if len(off) != 0 {
		t.Fatalf("disabled receiver claimed: %+v", off)
	}
}

func ssfOutboxConcurrent(t *testing.T, s core.Store) {
	x := ssfStore(t, s)
	mkRealm(t, s, "acme")
	r := ssfRecv(t, x, "acme", "a", "h1", true)
	st := ssfStream(t, x, r, core.SSFStatusEnabled)
	var rows []core.SSFOutbox
	for i := 0; i < 20; i++ {
		rows = append(rows, ssfRow(st, string(rune('a'+i)), t0))
	}
	ok(t, x.EnqueueSSF(ctx, rows))
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := x.ClaimSSFOutbox(ctx, t0, time.Minute, 7)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			for _, o := range got {
				seen[o.ID]++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("row %s claimed %d times", id, n)
		}
	}
	if len(seen) != 20 {
		t.Fatalf("claimed %d distinct rows, want 20", len(seen))
	}
}

func ssfOutboxFinish(t *testing.T, s core.Store) {
	x := ssfStore(t, s)
	mkRealm(t, s, "acme")
	r := ssfRecv(t, x, "acme", "a", "h1", true)
	st := ssfStream(t, x, r, core.SSFStatusEnabled)
	ok(t, x.EnqueueSSF(ctx, []core.SSFOutbox{ssfRow(st, "j1", t0), ssfRow(st, "j2", t0), ssfRow(st, "j3", t0)}))
	got, _ := x.ClaimSSFOutbox(ctx, t0, time.Minute, 10)
	if len(got) != 3 {
		t.Fatalf("%d", len(got))
	}
	byJTI := map[string]core.SSFOutbox{}
	for _, o := range got {
		byJTI[o.JTI] = o
	}
	ok(t, x.FinishSSFOutbox(ctx, byJTI["j1"].ID, core.SSFOutboxDelivered, time.Time{}, "ok"))
	ok(t, x.FinishSSFOutbox(ctx, byJTI["j2"].ID, core.SSFOutboxDead, time.Time{}, "status_400"))
	ok(t, x.FinishSSFOutbox(ctx, byJTI["j3"].ID, core.SSFOutboxPending, t0.Add(time.Hour), "network_error"))
	is(t, x.FinishSSFOutbox(ctx, "missing", core.SSFOutboxDead, time.Time{}, "x"), idp.ErrNotFound)

	c, err := x.CountSSFOutbox(ctx, "acme")
	ok(t, err)
	eq(t, c, map[string]int{"delivered": 1, "dead": 1, "pending": 1})
	if got, _ := x.ClaimSSFOutbox(ctx, t0.Add(time.Minute*5), time.Minute, 10); len(got) != 0 {
		t.Fatalf("retry not yet due: %+v", got)
	}
	got, _ = x.ClaimSSFOutbox(ctx, t0.Add(time.Hour), time.Minute, 10)
	if len(got) != 1 || got[0].JTI != "j3" || got[0].Attempts != 1 || got[0].LastOutcome != "network_error" {
		t.Fatalf("retry: %+v", got)
	}
	// prune: only rows older than each cutoff
	n, err := x.PruneSSFOutbox(ctx, t0.Add(-time.Second), t0.Add(-time.Second), t0.Add(-time.Second))
	ok(t, err)
	if n != 0 {
		t.Fatalf("pruned %d fresh rows", n)
	}
	n, err = x.PruneSSFOutbox(ctx, t0.Add(time.Second), t0.Add(time.Second), t0.Add(-time.Second))
	ok(t, err)
	if n != 2 { // delivered + dead, not pending
		t.Fatalf("pruned %d, want 2", n)
	}
	c, _ = x.CountSSFOutbox(ctx, "acme")
	eq(t, c, map[string]int{"pending": 1})
}

func ssfIsolation(t *testing.T, s core.Store) {
	x := ssfStore(t, s)
	mkRealm(t, s, "a")
	mkRealm(t, s, "b")
	ra := ssfRecv(t, x, "a", "same", "h1", true)
	rb := ssfRecv(t, x, "b", "same", "h2", true) // same name in another realm is fine
	sa := ssfStream(t, x, ra, core.SSFStatusEnabled)
	_ = ssfStream(t, x, rb, core.SSFStatusEnabled)
	_, err := x.GetSSFStream(ctx, "b", sa.ID)
	is(t, err, idp.ErrNotFound)
	_, err = x.GetSSFReceiver(ctx, "b", ra.ID)
	is(t, err, idp.ErrNotFound)
	l, _ := x.SSFStreamsFor(ctx, "b", "u1")
	if len(l) != 1 || l[0].Realm != "b" {
		t.Fatalf("%+v", l)
	}
	ok(t, x.EnqueueSSF(ctx, []core.SSFOutbox{ssfRow(sa, "j", t0)}))
	cb, _ := x.CountSSFOutbox(ctx, "b")
	if len(cb) != 0 {
		t.Fatalf("outbox leaked across realms: %v", cb)
	}
	// deleting a realm removes everything; a re-created realm starts empty
	ok(t, s.DeleteRealm(ctx, "a"))
	mkRealm(t, s, "a")
	if rs, _ := x.ListSSFReceivers(ctx, "a"); len(rs) != 0 {
		t.Fatalf("receivers survived realm delete: %+v", rs)
	}
	if _, err := x.GetSSFReceiverByTokenHash(ctx, "h1"); err == nil {
		t.Fatal("token of a deleted realm still authenticates")
	}
	if got, _ := x.ClaimSSFOutbox(ctx, t0, time.Minute, 10); len(got) != 0 {
		t.Fatalf("outbox of a deleted realm claimed: %+v", got)
	}
}
