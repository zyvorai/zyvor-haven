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
		Case{"DeviceFlowClientRoundtrip", deviceClientRoundtrip},
		Case{"DeviceCodeRoundtrip", deviceRoundtrip},
		Case{"DeviceCodeConflict", deviceConflict},
		Case{"DeviceCodeDecideOnce", deviceDecideOnce},
		Case{"DeviceCodeDecideConcurrent", deviceDecideConcurrent},
		Case{"DeviceCodePollSlowDown", devicePoll},
		Case{"DeviceCodeConsume", deviceConsume},
		Case{"DeviceCodeConsumeConcurrent", deviceConsumeConcurrent},
		Case{"DeviceCodePurge", devicePurge},
	)
}

func deviceStore(t *testing.T, s core.Store) core.DeviceStore {
	t.Helper()
	ds, ok := core.StoreAs[core.DeviceStore](s)
	if !ok {
		t.Skip("store does not implement core.DeviceStore")
	}
	return ds
}

func mkDevice(n string) core.DeviceCode {
	return core.DeviceCode{
		DeviceCodeHash: "dev-" + n, UserCodeHash: "usr-" + n, Realm: "acme", ClientID: "cli", Scope: "openid profile",
		Status: core.DevicePending, RequestIP: "203.0.113.9", RequestUA: "haven-cli/1.0", Interval: 5,
		CreatedAt: t0, ExpiresAt: t0.Add(10 * time.Minute),
	}
}

func deviceClientRoundtrip(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	in := core.Client{ID: "c-dev", Realm: "acme", ClientID: "cli", Name: "CLI", Enabled: true, Public: true,
		DeviceFlow: true, CreatedAt: t0}
	ok(t, s.CreateClient(ctx, in))
	got, err := s.GetClientByClientID(ctx, "acme", "cli")
	ok(t, err)
	eq(t, got, in)
	other := core.Client{ID: "c-plain", Realm: "acme", ClientID: "plain", CreatedAt: t0}
	ok(t, s.CreateClient(ctx, other))
	got, err = s.GetClient(ctx, "acme", "c-plain")
	ok(t, err)
	eq(t, got.DeviceFlow, false)

	up := in
	up.DeviceFlow = false
	ok(t, s.UpdateClient(ctx, up))
	got, err = s.GetClient(ctx, "acme", "c-dev")
	ok(t, err)
	eq(t, got.DeviceFlow, false)
	up.DeviceFlow = true
	ok(t, s.UpdateClient(ctx, up))
	l, err := s.ListClients(ctx, "acme")
	ok(t, err)
	n := 0
	for _, c := range l {
		if c.DeviceFlow {
			n++
		}
	}
	eq(t, n, 1)
}

func deviceRoundtrip(t *testing.T, s core.Store) {
	ds := deviceStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	in := mkDevice("1")
	ok(t, ds.PutDeviceCode(ctx, in))
	got, err := ds.GetDeviceCodeByUserCode(ctx, "acme", "usr-1")
	ok(t, err)
	eq(t, got, in)
	_, err = ds.GetDeviceCodeByUserCode(ctx, "other", "usr-1") // realm scoped
	is(t, err, idp.ErrNotFound)
	_, err = ds.GetDeviceCodeByUserCode(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)
}

func deviceConflict(t *testing.T, s core.Store) {
	ds := deviceStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, ds.PutDeviceCode(ctx, mkDevice("1")))
	is(t, ds.PutDeviceCode(ctx, mkDevice("1")), idp.ErrConflict) // same device hash
	dupUser := mkDevice("2")
	dupUser.UserCodeHash = "usr-1"
	is(t, ds.PutDeviceCode(ctx, dupUser), idp.ErrConflict) // same user code, same realm
	otherRealm := mkDevice("3")
	otherRealm.UserCodeHash, otherRealm.Realm = "usr-1", "other"
	ok(t, ds.PutDeviceCode(ctx, otherRealm)) // same user code in another realm is fine
}

func deviceDecideOnce(t *testing.T, s core.Store) {
	ds := deviceStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, ds.PutDeviceCode(ctx, mkDevice("1")))
	ok(t, ds.PutDeviceCode(ctx, mkDevice("2")))
	ok(t, ds.PutDeviceCode(ctx, mkDevice("3")))
	now := t0.Add(time.Minute)

	// Wrong realm cannot decide.
	_, err := ds.DecideDeviceCode(ctx, "other", "usr-1", now, core.DeviceDecision{Approve: true, UserID: "u"})
	is(t, err, idp.ErrNotFound)

	auth := t0.Add(-time.Hour)
	got, err := ds.DecideDeviceCode(ctx, "acme", "usr-1", now, core.DeviceDecision{Approve: true, UserID: "u-1", SessionID: "s-1", AuthTime: auth})
	ok(t, err)
	eq(t, got.Status, core.DeviceApproved)
	eq(t, got.UserID, "u-1")
	eq(t, got.SessionID, "s-1")
	if !got.AuthTime.Equal(auth) {
		t.Fatalf("AuthTime %v", got.AuthTime)
	}
	stored, err := ds.GetDeviceCodeByUserCode(ctx, "acme", "usr-1")
	ok(t, err)
	eq(t, stored, got)

	// An approved code cannot be decided again, either way.
	_, err = ds.DecideDeviceCode(ctx, "acme", "usr-1", now, core.DeviceDecision{})
	is(t, err, idp.ErrNotFound)
	_, err = ds.DecideDeviceCode(ctx, "acme", "usr-1", now, core.DeviceDecision{Approve: true, UserID: "u-2"})
	is(t, err, idp.ErrNotFound)

	// Denied likewise, and a denial records no user.
	got, err = ds.DecideDeviceCode(ctx, "acme", "usr-2", now, core.DeviceDecision{UserID: "ignored"})
	ok(t, err)
	eq(t, got.Status, core.DeviceDenied)
	eq(t, got.UserID, "")
	_, err = ds.DecideDeviceCode(ctx, "acme", "usr-2", now, core.DeviceDecision{Approve: true, UserID: "u-1"})
	is(t, err, idp.ErrNotFound)

	// Expired codes cannot be decided (boundary: expires_at itself is expired).
	_, err = ds.DecideDeviceCode(ctx, "acme", "usr-3", t0.Add(10*time.Minute), core.DeviceDecision{Approve: true, UserID: "u-1"})
	is(t, err, idp.ErrNotFound)
	_, err = ds.DecideDeviceCode(ctx, "acme", "missing", now, core.DeviceDecision{})
	is(t, err, idp.ErrNotFound)
}

func deviceDecideConcurrent(t *testing.T, s core.Store) {
	ds := deviceStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, ds.PutDeviceCode(ctx, mkDevice("1")))
	const n = 16
	var wins, approves atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := core.DeviceDecision{Approve: i%2 == 0, UserID: "u", SessionID: "s"}
			if _, err := ds.DecideDeviceCode(ctx, "acme", "usr-1", t0.Add(time.Second), d); err == nil {
				wins.Add(1)
				if d.Approve {
					approves.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	eq(t, wins.Load(), int32(1))
	got, err := ds.GetDeviceCodeByUserCode(ctx, "acme", "usr-1")
	ok(t, err)
	want := core.DeviceDenied
	if approves.Load() == 1 {
		want = core.DeviceApproved
	}
	eq(t, got.Status, want)
}

func devicePoll(t *testing.T, s core.Store) {
	ds := deviceStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, ds.PutDeviceCode(ctx, mkDevice("1")))

	// Ownership: the right (realm, client) only.
	_, _, err := ds.PollDeviceCode(ctx, "acme", "someone-else", "dev-1", t0)
	is(t, err, idp.ErrNotFound)
	_, _, err = ds.PollDeviceCode(ctx, "other", "cli", "dev-1", t0)
	is(t, err, idp.ErrNotFound)
	_, _, err = ds.PollDeviceCode(ctx, "acme", "cli", "nope", t0)
	is(t, err, idp.ErrNotFound)

	// First poll is free; a failed ownership check must not have recorded one.
	d, fast, err := ds.PollDeviceCode(ctx, "acme", "cli", "dev-1", t0.Add(time.Second))
	ok(t, err)
	eq(t, fast, false)
	eq(t, d.Interval, 5)
	// Too fast: 2s later with interval 5 -> slow_down, interval 10.
	d, fast, err = ds.PollDeviceCode(ctx, "acme", "cli", "dev-1", t0.Add(3*time.Second))
	ok(t, err)
	eq(t, fast, true)
	eq(t, d.Interval, 10)
	// LastPoll moved to the too-fast poll: 9s after it is still too fast (10s interval)...
	d, fast, err = ds.PollDeviceCode(ctx, "acme", "cli", "dev-1", t0.Add(12*time.Second))
	ok(t, err)
	eq(t, fast, true)
	eq(t, d.Interval, 15)
	// ...and exactly interval later is fine, with the interval kept.
	d, fast, err = ds.PollDeviceCode(ctx, "acme", "cli", "dev-1", t0.Add(27*time.Second))
	ok(t, err)
	eq(t, fast, false)
	eq(t, d.Interval, 15)
	if !d.LastPoll.Equal(t0.Add(27 * time.Second)) {
		t.Fatalf("LastPoll %v", d.LastPoll)
	}
	// The interval is capped.
	now := t0.Add(27 * time.Second)
	for i := 0; i < 100; i++ {
		d, _, err = ds.PollDeviceCode(ctx, "acme", "cli", "dev-1", now)
		ok(t, err)
	}
	eq(t, d.Interval, core.DeviceMaxInterval)
}

func deviceConsume(t *testing.T, s core.Store) {
	ds := deviceStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, ds.PutDeviceCode(ctx, mkDevice("1")))
	now := t0.Add(time.Minute)

	// Pending cannot be consumed.
	_, err := ds.ConsumeDeviceCode(ctx, "acme", "cli", "dev-1", now)
	is(t, err, idp.ErrNotFound)
	_, err = ds.DecideDeviceCode(ctx, "acme", "usr-1", now, core.DeviceDecision{Approve: true, UserID: "u-1", SessionID: "s-1", AuthTime: t0})
	ok(t, err)
	// Wrong client / realm cannot consume, and does not burn the code.
	_, err = ds.ConsumeDeviceCode(ctx, "acme", "other-client", "dev-1", now)
	is(t, err, idp.ErrNotFound)
	_, err = ds.ConsumeDeviceCode(ctx, "other", "cli", "dev-1", now)
	is(t, err, idp.ErrNotFound)
	got, err := ds.ConsumeDeviceCode(ctx, "acme", "cli", "dev-1", now)
	ok(t, err)
	eq(t, got.UserID, "u-1")
	eq(t, got.SessionID, "s-1")
	eq(t, got.Scope, "openid profile")
	_, err = ds.ConsumeDeviceCode(ctx, "acme", "cli", "dev-1", now) // single use
	is(t, err, idp.ErrNotFound)
	_, err = ds.GetDeviceCodeByUserCode(ctx, "acme", "usr-1")
	is(t, err, idp.ErrNotFound)

	// Denied and expired codes cannot be consumed.
	ok(t, ds.PutDeviceCode(ctx, mkDevice("2")))
	_, err = ds.DecideDeviceCode(ctx, "acme", "usr-2", now, core.DeviceDecision{})
	ok(t, err)
	_, err = ds.ConsumeDeviceCode(ctx, "acme", "cli", "dev-2", now)
	is(t, err, idp.ErrNotFound)
	ok(t, ds.PutDeviceCode(ctx, mkDevice("3")))
	_, err = ds.DecideDeviceCode(ctx, "acme", "usr-3", now, core.DeviceDecision{Approve: true, UserID: "u"})
	ok(t, err)
	_, err = ds.ConsumeDeviceCode(ctx, "acme", "cli", "dev-3", t0.Add(10*time.Minute))
	is(t, err, idp.ErrNotFound)
}

func deviceConsumeConcurrent(t *testing.T, s core.Store) {
	ds := deviceStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, ds.PutDeviceCode(ctx, mkDevice("1")))
	_, err := ds.DecideDeviceCode(ctx, "acme", "usr-1", t0, core.DeviceDecision{Approve: true, UserID: "u", SessionID: "s"})
	ok(t, err)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ds.ConsumeDeviceCode(ctx, "acme", "cli", "dev-1", t0.Add(time.Second)); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	eq(t, wins.Load(), int32(1))
}

func devicePurge(t *testing.T, s core.Store) {
	ds := deviceStore(t, s)
	mkRealm(t, s, "acme")
	old, fresh := mkDevice("1"), mkDevice("2")
	fresh.ExpiresAt = t0.Add(time.Hour)
	ok(t, ds.PutDeviceCode(ctx, old))
	ok(t, ds.PutDeviceCode(ctx, fresh))
	n, err := ds.PurgeExpiredDeviceCodes(ctx, t0.Add(9*time.Minute))
	ok(t, err)
	eq(t, n, 0)
	n, err = ds.PurgeExpiredDeviceCodes(ctx, t0.Add(10*time.Minute)) // expiry itself counts as expired
	ok(t, err)
	eq(t, n, 1)
	_, err = ds.GetDeviceCodeByUserCode(ctx, "acme", "usr-1")
	is(t, err, idp.ErrNotFound)
	_, err = ds.GetDeviceCodeByUserCode(ctx, "acme", "usr-2")
	ok(t, err)
}
