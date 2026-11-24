// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"StepUpPolicyRoundtrip", stepUpPolicy},
		Case{"StepUpDevices", stepUpDevices},
		Case{"StepUpDevicePruneAndIsolation", stepUpDevicePrune},
		Case{"StepUpDeviceConcurrentPrune", stepUpDeviceConcurrent},
		Case{"StepUpCascade", stepUpCascade},
	)
}

func stepUpStore(t *testing.T, s core.Store) core.StepUpStore {
	t.Helper()
	m, found := core.StoreAs[core.StepUpStore](s)
	if !found {
		t.Skip("store does not implement core.StepUpStore")
	}
	return m
}

func suUser(t *testing.T, s core.Store, realm, id string) {
	t.Helper()
	ok(t, s.CreateUser(ctx, core.User{ID: id, Realm: realm, Username: id}))
}

func stepUpPolicy(t *testing.T, s core.Store) {
	m := stepUpStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	got, err := m.GetStepUpPolicy(ctx, "acme")
	ok(t, err)
	eq(t, got, core.StepUpPolicy{}) // never set: everything off

	in := core.StepUpPolicy{AllowFallback: true, Enabled: true, Enforce: true, OnNewDevice: true, OnIPChange: true,
		IdleAfter: 90 * time.Minute, OnMaxAge: true, SensitiveScopes: []string{"offline_access", "roles"},
		SensitiveAuthMaxAge: 5 * time.Minute}
	ok(t, m.PutStepUpPolicy(ctx, "acme", in))
	got, err = m.GetStepUpPolicy(ctx, "acme")
	ok(t, err)
	eq(t, got, in)

	// Replace, including back to empty scopes.
	in2 := core.StepUpPolicy{Enabled: true}
	ok(t, m.PutStepUpPolicy(ctx, "acme", in2))
	got, _ = m.GetStepUpPolicy(ctx, "acme")
	eq(t, got, in2)

	// Per realm.
	got, _ = m.GetStepUpPolicy(ctx, "beta")
	eq(t, got, core.StepUpPolicy{})
	is(t, m.PutStepUpPolicy(ctx, "nope", in), idp.ErrNotFound)

	// No aliasing of the scopes slice.
	ok(t, m.PutStepUpPolicy(ctx, "acme", in))
	in.SensitiveScopes[0] = "mutated"
	got, _ = m.GetStepUpPolicy(ctx, "acme")
	if got.SensitiveScopes[0] != "offline_access" {
		t.Fatal("stored policy aliases the caller's slice")
	}
}

func dev(realm, user, hash string, at time.Time) core.KnownDevice {
	return core.KnownDevice{Realm: realm, UserID: user, Hash: hash, IPHash: "ip-" + hash, LastSeen: at}
}

func stepUpDevices(t *testing.T, s core.Store) {
	m := stepUpStore(t, s)
	mkRealm(t, s, "acme")
	suUser(t, s, "acme", "u1")
	_, err := m.GetDevice(ctx, "acme", "u1", "h1")
	is(t, err, idp.ErrNotFound)
	_, err = m.LatestDevice(ctx, "acme", "u1")
	is(t, err, idp.ErrNotFound)

	ok(t, m.TouchDevice(ctx, dev("acme", "u1", "h1", t0), 20))
	got, err := m.GetDevice(ctx, "acme", "u1", "h1")
	ok(t, err)
	eq(t, got, core.KnownDevice{Realm: "acme", UserID: "u1", Hash: "h1", IPHash: "ip-h1", FirstSeen: t0, LastSeen: t0})

	// Touching again updates LastSeen and IPHash but keeps FirstSeen.
	d := dev("acme", "u1", "h1", t0.Add(time.Hour))
	d.IPHash = "new"
	ok(t, m.TouchDevice(ctx, d, 20))
	got, _ = m.GetDevice(ctx, "acme", "u1", "h1")
	eq(t, got, core.KnownDevice{Realm: "acme", UserID: "u1", Hash: "h1", IPHash: "new", FirstSeen: t0, LastSeen: t0.Add(time.Hour)})

	ok(t, m.TouchDevice(ctx, dev("acme", "u1", "h2", t0.Add(2*time.Hour)), 20))
	last, err := m.LatestDevice(ctx, "acme", "u1")
	ok(t, err)
	if last.Hash != "h2" {
		t.Fatalf("latest = %s", last.Hash)
	}
	list, err := m.ListDevices(ctx, "acme", "u1")
	ok(t, err)
	if len(list) != 2 || list[0].Hash != "h2" || list[1].Hash != "h1" {
		t.Fatalf("list order: %+v", list)
	}

	ok(t, m.DeleteDevice(ctx, "acme", "u1", "h2"))
	ok(t, m.DeleteDevice(ctx, "acme", "u1", "h2")) // idempotent
	_, err = m.GetDevice(ctx, "acme", "u1", "h2")
	is(t, err, idp.ErrNotFound)
	ok(t, m.DeleteUserDevices(ctx, "acme", "u1"))
	ok(t, m.DeleteUserDevices(ctx, "acme", "u1"))
	list, _ = m.ListDevices(ctx, "acme", "u1")
	if len(list) != 0 {
		t.Fatalf("devices survived delete: %+v", list)
	}
	is(t, m.TouchDevice(ctx, dev("nope", "u1", "h", t0), 20), idp.ErrNotFound)
}

func stepUpDevicePrune(t *testing.T, s core.Store) {
	m := stepUpStore(t, s)
	mkRealm(t, s, "acme")
	suUser(t, s, "acme", "u1")
	suUser(t, s, "acme", "u2")
	for i := 0; i < 5; i++ {
		ok(t, m.TouchDevice(ctx, dev("acme", "u1", fmt.Sprintf("d%d", i), t0.Add(time.Duration(i)*time.Minute)), 3))
	}
	ok(t, m.TouchDevice(ctx, dev("acme", "u2", "other", t0), 3))
	list, _ := m.ListDevices(ctx, "acme", "u1")
	if len(list) != 3 || list[0].Hash != "d4" || list[2].Hash != "d2" {
		t.Fatalf("expected the 3 newest (d4,d3,d2): %+v", list)
	}
	// Another user's devices are untouched and not visible.
	if l2, _ := m.ListDevices(ctx, "acme", "u2"); len(l2) != 1 {
		t.Fatalf("u2: %+v", l2)
	}
	_, err := m.GetDevice(ctx, "acme", "u2", "d4")
	is(t, err, idp.ErrNotFound)
	// Refreshing an old device keeps it when others are trimmed.
	ok(t, m.TouchDevice(ctx, dev("acme", "u1", "d2", t0.Add(time.Hour)), 3))
	ok(t, m.TouchDevice(ctx, dev("acme", "u1", "d5", t0.Add(2*time.Hour)), 3))
	list, _ = m.ListDevices(ctx, "acme", "u1")
	if len(list) != 3 || list[0].Hash != "d5" || list[1].Hash != "d2" || list[2].Hash != "d4" {
		t.Fatalf("after refresh: %+v", list)
	}
}

func stepUpDeviceConcurrent(t *testing.T, s core.Store) {
	m := stepUpStore(t, s)
	mkRealm(t, s, "acme")
	suUser(t, s, "acme", "u1")
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := m.TouchDevice(ctx, dev("acme", "u1", fmt.Sprintf("c%02d", i), t0.Add(time.Duration(i)*time.Second)), 5); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	list, _ := m.ListDevices(ctx, "acme", "u1")
	if len(list) != 5 {
		t.Fatalf("%d devices kept under concurrent touches, want exactly 5", len(list))
	}
}

func stepUpCascade(t *testing.T, s core.Store) {
	m := stepUpStore(t, s)
	mkRealm(t, s, "acme")
	suUser(t, s, "acme", "u1")
	ok(t, m.PutStepUpPolicy(ctx, "acme", core.StepUpPolicy{Enabled: true}))
	ok(t, m.TouchDevice(ctx, dev("acme", "u1", "h", t0), 20))
	ok(t, s.DeleteRealm(ctx, "acme"))
	mkRealm(t, s, "acme")
	got, _ := m.GetStepUpPolicy(ctx, "acme")
	eq(t, got, core.StepUpPolicy{})
	suUser(t, s, "acme", "u1")
	if l, _ := m.ListDevices(ctx, "acme", "u1"); len(l) != 0 {
		t.Fatalf("devices survived realm delete: %+v", l)
	}
}
