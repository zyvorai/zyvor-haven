// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"SessionPolicyRoundtrip", sessionPolicyRoundtrip},
		Case{"SessionLimitEvictsOldest", sessionLimitEvicts},
		Case{"SessionLimitDenyNew", sessionLimitDeny},
		Case{"SessionLimitConcurrent", sessionLimitConcurrent},
		Case{"SessionRememberIdle", sessionRememberIdle},
		Case{"PasskeyOnlyPolicyAndMarks", passkeyOnlyStore},
		Case{"FrontchannelLogoutURI", frontchannelStore},
		Case{"SessionControlsRealmCascade", sessionControlsCascade},
	)
}

func sessionCtl(t *testing.T, s core.Store) core.SessionPolicyStore {
	t.Helper()
	m, found := core.StoreAs[core.SessionPolicyStore](s)
	if !found {
		t.Skip("store does not implement core.SessionPolicyStore")
	}
	return m
}

func sessionPolicyRoundtrip(t *testing.T, s core.Store) {
	m := sessionCtl(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	got, err := m.GetSessionPolicy(ctx, "acme")
	ok(t, err)
	eq(t, got, core.SessionPolicy{}) // never set: everything off
	in := core.SessionPolicy{MaxSessions: 3, OnLimit: core.SessionLimitDenyNew, RememberMe: true,
		RememberIdle: 48 * time.Hour, RememberMax: 20 * 24 * time.Hour}
	ok(t, m.PutSessionPolicy(ctx, "acme", in))
	got, err = m.GetSessionPolicy(ctx, "acme")
	ok(t, err)
	eq(t, got, in)
	ok(t, m.PutSessionPolicy(ctx, "acme", core.SessionPolicy{}))
	got, _ = m.GetSessionPolicy(ctx, "acme")
	eq(t, got, core.SessionPolicy{})
	got, _ = m.GetSessionPolicy(ctx, "beta")
	eq(t, got, core.SessionPolicy{})
	is(t, m.PutSessionPolicy(ctx, "nope", in), idp.ErrNotFound)
}

// limSession is a session created i minutes after t0 and alive for an hour.
func limSession(id, user string, i int) core.Session {
	x := mkSession(id, user)
	x.CreatedAt = t0.Add(time.Duration(i) * time.Minute)
	x.AuthTime, x.LastSeen = x.CreatedAt, x.CreatedAt
	x.IdleExpires, x.ExpiresAt = t0.Add(time.Hour), t0.Add(10*time.Hour)
	return x
}

func sessionIDs(t *testing.T, s core.Store, realm, user string) []string {
	t.Helper()
	all, err := s.ListSessions(ctx, realm, user, 1000)
	ok(t, err)
	var out []string
	for _, x := range all {
		out = append(out, x.ID)
	}
	slices.Sort(out)
	return out
}

func sessionLimitSetup(t *testing.T, s core.Store) core.SessionPolicyStore {
	t.Helper()
	m := sessionCtl(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	for _, u := range []string{"u-1", "u-2"} {
		ok(t, s.CreateUser(ctx, core.User{ID: u, Realm: "acme", Username: u}))
	}
	return m
}

func sessionLimitEvicts(t *testing.T, s core.Store) {
	m := sessionLimitSetup(t, s)
	now := t0.Add(30 * time.Minute)
	// Created out of order: eviction follows CreatedAt, not insertion.
	for _, x := range []core.Session{limSession("s-2", "u-1", 2), limSession("s-1", "u-1", 1), limSession("s-3", "u-1", 3),
		limSession("other", "u-2", 0)} {
		ok(t, s.PutSession(ctx, x))
	}
	// An expired and an idle-expired session do not count and are not returned.
	dead := limSession("dead", "u-1", 0)
	dead.ExpiresAt = now.Add(-time.Second)
	ok(t, s.PutSession(ctx, dead))
	idle := limSession("idle", "u-1", 0)
	idle.IdleExpires = now
	ok(t, s.PutSession(ctx, idle))

	// Max 4 live, 3 live now: nothing is evicted.
	ev, err := m.CreateLimitedSession(ctx, limSession("s-4", "u-1", 4), core.NewSessionOptions{Now: now, MaxLive: 4})
	ok(t, err)
	eq(t, len(ev), 0)
	// Max 2: s-1, s-2 and s-3 must go so that s-4 and s-5 remain.
	n := limSession("s-5", "u-1", 5)
	n.Clients = []string{"app"}
	ev, err = m.CreateLimitedSession(ctx, n, core.NewSessionOptions{Now: now, MaxLive: 2})
	ok(t, err)
	var got []string
	for _, e := range ev {
		got = append(got, e.ID)
		if e.UserID != "u-1" || e.Realm != "acme" {
			t.Fatalf("evicted somebody else's session: %+v", e)
		}
	}
	eq(t, got, []string{"s-1", "s-2", "s-3"})
	eq(t, sessionIDs(t, s, "acme", "u-1"), []string{"dead", "idle", "s-4", "s-5"})
	eq(t, sessionIDs(t, s, "acme", "u-2"), []string{"other"})
	stored, err := s.GetSession(ctx, "acme", "s-5")
	ok(t, err)
	eq(t, stored.Clients, []string{"app"})
	// An evicted session is gone for everyone.
	_, err = s.TakeSession(ctx, "acme", "s-1")
	is(t, err, idp.ErrNotFound)

	// Replaces: neither counted nor evicted.
	ev, err = m.CreateLimitedSession(ctx, limSession("s-6", "u-1", 6), core.NewSessionOptions{Now: now, MaxLive: 2, Replaces: "s-4"})
	ok(t, err)
	eq(t, len(ev), 0)
	eq(t, sessionIDs(t, s, "acme", "u-1"), []string{"dead", "idle", "s-4", "s-5", "s-6"})

	// MaxLive 0 = unlimited.
	ev, err = m.CreateLimitedSession(ctx, limSession("s-7", "u-1", 7), core.NewSessionOptions{Now: now})
	ok(t, err)
	eq(t, len(ev), 0)

	// Conflicts and unknown realm behave like PutSession and evict nothing.
	_, err = m.CreateLimitedSession(ctx, limSession("s-7", "u-1", 8), core.NewSessionOptions{Now: now, MaxLive: 1})
	is(t, err, idp.ErrConflict)
	eq(t, sessionIDs(t, s, "acme", "u-1"), []string{"dead", "idle", "s-4", "s-5", "s-6", "s-7"})
	bad := limSession("s-9", "u-1", 9)
	bad.Realm = "nope"
	_, err = m.CreateLimitedSession(ctx, bad, core.NewSessionOptions{Now: now})
	is(t, err, idp.ErrNotFound)
}

func sessionLimitDeny(t *testing.T, s core.Store) {
	m := sessionLimitSetup(t, s)
	now := t0.Add(30 * time.Minute)
	o := core.NewSessionOptions{Now: now, MaxLive: 2, DenyNew: true}
	for i := 1; i <= 2; i++ {
		_, err := m.CreateLimitedSession(ctx, limSession(fmt.Sprintf("s-%d", i), "u-1", i), o)
		ok(t, err)
	}
	ev, err := m.CreateLimitedSession(ctx, limSession("s-3", "u-1", 3), o)
	is(t, err, core.ErrSessionLimit)
	eq(t, len(ev), 0)
	eq(t, sessionIDs(t, s, "acme", "u-1"), []string{"s-1", "s-2"})
	// Another user is not affected; replacing an own session is allowed.
	_, err = m.CreateLimitedSession(ctx, limSession("o-1", "u-2", 1), o)
	ok(t, err)
	r := o
	r.Replaces = "s-1"
	_, err = m.CreateLimitedSession(ctx, limSession("s-4", "u-1", 4), r)
	ok(t, err)
	// Once sessions have expired they free their slots.
	late := core.NewSessionOptions{Now: t0.Add(2 * time.Hour), MaxLive: 1, DenyNew: true}
	n := limSession("s-5", "u-1", 5)
	n.IdleExpires = t0.Add(3 * time.Hour)
	_, err = m.CreateLimitedSession(ctx, n, late)
	ok(t, err)
}

func sessionLimitConcurrent(t *testing.T, s core.Store) {
	m := sessionLimitSetup(t, s)
	now := t0.Add(30 * time.Minute)
	for _, tc := range []struct {
		user string
		deny bool
	}{{"u-1", true}, {"u-2", false}} {
		var wg sync.WaitGroup
		var created, denied atomic.Int32
		for i := range 24 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				x := limSession(fmt.Sprintf("%s-%02d", tc.user, i), tc.user, i)
				_, err := m.CreateLimitedSession(ctx, x, core.NewSessionOptions{Now: now, MaxLive: 3, DenyNew: tc.deny})
				switch {
				case err == nil:
					created.Add(1)
				case errors.Is(err, core.ErrSessionLimit):
					denied.Add(1)
				default:
					t.Errorf("create: %v", err)
				}
			}()
		}
		wg.Wait()
		if got := sessionIDs(t, s, "acme", tc.user); len(got) != 3 {
			t.Fatalf("deny=%v: %d sessions survive a limit of 3: %v", tc.deny, len(got), got)
		}
		if tc.deny && (created.Load() != 3 || denied.Load() != 21) {
			t.Fatalf("deny: created %d denied %d", created.Load(), denied.Load())
		}
		if !tc.deny && created.Load() != 24 {
			t.Fatalf("revoke oldest: created %d", created.Load())
		}
	}
}

func sessionRememberIdle(t *testing.T, s core.Store) {
	m := sessionLimitSetup(t, s)
	_, err := m.CreateLimitedSession(ctx, limSession("r-1", "u-1", 1),
		core.NewSessionOptions{Now: t0, RememberIdle: 72 * time.Hour})
	ok(t, err)
	ok(t, s.PutSession(ctx, limSession("p-1", "u-1", 2)))
	for id, want := range map[string]time.Duration{"r-1": 72 * time.Hour, "p-1": 0, "missing": 0} {
		got, err := m.SessionRememberIdle(ctx, "acme", id)
		ok(t, err)
		if got != want {
			t.Errorf("%s: %v, want %v", id, got, want)
		}
	}
	got, err := m.SessionRememberIdle(ctx, "beta", "r-1")
	ok(t, err)
	eq(t, got, time.Duration(0)) // realm isolation
	ok(t, s.TouchSession(ctx, "acme", "r-1", t0, t0.Add(time.Hour)))
	got, _ = m.SessionRememberIdle(ctx, "acme", "r-1")
	eq(t, got, 72*time.Hour) // a touch keeps the mark
	_, err = s.TakeSession(ctx, "acme", "r-1")
	ok(t, err)
	got, _ = m.SessionRememberIdle(ctx, "acme", "r-1")
	eq(t, got, time.Duration(0))
}

func passkeyOnlyStore(t *testing.T, s core.Store) {
	m, found := core.StoreAs[core.PasskeyOnlyStore](s)
	ps, found2 := core.StoreAs[core.PasskeyStore](s)
	if !found || !found2 {
		t.Skip("store does not implement core.PasskeyOnlyStore")
	}
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	ok(t, s.CreateUser(ctx, core.User{ID: "u-1", Realm: "acme", Username: "u-1"}))
	ok(t, s.CreateUser(ctx, core.User{ID: "u-2", Realm: "acme", Username: "u-2"}))
	v, err := m.PasskeyOnly(ctx, "acme")
	ok(t, err)
	eq(t, v, false) // off by default
	ok(t, m.SetPasskeyOnly(ctx, "acme", true))
	v, _ = m.PasskeyOnly(ctx, "acme")
	eq(t, v, true)
	v, _ = m.PasskeyOnly(ctx, "beta")
	eq(t, v, false)
	ok(t, m.SetPasskeyOnly(ctx, "acme", false))
	v, _ = m.PasskeyOnly(ctx, "acme")
	eq(t, v, false)
	is(t, m.SetPasskeyOnly(ctx, "nope", true), idp.ErrNotFound)

	add := func(id, user string, at time.Time) {
		ok(t, ps.AddPasskey(ctx, core.Passkey{Realm: "acme", UserID: user, CredentialID: id, PublicKey: []byte{1}, CreatedAt: at}))
	}
	add("c-b", "u-1", t0)
	add("c-a", "u-1", t0)
	add("c-z", "u-2", t0)
	marks := func(user string) []string {
		got, err := m.PasswordlessPasskeys(ctx, "acme", user)
		ok(t, err)
		return got
	}
	eq(t, marks("u-1"), []string(nil))
	ok(t, m.MarkPasswordlessPasskey(ctx, "acme", "c-b", t0))
	ok(t, m.MarkPasswordlessPasskey(ctx, "acme", "c-b", t0.Add(time.Hour))) // idempotent
	ok(t, m.MarkPasswordlessPasskey(ctx, "acme", "c-a", t0))
	ok(t, m.MarkPasswordlessPasskey(ctx, "acme", "c-z", t0))
	eq(t, marks("u-1"), []string{"c-a", "c-b"})
	eq(t, marks("u-2"), []string{"c-z"})
	is(t, m.MarkPasswordlessPasskey(ctx, "acme", "missing", t0), idp.ErrNotFound)
	is(t, m.MarkPasswordlessPasskey(ctx, "beta", "c-a", t0), idp.ErrNotFound)
	other, err := m.PasswordlessPasskeys(ctx, "beta", "u-1")
	ok(t, err)
	eq(t, other, []string(nil))
	// A deleted credential loses the mark, also when registered again.
	ok(t, ps.DeletePasskey(ctx, "acme", "u-1", "c-a", false))
	eq(t, marks("u-1"), []string{"c-b"})
	add("c-a", "u-1", t0.Add(time.Minute))
	eq(t, marks("u-1"), []string{"c-b"})
	ok(t, s.DeleteUser(ctx, "acme", "u-1"))
	eq(t, marks("u-1"), []string(nil))
}

func frontchannelStore(t *testing.T, s core.Store) {
	m, found := core.StoreAs[core.FrontchannelStore](s)
	if !found {
		t.Skip("store does not implement core.FrontchannelStore")
	}
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	ok(t, s.CreateClient(ctx, core.Client{ID: "c-1", Realm: "acme", ClientID: "app"}))
	get := func(realm, id string) string {
		v, err := m.FrontchannelLogoutURI(ctx, realm, id)
		ok(t, err)
		return v
	}
	eq(t, get("acme", "c-1"), "")
	ok(t, m.SetFrontchannelLogoutURI(ctx, "acme", "c-1", "https://app.example/fc"))
	eq(t, get("acme", "c-1"), "https://app.example/fc")
	ok(t, m.SetFrontchannelLogoutURI(ctx, "acme", "c-1", "https://app.example/fc2?x=1"))
	eq(t, get("acme", "c-1"), "https://app.example/fc2?x=1")
	eq(t, get("beta", "c-1"), "")
	is(t, m.SetFrontchannelLogoutURI(ctx, "beta", "c-1", "https://evil.example/"), idp.ErrNotFound)
	is(t, m.SetFrontchannelLogoutURI(ctx, "acme", "nope", "https://app.example/"), idp.ErrNotFound)
	ok(t, m.SetFrontchannelLogoutURI(ctx, "acme", "c-1", ""))
	eq(t, get("acme", "c-1"), "")
	ok(t, m.SetFrontchannelLogoutURI(ctx, "acme", "c-1", "https://app.example/fc"))
	ok(t, s.DeleteClient(ctx, "acme", "c-1"))
	eq(t, get("acme", "c-1"), "")
	// A new client with the same client_id starts without one.
	ok(t, s.CreateClient(ctx, core.Client{ID: "c-2", Realm: "acme", ClientID: "app"}))
	eq(t, get("acme", "c-2"), "")
}

func sessionControlsCascade(t *testing.T, s core.Store) {
	m := sessionCtl(t, s)
	po, found := core.StoreAs[core.PasskeyOnlyStore](s)
	if !found {
		t.Skip("store does not implement core.PasskeyOnlyStore")
	}
	mkRealm(t, s, "acme")
	ok(t, m.PutSessionPolicy(ctx, "acme", core.SessionPolicy{MaxSessions: 1, RememberMe: true}))
	ok(t, po.SetPasskeyOnly(ctx, "acme", true))
	ok(t, s.DeleteRealm(ctx, "acme"))
	mkRealm(t, s, "acme") // re-created: nothing is inherited
	p, err := m.GetSessionPolicy(ctx, "acme")
	ok(t, err)
	eq(t, p, core.SessionPolicy{})
	v, err := po.PasskeyOnly(ctx, "acme")
	ok(t, err)
	eq(t, v, false)
}
