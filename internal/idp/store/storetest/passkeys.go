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
		Case{"PasskeyRoundtrip", passkeyRoundtrip},
		Case{"PasskeyUniquePerRealm", passkeyUnique},
		Case{"PasskeyUserHandle", passkeyHandle},
		Case{"PasskeyUseRenameDelete", passkeyUseRenameDelete},
		Case{"PasskeyKeepLastConcurrent", passkeyKeepLastConcurrent},
		Case{"PasskeyChallengeSingleUse", passkeyChallenge},
		Case{"PasskeyChallengeConcurrent", passkeyChallengeConcurrent},
		Case{"PasskeyRealmPolicy", passkeyPolicy},
		Case{"PasskeyRealmCascade", passkeyCascade},
	)
}

func passkeyStore(t *testing.T, s core.Store) core.PasskeyStore {
	t.Helper()
	ps, found := core.StoreAs[core.PasskeyStore](s)
	if !found {
		t.Skip("store does not implement core.PasskeyStore")
	}
	return ps
}

func pkUser(t *testing.T, s core.Store, realm, id string) {
	t.Helper()
	ok(t, s.CreateUser(ctx, core.User{ID: id, Realm: realm, Username: id}))
}

func mkPasskey(realm, user, cred string) core.Passkey {
	return core.Passkey{Realm: realm, UserID: user, CredentialID: cred, PublicKey: []byte{0xa1, 0x01, 0x02},
		SignCount: 4000000000, Transports: []string{"internal", "hybrid"}, AAGUID: "00112233445566778899aabbccddeeff",
		Name: "Laptop", BackupEligible: true, BackupState: true, CreatedAt: t0}
}

func passkeyRoundtrip(t *testing.T, s core.Store) {
	ps := passkeyStore(t, s)
	mkRealm(t, s, "acme")
	pkUser(t, s, "acme", "u1")
	in := mkPasskey("acme", "u1", "cred-1")
	ok(t, ps.AddPasskey(ctx, in))
	got, err := ps.GetPasskey(ctx, "acme", "cred-1")
	ok(t, err)
	eq(t, got, in)
	// Empty transports and zero CreatedAt (filled by the store).
	e := mkPasskey("acme", "u1", "cred-2")
	e.Transports, e.CreatedAt = nil, time.Time{}
	ok(t, ps.AddPasskey(ctx, e))
	got, err = ps.GetPasskey(ctx, "acme", "cred-2")
	ok(t, err)
	if len(got.Transports) != 0 || got.CreatedAt.IsZero() || !got.LastUsedAt.IsZero() {
		t.Fatalf("defaults wrong: %+v", got)
	}
	list, err := ps.ListPasskeys(ctx, "acme", "u1")
	ok(t, err)
	if len(list) != 2 || list[0].CredentialID != "cred-1" {
		t.Fatalf("list: %+v", list)
	}
	_, err = ps.GetPasskey(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)
	// A credential for a user that does not exist is refused.
	is(t, ps.AddPasskey(ctx, mkPasskey("acme", "ghost", "cred-3")), idp.ErrNotFound)
	// No aliasing: mutating a returned value does not change the store.
	got, _ = ps.GetPasskey(ctx, "acme", "cred-1")
	got.PublicKey[0] = 0xff
	again, _ := ps.GetPasskey(ctx, "acme", "cred-1")
	if again.PublicKey[0] != 0xa1 {
		t.Fatal("store aliases returned key bytes")
	}
}

func passkeyUnique(t *testing.T, s core.Store) {
	ps := passkeyStore(t, s)
	mkRealm(t, s, "a")
	mkRealm(t, s, "b")
	pkUser(t, s, "a", "u1")
	pkUser(t, s, "a", "u2")
	pkUser(t, s, "b", "u3")
	ok(t, ps.AddPasskey(ctx, mkPasskey("a", "u1", "same")))
	is(t, ps.AddPasskey(ctx, mkPasskey("a", "u1", "same")), idp.ErrConflict)
	is(t, ps.AddPasskey(ctx, mkPasskey("a", "u2", "same")), idp.ErrConflict) // another user, same realm
	ok(t, ps.AddPasskey(ctx, mkPasskey("b", "u3", "same")))                  // other realm is independent
	// Another user's credential is invisible in listings and cannot be renamed or deleted.
	l, err := ps.ListPasskeys(ctx, "a", "u2")
	ok(t, err)
	if len(l) != 0 {
		t.Fatalf("u2 sees %d credentials", len(l))
	}
	is(t, ps.RenamePasskey(ctx, "a", "u2", "same", "x"), idp.ErrNotFound)
	is(t, ps.DeletePasskey(ctx, "a", "u2", "same", false), idp.ErrNotFound)
	_, err = ps.GetPasskey(ctx, "a", "same")
	ok(t, err)
}

func passkeyHandle(t *testing.T, s core.Store) {
	ps := passkeyStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	pkUser(t, s, "acme", "u1")
	pkUser(t, s, "acme", "u2")
	h, err := ps.UserHandle(ctx, "acme", "u1", "handle-one")
	ok(t, err)
	if h != "handle-one" {
		t.Fatalf("handle %q", h)
	}
	h, err = ps.UserHandle(ctx, "acme", "u1", "a-different-candidate")
	ok(t, err)
	if h != "handle-one" {
		t.Fatalf("existing handle must win, got %q", h)
	}
	id, err := ps.UserByHandle(ctx, "acme", "handle-one")
	ok(t, err)
	if id != "u1" {
		t.Fatalf("by handle: %q", id)
	}
	_, err = ps.UserByHandle(ctx, "other", "handle-one") // realm isolation
	is(t, err, idp.ErrNotFound)
	_, err = ps.UserByHandle(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)
	_, err = ps.UserHandle(ctx, "acme", "ghost", "h-ghost")
	is(t, err, idp.ErrNotFound)
	// Handles are unique within a realm.
	if _, err := ps.UserHandle(ctx, "acme", "u2", "handle-one"); err == nil {
		t.Fatal("two users share a handle")
	}
}

func passkeyUseRenameDelete(t *testing.T, s core.Store) {
	ps := passkeyStore(t, s)
	mkRealm(t, s, "acme")
	pkUser(t, s, "acme", "u1")
	in := mkPasskey("acme", "u1", "c1")
	in.BackupState = false
	ok(t, ps.AddPasskey(ctx, in))
	ok(t, ps.AddPasskey(ctx, mkPasskey("acme", "u1", "c2")))
	at := t0.Add(time.Hour)
	ok(t, ps.UpdatePasskeyUse(ctx, "acme", "c1", 7, true, at))
	got, _ := ps.GetPasskey(ctx, "acme", "c1")
	if got.SignCount != 7 || !got.BackupState || !got.LastUsedAt.Equal(at) {
		t.Fatalf("use not recorded: %+v", got)
	}
	is(t, ps.UpdatePasskeyUse(ctx, "acme", "nope", 1, false, at), idp.ErrNotFound)
	ok(t, ps.RenamePasskey(ctx, "acme", "u1", "c1", "Phone"))
	got, _ = ps.GetPasskey(ctx, "acme", "c1")
	if got.Name != "Phone" {
		t.Fatalf("rename: %q", got.Name)
	}
	is(t, ps.DeletePasskey(ctx, "acme", "u1", "nope", false), idp.ErrNotFound)
	ok(t, ps.DeletePasskey(ctx, "acme", "u1", "c1", true)) // two left: fine
	is(t, ps.DeletePasskey(ctx, "acme", "u1", "c2", true), idp.ErrConflict)
	_, err := ps.GetPasskey(ctx, "acme", "c2")
	ok(t, err) // the last credential survived
	ok(t, ps.DeletePasskey(ctx, "acme", "u1", "c2", false))
}

// Two concurrent deletes of a user's last two credentials with keepLast must
// leave exactly one.
func passkeyKeepLastConcurrent(t *testing.T, s core.Store) {
	ps := passkeyStore(t, s)
	mkRealm(t, s, "acme")
	pkUser(t, s, "acme", "u1")
	ok(t, ps.AddPasskey(ctx, mkPasskey("acme", "u1", "c1")))
	ok(t, ps.AddPasskey(ctx, mkPasskey("acme", "u1", "c2")))
	var wg sync.WaitGroup
	var deleted atomic.Int32
	for _, id := range []string{"c1", "c2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ps.DeletePasskey(ctx, "acme", "u1", id, true) == nil {
				deleted.Add(1)
			}
		}()
	}
	wg.Wait()
	l, _ := ps.ListPasskeys(ctx, "acme", "u1")
	if deleted.Load() != 1 || len(l) != 1 {
		t.Fatalf("deleted %d, %d credentials left", deleted.Load(), len(l))
	}
}

func passkeyChallenge(t *testing.T, s core.Store) {
	ps := passkeyStore(t, s)
	// The challenge table is global (not realm scoped), so use digests that are
	// unique per run: a previous run may have left rows behind.
	suffix := time.Now().Format("150405.000000000")
	d1, d2 := "d1-"+suffix, "d2-"+suffix
	exp := t0.Add(5 * time.Minute)
	ok(t, ps.ConsumeChallenge(ctx, d1, t0, exp))
	is(t, ps.ConsumeChallenge(ctx, d1, t0.Add(time.Minute), exp), idp.ErrConflict)
	ok(t, ps.ConsumeChallenge(ctx, d2, t0, exp))
	// After expiry the marker may be purged; the signed token has expired by
	// then so reuse is impossible, and the digest may be recorded again.
	ok(t, ps.ConsumeChallenge(ctx, d1, exp.Add(time.Minute), exp.Add(10*time.Minute)))
}

func passkeyChallengeConcurrent(t *testing.T, s core.Store) {
	ps := passkeyStore(t, s)
	once := "once-" + time.Now().Format("150405.000000000")
	var wg sync.WaitGroup
	var won atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ps.ConsumeChallenge(ctx, once, t0, t0.Add(time.Hour)) == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("%d consumers won a single-use challenge", won.Load())
	}
}

func passkeyPolicy(t *testing.T, s core.Store) {
	ps := passkeyStore(t, s)
	mkRealm(t, s, "acme")
	v, err := ps.RealmRequiresPasskeys(ctx, "acme")
	ok(t, err)
	if v {
		t.Fatal("default must be off")
	}
	ok(t, ps.SetRealmRequiresPasskeys(ctx, "acme", true))
	v, _ = ps.RealmRequiresPasskeys(ctx, "acme")
	if !v {
		t.Fatal("not set")
	}
	ok(t, ps.SetRealmRequiresPasskeys(ctx, "acme", false))
	v, _ = ps.RealmRequiresPasskeys(ctx, "acme")
	if v {
		t.Fatal("not cleared")
	}
	if err := ps.SetRealmRequiresPasskeys(ctx, "ghost", true); err == nil {
		t.Fatal("policy for a missing realm accepted")
	}
}

func passkeyCascade(t *testing.T, s core.Store) {
	ps := passkeyStore(t, s)
	mkRealm(t, s, "acme")
	pkUser(t, s, "acme", "u1")
	ok(t, ps.AddPasskey(ctx, mkPasskey("acme", "u1", "c1")))
	_, err := ps.UserHandle(ctx, "acme", "u1", "h1")
	ok(t, err)
	// Deleting a user removes their credentials and handle.
	pkUser(t, s, "acme", "u2")
	ok(t, ps.AddPasskey(ctx, mkPasskey("acme", "u2", "c2")))
	_, err = ps.UserHandle(ctx, "acme", "u2", "h2")
	ok(t, err)
	ok(t, s.DeleteUser(ctx, "acme", "u2"))
	_, err = ps.GetPasskey(ctx, "acme", "c2")
	is(t, err, idp.ErrNotFound)
	_, err = ps.UserByHandle(ctx, "acme", "h2")
	is(t, err, idp.ErrNotFound)
	ok(t, s.DeleteRealm(ctx, "acme"))
	mkRealm(t, s, "acme")
	_, err = ps.GetPasskey(ctx, "acme", "c1")
	is(t, err, idp.ErrNotFound)
	_, err = ps.UserByHandle(ctx, "acme", "h1")
	is(t, err, idp.ErrNotFound)
}
