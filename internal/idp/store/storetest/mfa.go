// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"MFACredentialLifecycle", mfaLifecycle},
		Case{"MFAConfirmExactlyOnce", mfaConfirmOnce},
		Case{"MFAStepReplayAtomic", mfaStepAtomic},
		Case{"MFARecoveryExactlyOnce", mfaRecoveryOnce},
		Case{"MFARecoveryReplaceAndDelete", mfaRecoveryReplace},
		Case{"MFAPolicy", mfaPolicy},
	)
}

func mfaStore(t *testing.T, s core.Store) core.MFAStore {
	t.Helper()
	m, found := core.StoreAs[core.MFAStore](s)
	if !found {
		t.Skip("store does not implement core.MFAStore")
	}
	return m
}

func mfaLifecycle(t *testing.T, s core.Store) {
	m := mfaStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	_, err := m.GetTOTP(ctx, "acme", "u1")
	is(t, err, idp.ErrNotFound)

	in := core.TOTPCredential{Realm: "acme", UserID: "u1", SealedSeed: "v1.sealed", CreatedAt: t0}
	ok(t, m.PutTOTP(ctx, in))
	got, err := m.GetTOTP(ctx, "acme", "u1")
	ok(t, err)
	eq(t, got, in) // unconfirmed, step 0

	// Restarting an unconfirmed enrollment replaces the seed.
	in2 := core.TOTPCredential{Realm: "acme", UserID: "u1", SealedSeed: "v1.other", CreatedAt: t0.Add(time.Second)}
	ok(t, m.PutTOTP(ctx, in2))
	got, _ = m.GetTOTP(ctx, "acme", "u1")
	eq(t, got, in2)

	// Isolation between realms and users.
	_, err = m.GetTOTP(ctx, "beta", "u1")
	is(t, err, idp.ErrNotFound)
	_, err = m.GetTOTP(ctx, "acme", "u2")
	is(t, err, idp.ErrNotFound)

	// Unconfirmed credentials cannot consume steps.
	won, err := m.UseTOTPStep(ctx, "acme", "u1", 5)
	ok(t, err)
	if won {
		t.Fatal("UseTOTPStep succeeded on an unconfirmed credential")
	}

	won, err = m.ConfirmTOTP(ctx, "acme", "u1", 100)
	ok(t, err)
	if !won {
		t.Fatal("confirm failed")
	}
	got, _ = m.GetTOTP(ctx, "acme", "u1")
	if !got.Confirmed || got.LastUsedStep != 100 || got.SealedSeed != "v1.other" {
		t.Fatalf("after confirm: %+v", got)
	}

	// A confirmed credential is never silently replaced.
	is(t, m.PutTOTP(ctx, in), idp.ErrConflict)
	got, _ = m.GetTOTP(ctx, "acme", "u1")
	if got.SealedSeed != "v1.other" || !got.Confirmed {
		t.Fatalf("confirmed credential was overwritten: %+v", got)
	}

	// Delete removes credential and recovery codes; idempotent.
	ok(t, m.ReplaceRecoveryCodes(ctx, "acme", "u1", []string{"h1", "h2"}))
	ok(t, m.DeleteUserMFA(ctx, "acme", "u1"))
	ok(t, m.DeleteUserMFA(ctx, "acme", "u1"))
	_, err = m.GetTOTP(ctx, "acme", "u1")
	is(t, err, idp.ErrNotFound)
	n, err := m.CountRecoveryCodes(ctx, "acme", "u1")
	ok(t, err)
	if n != 0 {
		t.Fatalf("recovery codes survived delete: %d", n)
	}
	// Enrollment can start again after a delete.
	ok(t, m.PutTOTP(ctx, in))

	// Missing realm.
	is(t, m.PutTOTP(ctx, core.TOTPCredential{Realm: "nope", UserID: "u", SealedSeed: "x"}), idp.ErrNotFound)
}

func mfaConfirmOnce(t *testing.T, s core.Store) {
	m := mfaStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, m.PutTOTP(ctx, core.TOTPCredential{Realm: "acme", UserID: "u1", SealedSeed: "x", CreatedAt: t0}))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			won, err := m.ConfirmTOTP(ctx, "acme", "u1", int64(1000+i))
			if err != nil {
				t.Error(err)
			}
			if won {
				wins.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d parallel confirms won, want exactly 1", wins.Load())
	}
	won, err := m.ConfirmTOTP(ctx, "acme", "nobody", 1)
	ok(t, err)
	if won {
		t.Fatal("confirm of a missing credential reported success")
	}
}

// lastUsedStep atomicity: parallel submissions of one step, exactly one wins;
// a step at or below the stored one never wins.
func mfaStepAtomic(t *testing.T, s core.Store) {
	m := mfaStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, m.PutTOTP(ctx, core.TOTPCredential{Realm: "acme", UserID: "u1", SealedSeed: "x", CreatedAt: t0}))
	_, err := m.ConfirmTOTP(ctx, "acme", "u1", 10)
	ok(t, err)

	for _, step := range []int64{10, 9, 1, 0, -5} {
		won, err := m.UseTOTPStep(ctx, "acme", "u1", step)
		ok(t, err)
		if won {
			t.Fatalf("step %d accepted at last_used_step 10", step)
		}
	}
	for round, step := range []int64{11, 12, 40} {
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				won, err := m.UseTOTPStep(ctx, "acme", "u1", step)
				if err != nil {
					t.Error(err)
				}
				if won {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("round %d: %d parallel submissions of step %d won, want exactly 1", round, wins.Load(), step)
		}
		got, _ := m.GetTOTP(ctx, "acme", "u1")
		if got.LastUsedStep != step {
			t.Fatalf("last step %d, want %d", got.LastUsedStep, step)
		}
	}
	// Racing different steps: the stored value ends at the maximum and never
	// goes backwards.
	var wg sync.WaitGroup
	for i := int64(41); i <= 72; i++ {
		wg.Add(1)
		go func(i int64) {
			defer wg.Done()
			if _, err := m.UseTOTPStep(ctx, "acme", "u1", i); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	got, _ := m.GetTOTP(ctx, "acme", "u1")
	if got.LastUsedStep != 72 {
		t.Fatalf("after racing steps 41..72 last step is %d, want 72", got.LastUsedStep)
	}
}

func mfaRecoveryOnce(t *testing.T, s core.Store) {
	m := mfaStore(t, s)
	mkRealm(t, s, "acme")
	var hashes []string
	for i := 0; i < 10; i++ {
		hashes = append(hashes, fmt.Sprintf("hash-%d", i))
	}
	ok(t, m.ReplaceRecoveryCodes(ctx, "acme", "u1", hashes))
	n, err := m.CountRecoveryCodes(ctx, "acme", "u1")
	ok(t, err)
	if n != 10 {
		t.Fatalf("count %d", n)
	}

	// 32 goroutines race for each of three codes: exactly one winner per code.
	for _, h := range hashes[:3] {
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				won, err := m.ConsumeRecoveryCode(ctx, "acme", "u1", h)
				if err != nil {
					t.Error(err)
				}
				if won {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d parallel consumers of %s won, want exactly 1", wins.Load(), h)
		}
	}
	n, _ = m.CountRecoveryCodes(ctx, "acme", "u1")
	if n != 7 {
		t.Fatalf("count after 3 consumed: %d", n)
	}
	// Another user or realm cannot consume this user's code.
	mkRealm(t, s, "beta")
	for _, who := range [][2]string{{"acme", "u2"}, {"beta", "u1"}} {
		won, err := m.ConsumeRecoveryCode(ctx, who[0], who[1], hashes[5])
		ok(t, err)
		if won {
			t.Fatalf("%v consumed a code of acme/u1", who)
		}
	}
	won, _ := m.ConsumeRecoveryCode(ctx, "acme", "u1", "unknown")
	if won {
		t.Fatal("unknown hash consumed")
	}
}

func mfaRecoveryReplace(t *testing.T, s core.Store) {
	m := mfaStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, m.ReplaceRecoveryCodes(ctx, "acme", "u1", []string{"a", "b", "c"}))
	ok(t, m.ReplaceRecoveryCodes(ctx, "acme", "u2", []string{"a"})) // same hash, other user
	ok(t, m.ReplaceRecoveryCodes(ctx, "acme", "u1", []string{"d", "e"}))
	for _, old := range []string{"a", "b", "c"} {
		won, err := m.ConsumeRecoveryCode(ctx, "acme", "u1", old)
		ok(t, err)
		if won {
			t.Fatalf("old code %q survived regeneration", old)
		}
	}
	n, _ := m.CountRecoveryCodes(ctx, "acme", "u1")
	if n != 2 {
		t.Fatalf("count %d, want 2", n)
	}
	// u2 is untouched.
	n, _ = m.CountRecoveryCodes(ctx, "acme", "u2")
	if n != 1 {
		t.Fatalf("u2 count %d, want 1", n)
	}
	// Replacing with an empty set clears.
	ok(t, m.ReplaceRecoveryCodes(ctx, "acme", "u1", nil))
	n, _ = m.CountRecoveryCodes(ctx, "acme", "u1")
	if n != 0 {
		t.Fatalf("count %d after empty replace", n)
	}
	is(t, m.ReplaceRecoveryCodes(ctx, "nope", "u1", []string{"x"}), idp.ErrNotFound)
}

func mfaPolicy(t *testing.T, s core.Store) {
	m := mfaStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	p, err := m.GetMFAPolicy(ctx, "acme")
	ok(t, err)
	if p.RequireMFA {
		t.Fatal("default policy requires MFA")
	}
	ok(t, m.PutMFAPolicy(ctx, "acme", core.MFAPolicy{RequireMFA: true}))
	p, _ = m.GetMFAPolicy(ctx, "acme")
	if !p.RequireMFA {
		t.Fatal("policy not stored")
	}
	p, _ = m.GetMFAPolicy(ctx, "beta")
	if p.RequireMFA {
		t.Fatal("policy leaked to another realm")
	}
	ok(t, m.PutMFAPolicy(ctx, "acme", core.MFAPolicy{}))
	p, _ = m.GetMFAPolicy(ctx, "acme")
	if p.RequireMFA {
		t.Fatal("policy not cleared")
	}
	is(t, m.PutMFAPolicy(ctx, "nope", core.MFAPolicy{RequireMFA: true}), idp.ErrNotFound)
}
