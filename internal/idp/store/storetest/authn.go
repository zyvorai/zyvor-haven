// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"AuthnPolicy", authnPolicy},
		Case{"AuthnSessionRecord", authnSession},
		Case{"AuthnSessionRecordConcurrent", authnSessionConcurrent},
		Case{"AuthnCascade", authnCascade},
	)
}

func authnStore(t *testing.T, s core.Store) core.AuthnStore {
	t.Helper()
	m, found := core.StoreAs[core.AuthnStore](s)
	if !found {
		t.Skip("store does not implement core.AuthnStore")
	}
	return m
}

func authnPolicy(t *testing.T, s core.Store) {
	m := authnStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	_, err := m.GetACRPolicy(ctx, "acme")
	is(t, err, idp.ErrNotFound)

	in := core.DefaultACRPolicy()
	in.EnrollOnStepUp, in.AdminACR, in.AdminMaxAgeSeconds = true, core.ACRMultiFactor, 900
	ok(t, m.PutACRPolicy(ctx, "acme", in))
	got, err := m.GetACRPolicy(ctx, "acme")
	ok(t, err)
	eq(t, got, in)

	// No aliasing: neither the caller's value nor a returned one is the stored one.
	in.Levels[0].AnyOf[0][0] = "mutated"
	got.Levels[1].Value = "mutated"
	again, err := m.GetACRPolicy(ctx, "acme")
	ok(t, err)
	if again.Levels[0].AnyOf[0][0] != core.AMRPassword || again.Levels[1].Value != core.ACRMultiFactor {
		t.Fatalf("stored policy aliases a caller's slice: %+v", again)
	}

	// Replace, per realm, unknown realm, delete (idempotent).
	small := core.ACRPolicy{Levels: []core.ACRLevel{{Value: "only", AnyOf: [][]string{{core.AMRMFA}}}}}
	ok(t, m.PutACRPolicy(ctx, "acme", small))
	got, err = m.GetACRPolicy(ctx, "acme")
	ok(t, err)
	eq(t, got, small)
	_, err = m.GetACRPolicy(ctx, "beta")
	is(t, err, idp.ErrNotFound)
	is(t, m.PutACRPolicy(ctx, "nope", small), idp.ErrNotFound)
	ok(t, m.DeleteACRPolicy(ctx, "acme"))
	ok(t, m.DeleteACRPolicy(ctx, "acme"))
	_, err = m.GetACRPolicy(ctx, "acme")
	is(t, err, idp.ErrNotFound)
}

func authnSession(t *testing.T, s core.Store) {
	m := authnStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	ok(t, s.PutSession(ctx, mkSession("s-1", "u-1")))
	ok(t, s.PutSession(ctx, mkSession("s-2", "u-1")))

	_, err := m.GetSessionAuthn(ctx, "acme", "s-1")
	is(t, err, idp.ErrNotFound)
	// The session must exist, in that realm.
	is(t, m.PutSessionAuthn(ctx, core.SessionAuthn{Realm: "acme", SessionID: "nope", AMR: []string{"pwd"}}), idp.ErrNotFound)
	is(t, m.PutSessionAuthn(ctx, core.SessionAuthn{Realm: "beta", SessionID: "s-1", AMR: []string{"pwd"}}), idp.ErrNotFound)

	in := core.SessionAuthn{Realm: "acme", SessionID: "s-1", AMR: []string{"pwd", "otp", "mfa"}}
	ok(t, m.PutSessionAuthn(ctx, in))
	got, err := m.GetSessionAuthn(ctx, "acme", "s-1")
	ok(t, err)
	eq(t, got, in)
	// Immutable: a record can never be raised after the fact.
	is(t, m.PutSessionAuthn(ctx, core.SessionAuthn{Realm: "acme", SessionID: "s-1", AMR: []string{"webauthn", "mfa"}}), idp.ErrConflict)
	got, _ = m.GetSessionAuthn(ctx, "acme", "s-1")
	eq(t, got, in)
	// Realm isolation, and an empty method list is allowed (reaches nothing).
	_, err = m.GetSessionAuthn(ctx, "beta", "s-1")
	is(t, err, idp.ErrNotFound)
	ok(t, m.PutSessionAuthn(ctx, core.SessionAuthn{Realm: "acme", SessionID: "s-2"}))
	got, err = m.GetSessionAuthn(ctx, "acme", "s-2")
	ok(t, err)
	if len(got.AMR) != 0 {
		t.Fatalf("empty amr came back as %v", got.AMR)
	}
	// The record dies with its session.
	_, err = s.TakeSession(ctx, "acme", "s-1")
	ok(t, err)
	_, err = m.GetSessionAuthn(ctx, "acme", "s-1")
	is(t, err, idp.ErrNotFound)
}

func authnSessionConcurrent(t *testing.T, s core.Store) {
	m := authnStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, s.PutSession(ctx, mkSession("s-1", "u-1")))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := m.PutSessionAuthn(ctx, core.SessionAuthn{Realm: "acme", SessionID: "s-1", AMR: []string{"pwd"}})
			switch {
			case err == nil:
				wins.Add(1)
			case !errors.Is(err, idp.ErrConflict):
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d writers won, want 1", wins.Load())
	}
}

func authnCascade(t *testing.T, s core.Store) {
	m := authnStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, m.PutACRPolicy(ctx, "acme", core.DefaultACRPolicy()))
	ok(t, s.PutSession(ctx, mkSession("s-1", "u-1")))
	ok(t, m.PutSessionAuthn(ctx, core.SessionAuthn{Realm: "acme", SessionID: "s-1", AMR: []string{"pwd"}}))
	ok(t, s.DeleteRealm(ctx, "acme"))
	mkRealm(t, s, "acme")
	_, err := m.GetACRPolicy(ctx, "acme")
	is(t, err, idp.ErrNotFound)
	_, err = m.GetSessionAuthn(ctx, "acme", "s-1")
	is(t, err, idp.ErrNotFound)
}
