// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(Case{Name: "SigningKeyOneActivePerRealm", Fn: signingKeyOneActive})
}

func activeCount(t *testing.T, s core.Store, realm string) int {
	t.Helper()
	keys, err := s.ListSigningKeys(ctx, realm)
	ok(t, err)
	n := 0
	for _, k := range keys {
		if k.Active {
			n++
		}
	}
	return n
}

// A realm has exactly one active signing key. This used to be enforced only by
// an in-process check, so two replicas starting together each created one.
func signingKeyOneActive(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mk := func(realm, kid string, active bool) core.SigningKey {
		return core.SigningKey{KID: kid, Realm: realm, Alg: "ES256", PrivatePEM: []byte("pem-" + kid),
			PublicJWK: []byte(`{"kid":"` + kid + `"}`), Active: active, CreatedAt: t0}
	}

	ok(t, s.PutSigningKey(ctx, mk("acme", "k1", true)))
	if err := s.PutSigningKey(ctx, mk("acme", "k2", true)); !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("a second active key for the realm must be refused with ErrConflict, got %v", err)
	}
	if n := activeCount(t, s, "acme"); n != 1 {
		t.Fatalf("%d active keys after the refused insert", n)
	}
	// Rewriting the active key itself is not a conflict.
	ok(t, s.PutSigningKey(ctx, mk("acme", "k1", true)))
	// Inactive keys are unlimited.
	ok(t, s.PutSigningKey(ctx, mk("acme", "old1", false)))
	ok(t, s.PutSigningKey(ctx, mk("acme", "old2", false)))
	// Rotation order: demote the current key, then activate the next.
	ok(t, s.PutSigningKey(ctx, mk("acme", "k1", false)))
	ok(t, s.PutSigningKey(ctx, mk("acme", "k2", true)))
	if n := activeCount(t, s, "acme"); n != 1 {
		t.Fatalf("%d active keys after rotation", n)
	}
	// The invariant is per realm.
	mkRealm(t, s, "other")
	ok(t, s.PutSigningKey(ctx, mk("other", "o1", true)))

	// Racing creators, as two replicas starting together: exactly one wins and
	// everybody else gets ErrConflict (never a second active key, never another error).
	mkRealm(t, s, "race")
	const n = 24
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			k := mk("race", fmt.Sprintf("r%02d", i), true)
			k.CreatedAt = t0.Add(time.Duration(i) * time.Millisecond)
			errs[i] = s.PutSigningKey(ctx, k)
		}(i)
	}
	close(start)
	wg.Wait()
	wins := 0
	for i, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, idp.ErrConflict):
			t.Fatalf("creator %d: unexpected error %v", i, err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d creators won the race, want exactly 1", wins)
	}
	if got := activeCount(t, s, "race"); got != 1 {
		t.Fatalf("%d active keys after the race", got)
	}
}
