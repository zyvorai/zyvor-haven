// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"DPoPProofReplay", dpopReplay},
		Case{"DPoPProofConcurrent", dpopConcurrent},
		Case{"DPoPRefreshBinding", dpopBinding},
		Case{"DPoPPurge", dpopPurge},
	)
}

func dpopStore(t *testing.T, s core.Store) core.DPoPStore {
	t.Helper()
	ds, found := core.StoreAs[core.DPoPStore](s)
	if !found {
		t.Skip("store has no DPoPStore")
	}
	// The DPoP tables are not tied to realms (nothing cascades when a realm
	// goes), so start every case from nothing left over by another.
	_, err := ds.PurgeExpiredDPoP(ctx, t0.Add(100*365*24*time.Hour))
	ok(t, err)
	return ds
}

func dpopReplay(t *testing.T, s core.Store) {
	ds := dpopStore(t, s)
	exp := t0.Add(2 * time.Minute)
	ok(t, ds.RememberDPoPProof(ctx, "acme", "h1", t0, exp))
	if err := ds.RememberDPoPProof(ctx, "acme", "h1", t0.Add(time.Second), exp); !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("replay: %v", err)
	}
	// Same hash in another realm is a different proof.
	ok(t, ds.RememberDPoPProof(ctx, "other", "h1", t0, exp))
	// Last instant before expiry still a replay; at expiry it may be reused.
	if err := ds.RememberDPoPProof(ctx, "acme", "h1", exp.Add(-time.Microsecond), exp.Add(time.Hour)); !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("just before expiry: %v", err)
	}
	ok(t, ds.RememberDPoPProof(ctx, "acme", "h1", exp, exp.Add(time.Minute)))
}

func dpopConcurrent(t *testing.T, s core.Store) {
	ds := dpopStore(t, s)
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := ds.RememberDPoPProof(ctx, "acme", "same", t0, t0.Add(time.Minute)); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, idp.ErrConflict):
				conflicts.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != 15 {
		t.Fatalf("wins=%d conflicts=%d", wins.Load(), conflicts.Load())
	}
}

func dpopBinding(t *testing.T, s core.Store) {
	ds := dpopStore(t, s)
	if _, err := ds.RefreshTokenBinding(ctx, "rt1", t0); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("unbound: %v", err)
	}
	exp := t0.Add(time.Hour)
	ok(t, ds.BindRefreshToken(ctx, "rt1", "jktA", exp))
	got, err := ds.RefreshTokenBinding(ctx, "rt1", t0)
	ok(t, err)
	eq(t, got, "jktA")
	ok(t, ds.BindRefreshToken(ctx, "rt1", "jktA", exp)) // same key: no-op
	if err := ds.BindRefreshToken(ctx, "rt1", "jktB", exp); !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("rebind to another key: %v", err)
	}
	got, _ = ds.RefreshTokenBinding(ctx, "rt1", t0)
	eq(t, got, "jktA") // unchanged by the failed rebind
	if _, err := ds.RefreshTokenBinding(ctx, "rt1", exp); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("expired binding must read as unbound: %v", err)
	}
}

func dpopPurge(t *testing.T, s core.Store) {
	ds := dpopStore(t, s)
	ok(t, ds.RememberDPoPProof(ctx, "acme", "old", t0, t0.Add(time.Minute)))
	ok(t, ds.RememberDPoPProof(ctx, "acme", "new", t0, t0.Add(time.Hour)))
	ok(t, ds.BindRefreshToken(ctx, "rtold", "j", t0.Add(time.Minute)))
	ok(t, ds.BindRefreshToken(ctx, "rtnew", "j", t0.Add(time.Hour)))
	n, err := ds.PurgeExpiredDPoP(ctx, t0.Add(30*time.Minute))
	ok(t, err)
	eq(t, n, 2)
	if err := ds.RememberDPoPProof(ctx, "acme", "new", t0.Add(30*time.Minute), t0.Add(2*time.Hour)); !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("live proof must survive purge: %v", err)
	}
	if _, err := ds.RefreshTokenBinding(ctx, "rtnew", t0.Add(30*time.Minute)); err != nil {
		t.Fatalf("live binding must survive purge: %v", err)
	}
}
