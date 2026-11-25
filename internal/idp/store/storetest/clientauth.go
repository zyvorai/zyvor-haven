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
		Case{"ClientAuthConfig", clientAuthConfig},
		Case{"ClientAuthCascade", clientAuthCascade},
		Case{"ClientAssertionReplay", clientAssertionReplay},
		Case{"ClientAssertionConcurrent", clientAssertionConcurrent},
		Case{"ClientAssertionPurge", clientAssertionPurge},
	)
}

func clientAuthStore(t *testing.T, s core.Store) core.ClientAuthStore {
	t.Helper()
	cs, found := core.StoreAs[core.ClientAuthStore](s)
	if !found {
		t.Skip("store has no ClientAuthStore")
	}
	// The replay table is not tied to realms (nothing cascades when a realm
	// goes), so start every case from nothing left over by another.
	_, err := cs.PurgeExpiredClientAssertions(ctx, t0.Add(100*365*24*time.Hour))
	ok(t, err)
	return cs
}

func clientAuthClient(t *testing.T, s core.Store, realm, id string) core.Client {
	t.Helper()
	ok(t, s.CreateClient(ctx, core.Client{Realm: realm, ClientID: id, Enabled: true}))
	c, err := s.GetClientByClientID(ctx, realm, id)
	ok(t, err)
	return c
}

func clientAuthConfig(t *testing.T, s core.Store) {
	cs := clientAuthStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	cl := clientAuthClient(t, s, "acme", "svc")
	_, err := cs.GetClientAuth(ctx, "acme", cl.ID)
	is(t, err, idp.ErrNotFound)

	in := core.ClientAuth{Realm: "acme", ClientRef: cl.ID, Method: core.AuthMethodPrivateKeyJWT, JWKS: `{"keys":[]}`,
		JWKSURI: "https://c.example/jwks", SigningAlg: "ES256", TLSSubjectDN: "CN=a,O=b", TLSSANDNS: "a.example",
		TLSSANURI: "spiffe://a/b", TLSSANIP: "192.0.2.1", TLSSANEmail: "a@b.example", CertBoundTokens: true}
	ok(t, cs.PutClientAuth(ctx, in))
	got, err := cs.GetClientAuth(ctx, "acme", cl.ID)
	ok(t, err)
	eq(t, got, in)

	// Put replaces every field.
	next := core.ClientAuth{Realm: "acme", ClientRef: cl.ID, Method: core.AuthMethodTLS, TLSSANDNS: "x.example"}
	ok(t, cs.PutClientAuth(ctx, next))
	got, err = cs.GetClientAuth(ctx, "acme", cl.ID)
	ok(t, err)
	eq(t, got, next)

	// Another realm sees nothing, cannot write it and cannot delete it.
	_, err = cs.GetClientAuth(ctx, "other", cl.ID)
	is(t, err, idp.ErrNotFound)
	is(t, cs.PutClientAuth(ctx, core.ClientAuth{Realm: "other", ClientRef: cl.ID, Method: core.AuthMethodSecretPost}), idp.ErrNotFound)
	ok(t, cs.DeleteClientAuth(ctx, "other", cl.ID))
	got, err = cs.GetClientAuth(ctx, "acme", cl.ID)
	ok(t, err)
	eq(t, got, next)
	is(t, cs.PutClientAuth(ctx, core.ClientAuth{Realm: "acme", ClientRef: "no-such-client", Method: core.AuthMethodNone}), idp.ErrNotFound)

	ok(t, cs.DeleteClientAuth(ctx, "acme", cl.ID))
	_, err = cs.GetClientAuth(ctx, "acme", cl.ID)
	is(t, err, idp.ErrNotFound)
	ok(t, cs.DeleteClientAuth(ctx, "acme", cl.ID)) // idempotent
}

func clientAuthCascade(t *testing.T, s core.Store) {
	cs := clientAuthStore(t, s)
	mkRealm(t, s, "acme")
	cl := clientAuthClient(t, s, "acme", "svc")
	ok(t, cs.PutClientAuth(ctx, core.ClientAuth{Realm: "acme", ClientRef: cl.ID, Method: core.AuthMethodPrivateKeyJWT, JWKSURI: "https://a/k"}))
	ok(t, s.DeleteClient(ctx, "acme", cl.ID))
	_, err := cs.GetClientAuth(ctx, "acme", cl.ID)
	is(t, err, idp.ErrNotFound)
	again := clientAuthClient(t, s, "acme", "svc") // the same client_id starts from nothing
	_, err = cs.GetClientAuth(ctx, "acme", again.ID)
	is(t, err, idp.ErrNotFound)

	ok(t, cs.PutClientAuth(ctx, core.ClientAuth{Realm: "acme", ClientRef: again.ID, Method: core.AuthMethodSecretBasic}))
	ok(t, s.DeleteRealm(ctx, "acme"))
	mkRealm(t, s, "acme")
	_, err = cs.GetClientAuth(ctx, "acme", again.ID)
	is(t, err, idp.ErrNotFound)
}

func clientAssertionReplay(t *testing.T, s core.Store) {
	cs := clientAuthStore(t, s)
	exp := t0.Add(2 * time.Minute)
	ok(t, cs.RememberClientAssertion(ctx, "acme", "h1", t0, exp))
	if err := cs.RememberClientAssertion(ctx, "acme", "h1", t0.Add(time.Second), exp); !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("replay: %v", err)
	}
	ok(t, cs.RememberClientAssertion(ctx, "other", "h1", t0, exp)) // per realm
	ok(t, cs.RememberClientAssertion(ctx, "acme", "h2", t0, exp))
	if err := cs.RememberClientAssertion(ctx, "acme", "h1", exp.Add(-time.Microsecond), exp.Add(time.Hour)); !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("just before expiry: %v", err)
	}
	ok(t, cs.RememberClientAssertion(ctx, "acme", "h1", exp, exp.Add(time.Minute)))
}

func clientAssertionConcurrent(t *testing.T, s core.Store) {
	cs := clientAuthStore(t, s)
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch err := cs.RememberClientAssertion(ctx, "acme", "same", t0, t0.Add(time.Minute)); {
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

func clientAssertionPurge(t *testing.T, s core.Store) {
	cs := clientAuthStore(t, s)
	ok(t, cs.RememberClientAssertion(ctx, "acme", "old", t0, t0.Add(time.Minute)))
	ok(t, cs.RememberClientAssertion(ctx, "acme", "new", t0, t0.Add(time.Hour)))
	n, err := cs.PurgeExpiredClientAssertions(ctx, t0.Add(30*time.Minute))
	ok(t, err)
	eq(t, n, 1)
	if err := cs.RememberClientAssertion(ctx, "acme", "new", t0.Add(30*time.Minute), t0.Add(2*time.Hour)); !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("live entry must survive purge: %v", err)
	}
}
