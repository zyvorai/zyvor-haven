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
		Case{"FAPIClientSettings", fapiClientSettings},
		Case{"FAPIRequestSingleUse", fapiRequestSingleUse},
		Case{"FAPIRequestConcurrent", fapiRequestConcurrent},
		Case{"FAPIBindings", fapiBindings},
		Case{"FAPIPurge", fapiPurge},
	)
}

func fapiStore(t *testing.T, s core.Store) core.FAPIStore {
	t.Helper()
	fs, found := core.StoreAs[core.FAPIStore](s)
	if !found {
		t.Skip("store has no FAPIStore")
	}
	return fs
}

func fapiClient(t *testing.T, s core.Store, realm, id string) core.Client {
	t.Helper()
	ok(t, s.CreateClient(ctx, core.Client{Realm: realm, ClientID: id, Enabled: true, AuthCodeFlow: true}))
	c, err := s.GetClientByClientID(ctx, realm, id)
	ok(t, err)
	return c
}

func fapiClientSettings(t *testing.T, s core.Store) {
	fs := fapiStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	c := fapiClient(t, s, "acme", "app")
	_, err := fs.GetClientFAPI(ctx, "acme", c.ID)
	is(t, err, idp.ErrNotFound) // never set: defaults
	in := core.ClientFAPI{Realm: "acme", ClientRef: c.ID, RequirePAR: true, RequireDPoP: true, RequireSignedRequest: true,
		JWKS: `{"keys":[]}`, AuthzDetailTypes: []string{"payment_initiation", "account_information"}}
	ok(t, fs.PutClientFAPI(ctx, in))
	got, err := fs.GetClientFAPI(ctx, "acme", c.ID)
	ok(t, err)
	eq(t, got, in)
	// Returned slices are copies.
	got.AuthzDetailTypes[0] = "tampered"
	again, _ := fs.GetClientFAPI(ctx, "acme", c.ID)
	eq(t, again.AuthzDetailTypes[0], "payment_initiation")
	// Replace, with empty types.
	ok(t, fs.PutClientFAPI(ctx, core.ClientFAPI{Realm: "acme", ClientRef: c.ID}))
	got, err = fs.GetClientFAPI(ctx, "acme", c.ID)
	ok(t, err)
	eq(t, got, core.ClientFAPI{Realm: "acme", ClientRef: c.ID})
	// Unknown client and cross-realm access.
	is(t, fs.PutClientFAPI(ctx, core.ClientFAPI{Realm: "acme", ClientRef: "nope"}), idp.ErrNotFound)
	is(t, fs.PutClientFAPI(ctx, core.ClientFAPI{Realm: "beta", ClientRef: c.ID}), idp.ErrNotFound)
	_, err = fs.GetClientFAPI(ctx, "beta", c.ID)
	is(t, err, idp.ErrNotFound)
	// Deleting the client deletes its settings: a re-created client_id starts from defaults.
	ok(t, fs.PutClientFAPI(ctx, core.ClientFAPI{Realm: "acme", ClientRef: c.ID, RequirePAR: true, JWKS: "k"}))
	ok(t, s.DeleteClient(ctx, "acme", c.ID))
	c2 := fapiClient(t, s, "acme", "app")
	_, err = fs.GetClientFAPI(ctx, "acme", c2.ID)
	is(t, err, idp.ErrNotFound)
	_, err = fs.GetClientFAPI(ctx, "acme", c.ID)
	is(t, err, idp.ErrNotFound)
	ok(t, fs.DeleteClientFAPI(ctx, "acme", c2.ID)) // idempotent
}

func fapiReq(kind, id string, exp time.Time) core.FAPIRequest {
	return core.FAPIRequest{Kind: kind, IDHash: id, Realm: "acme", ClientID: "app", Params: `{"state":"s"}`, ExpiresAt: exp}
}

func fapiRequestSingleUse(t *testing.T, s core.Store) {
	fs := fapiStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	exp := t0.Add(time.Minute)
	ok(t, fs.PutFAPIRequest(ctx, fapiReq(core.FAPIKindPAR, "h1", exp)))
	is(t, fs.PutFAPIRequest(ctx, fapiReq(core.FAPIKindPAR, "h1", exp)), idp.ErrConflict)
	ok(t, fs.PutFAPIRequest(ctx, fapiReq(core.FAPIKindCtx, "h1", exp))) // kinds are separate namespaces
	// Wrong realm / wrong kind find nothing and do not consume.
	_, err := fs.ConsumeFAPIRequest(ctx, "beta", core.FAPIKindPAR, "h1", t0)
	is(t, err, idp.ErrNotFound)
	// GetFAPIRequest does not consume.
	g, err := fs.GetFAPIRequest(ctx, "acme", core.FAPIKindCtx, "h1", t0)
	ok(t, err)
	eq(t, g, fapiReq(core.FAPIKindCtx, "h1", exp))
	_, err = fs.GetFAPIRequest(ctx, "acme", core.FAPIKindCtx, "h1", t0)
	ok(t, err)
	// Consume once.
	got, err := fs.ConsumeFAPIRequest(ctx, "acme", core.FAPIKindPAR, "h1", t0)
	ok(t, err)
	eq(t, got, fapiReq(core.FAPIKindPAR, "h1", exp))
	_, err = fs.ConsumeFAPIRequest(ctx, "acme", core.FAPIKindPAR, "h1", t0)
	is(t, err, idp.ErrNotFound)
	// The ctx row of the same id is untouched.
	_, err = fs.GetFAPIRequest(ctx, "acme", core.FAPIKindCtx, "h1", t0)
	ok(t, err)
	// Expired: not readable, not consumable.
	_, err = fs.GetFAPIRequest(ctx, "acme", core.FAPIKindCtx, "h1", exp)
	is(t, err, idp.ErrNotFound)
	ok(t, fs.PutFAPIRequest(ctx, fapiReq(core.FAPIKindPAR, "h2", exp)))
	_, err = fs.ConsumeFAPIRequest(ctx, "acme", core.FAPIKindPAR, "h2", exp)
	is(t, err, idp.ErrNotFound)
	// Unknown realm.
	is(t, fs.PutFAPIRequest(ctx, core.FAPIRequest{Kind: core.FAPIKindPAR, IDHash: "x", Realm: "ghost", ExpiresAt: exp}), idp.ErrNotFound)
}

func fapiRequestConcurrent(t *testing.T, s core.Store) {
	fs := fapiStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, fs.PutFAPIRequest(ctx, fapiReq(core.FAPIKindPAR, "same", t0.Add(time.Minute))))
	var wins, misses atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch _, err := fs.ConsumeFAPIRequest(ctx, "acme", core.FAPIKindPAR, "same", t0); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, idp.ErrNotFound):
				misses.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || misses.Load() != 15 {
		t.Fatalf("wins=%d misses=%d", wins.Load(), misses.Load())
	}
}

func fapiBindings(t *testing.T, s core.Store) {
	fs := fapiStore(t, s)
	mkRealm(t, s, "acme")
	_, err := fs.GetFAPIBinding(ctx, core.FAPIKindCode, "c1", t0)
	is(t, err, idp.ErrNotFound)
	exp := t0.Add(time.Hour)
	b := core.FAPIBinding{Kind: core.FAPIKindCode, KeyHash: "c1", Realm: "acme", ClientID: "app",
		Details: `[{"type":"payment_initiation"}]`, DPoPJKT: "jkt", ExpiresAt: exp}
	ok(t, fs.PutFAPIBinding(ctx, b))
	got, err := fs.GetFAPIBinding(ctx, core.FAPIKindCode, "c1", t0)
	ok(t, err)
	eq(t, got, b)
	_, err = fs.GetFAPIBinding(ctx, core.FAPIKindRefresh, "c1", t0) // kind separates namespaces
	is(t, err, idp.ErrNotFound)
	// Upsert replaces.
	b.Details = `[{"type":"other"}]`
	ok(t, fs.PutFAPIBinding(ctx, b))
	got, _ = fs.GetFAPIBinding(ctx, core.FAPIKindCode, "c1", t0)
	eq(t, got.Details, b.Details)
	_, err = fs.GetFAPIBinding(ctx, core.FAPIKindCode, "c1", exp)
	is(t, err, idp.ErrNotFound)
}

func fapiPurge(t *testing.T, s core.Store) {
	fs := fapiStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, fs.PutFAPIRequest(ctx, fapiReq(core.FAPIKindPAR, "old", t0.Add(time.Minute))))
	ok(t, fs.PutFAPIRequest(ctx, fapiReq(core.FAPIKindPAR, "new", t0.Add(time.Hour))))
	ok(t, fs.PutFAPIBinding(ctx, core.FAPIBinding{Kind: core.FAPIKindCode, KeyHash: "old", Realm: "acme", ExpiresAt: t0.Add(time.Minute)}))
	ok(t, fs.PutFAPIBinding(ctx, core.FAPIBinding{Kind: core.FAPIKindCode, KeyHash: "new", Realm: "acme", ExpiresAt: t0.Add(time.Hour)}))
	n, err := fs.PurgeExpiredFAPI(ctx, t0.Add(30*time.Minute))
	ok(t, err)
	eq(t, n, 2)
	if _, err := fs.GetFAPIRequest(ctx, "acme", core.FAPIKindPAR, "new", t0.Add(30*time.Minute)); err != nil {
		t.Fatalf("live request must survive purge: %v", err)
	}
	if _, err := fs.GetFAPIBinding(ctx, core.FAPIKindCode, "new", t0.Add(30*time.Minute)); err != nil {
		t.Fatalf("live binding must survive purge: %v", err)
	}
}
