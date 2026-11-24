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
		Case{"DCRInitialTokenLifecycle", dcrTokenLifecycle},
		Case{"DCRInitialTokenConsumeOnce", dcrTokenConsumeOnce},
		Case{"DCRRegisteredClient", dcrRegisteredClient},
		Case{"DCRPolicy", dcrPolicy},
		Case{"DCRRealmIsolation", dcrIsolation},
	)
}

func dcrOf(t *testing.T, s core.Store) core.DCRStore {
	t.Helper()
	d, found := core.StoreAs[core.DCRStore](s)
	if !found {
		t.Skip("store does not implement core.DCRStore")
	}
	return d
}

func mkIAT(id, hash string, count int) core.InitialAccessToken {
	return core.InitialAccessToken{ID: id, Realm: "acme", TokenHash: hash, Note: "ci", Count: count,
		Remaining: count, CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
}

func dcrTokenLifecycle(t *testing.T, s core.Store) {
	d := dcrOf(t, s)
	mkRealm(t, s, "acme")
	in := mkIAT("t-1", "h-1", 2)
	ok(t, d.PutInitialAccessToken(ctx, in))
	is(t, d.PutInitialAccessToken(ctx, mkIAT("t-1", "h-other", 1)), idp.ErrConflict)
	is(t, d.PutInitialAccessToken(ctx, mkIAT("t-2", "h-1", 1)), idp.ErrConflict)

	l, err := d.ListInitialAccessTokens(ctx, "acme")
	ok(t, err)
	eq(t, l, []core.InitialAccessToken{in})

	got, err := d.ConsumeInitialAccessToken(ctx, "acme", "h-1", t0)
	ok(t, err)
	if got.Remaining != 1 || got.ID != "t-1" {
		t.Fatalf("consume: %+v", got)
	}
	// Refund never exceeds Count and a missing token is not an error.
	ok(t, d.RefundInitialAccessToken(ctx, "acme", "t-1"))
	ok(t, d.RefundInitialAccessToken(ctx, "acme", "t-1"))
	ok(t, d.RefundInitialAccessToken(ctx, "acme", "nope"))
	l, _ = d.ListInitialAccessTokens(ctx, "acme")
	if l[0].Remaining != 2 {
		t.Fatalf("refund capped wrongly: %d", l[0].Remaining)
	}

	// Exhausted, expired, unknown and revoked all look the same.
	_, err = d.ConsumeInitialAccessToken(ctx, "acme", "h-1", t0)
	ok(t, err)
	_, err = d.ConsumeInitialAccessToken(ctx, "acme", "h-1", t0)
	ok(t, err)
	_, err = d.ConsumeInitialAccessToken(ctx, "acme", "h-1", t0)
	is(t, err, idp.ErrNotFound)
	ok(t, d.PutInitialAccessToken(ctx, mkIAT("t-3", "h-3", 1)))
	_, err = d.ConsumeInitialAccessToken(ctx, "acme", "h-3", t0.Add(time.Hour)) // expires_at == now: expired
	is(t, err, idp.ErrNotFound)
	_, err = d.ConsumeInitialAccessToken(ctx, "acme", "nope", t0)
	is(t, err, idp.ErrNotFound)
	ok(t, d.DeleteInitialAccessToken(ctx, "acme", "t-3"))
	_, err = d.ConsumeInitialAccessToken(ctx, "acme", "h-3", t0)
	is(t, err, idp.ErrNotFound)
	is(t, d.DeleteInitialAccessToken(ctx, "acme", "t-3"), idp.ErrNotFound)
	is(t, d.PutInitialAccessToken(ctx, core.InitialAccessToken{ID: "x", Realm: "missing", TokenHash: "hx",
		Count: 1, Remaining: 1, ExpiresAt: t0}), idp.ErrNotFound)
}

// Exactly Count of many concurrent consumers win.
func dcrTokenConsumeOnce(t *testing.T, s core.Store) {
	d := dcrOf(t, s)
	mkRealm(t, s, "acme")
	ok(t, d.PutInitialAccessToken(ctx, mkIAT("t-1", "h-1", 3)))
	var wg sync.WaitGroup
	var won atomic.Int32
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.ConsumeInitialAccessToken(ctx, "acme", "h-1", t0); err == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 3 {
		t.Fatalf("%d consumers won, want exactly 3", won.Load())
	}
}

func dcrRegisteredClient(t *testing.T, s core.Store) {
	d := dcrOf(t, s)
	mkRealm(t, s, "acme")
	ok(t, s.CreateClient(ctx, core.Client{ID: "uuid-1", Realm: "acme", ClientID: "hc_one", Enabled: true, CreatedAt: t0}))
	in := core.RegisteredClient{
		Realm: "acme", ClientID: "hc_one", ClientUUID: "uuid-1", RegTokenHash: "rh-1", CreatedVia: core.DCRCreatedVia,
		InitialTokenID: "t-1", ApplicationType: "native", TokenAuthMethod: "none", Scope: "openid profile",
		GrantTypes: []string{"authorization_code", "refresh_token"}, Contacts: []string{"a@example.com"},
		LogoURI: "https://e.example/l.png", ClientURI: "https://e.example", PolicyURI: "https://e.example/p",
		TosURI: "https://e.example/t", CreatedAt: t0, UpdatedAt: t0,
	}
	ok(t, d.PutRegisteredClient(ctx, in))
	is(t, d.PutRegisteredClient(ctx, in), idp.ErrConflict)
	got, err := d.GetRegisteredClient(ctx, "acme", "hc_one")
	ok(t, err)
	eq(t, got, in)

	up := in
	up.ApplicationType, up.Scope, up.GrantTypes, up.Contacts = "web", "openid", []string{"authorization_code"}, nil
	up.LogoURI, up.UpdatedAt = "", t0.Add(time.Minute)
	up.RegTokenHash, up.InitialTokenID, up.CreatedAt = "tampered", "tampered", t0.Add(time.Hour)
	ok(t, d.UpdateRegisteredClient(ctx, up))
	got, err = d.GetRegisteredClient(ctx, "acme", "hc_one")
	ok(t, err)
	if got.RegTokenHash != "rh-1" || got.InitialTokenID != "t-1" || !got.CreatedAt.Equal(t0) || got.ClientUUID != "uuid-1" {
		t.Fatalf("update changed identity fields: %+v", got)
	}
	if got.ApplicationType != "web" || got.Scope != "openid" || got.LogoURI != "" || len(got.Contacts) != 0 ||
		len(got.GrantTypes) != 1 || !got.UpdatedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("update not applied: %+v", got)
	}
	l, err := d.ListRegisteredClients(ctx, "acme")
	ok(t, err)
	if len(l) != 1 || l[0].ClientID != "hc_one" {
		t.Fatalf("list: %+v", l)
	}
	ok(t, d.DeleteRegisteredClient(ctx, "acme", "hc_one"))
	_, err = d.GetRegisteredClient(ctx, "acme", "hc_one")
	is(t, err, idp.ErrNotFound)
	is(t, d.DeleteRegisteredClient(ctx, "acme", "hc_one"), idp.ErrNotFound)
	is(t, d.UpdateRegisteredClient(ctx, up), idp.ErrNotFound)
}

func dcrPolicy(t *testing.T, s core.Store) {
	d := dcrOf(t, s)
	mkRealm(t, s, "acme")
	_, err := d.GetRegistrationPolicy(ctx, "acme")
	is(t, err, idp.ErrNotFound)
	p := core.RegistrationPolicy{Realm: "acme", MaxClients: 5, AllowedGrantTypes: []string{"authorization_code"}}
	ok(t, d.PutRegistrationPolicy(ctx, p))
	got, err := d.GetRegistrationPolicy(ctx, "acme")
	ok(t, err)
	eq(t, got, p)
	p.MaxClients, p.AllowedGrantTypes = 0, []string{"client_credentials", "refresh_token"}
	ok(t, d.PutRegistrationPolicy(ctx, p))
	got, _ = d.GetRegistrationPolicy(ctx, "acme")
	eq(t, got, p)
	is(t, d.PutRegistrationPolicy(ctx, core.RegistrationPolicy{Realm: "nope", MaxClients: 1}), idp.ErrNotFound)
}

func dcrIsolation(t *testing.T, s core.Store) {
	d := dcrOf(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, d.PutInitialAccessToken(ctx, mkIAT("t-1", "h-1", 1)))
	_, err := d.ConsumeInitialAccessToken(ctx, "other", "h-1", t0)
	is(t, err, idp.ErrNotFound)
	is(t, d.DeleteInitialAccessToken(ctx, "other", "t-1"), idp.ErrNotFound)
	l, _ := d.ListInitialAccessTokens(ctx, "other")
	if len(l) != 0 {
		t.Fatalf("other realm sees tokens: %+v", l)
	}
	_, err = d.GetRegisteredClient(ctx, "other", "hc_one")
	is(t, err, idp.ErrNotFound)
}
