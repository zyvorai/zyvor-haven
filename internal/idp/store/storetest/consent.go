// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"ConsentPolicy", consentPolicy},
		Case{"ConsentClient", consentClient},
		Case{"ConsentGrantLifecycle", consentGrantLifecycle},
		Case{"ConsentGrantRealmIsolation", consentGrantIsolation},
		Case{"ConsentRevokeClientRefresh", consentRevokeRefresh},
		Case{"ConsentBlocks", consentBlocks},
		Case{"ConsentReceiptChain", consentReceiptChain},
		Case{"ConsentReceiptConcurrent", consentReceiptConcurrent},
		Case{"ConsentRealmDeleteDropsAll", consentRealmDelete},
	)
}

func consentOf(t *testing.T, s core.Store) core.ConsentStore {
	t.Helper()
	c, found := core.StoreAs[core.ConsentStore](s)
	if !found {
		t.Skip("store does not implement core.ConsentStore")
	}
	return c
}

func consentPolicy(t *testing.T, s core.Store) {
	c := consentOf(t, s)
	mkRealm(t, s, "acme")
	_, err := c.GetConsentPolicy(ctx, "acme")
	is(t, err, idp.ErrNotFound)
	p := core.ConsentPolicy{Realm: "acme", CIMDEnabled: true, CIMDHosts: []string{"a.example"}, RequireAll: true,
		SkipClients: []string{"portal"}, RememberCIMD: true, GrantTTLSeconds: 3600}
	ok(t, c.PutConsentPolicy(ctx, p))
	got, err := c.GetConsentPolicy(ctx, "acme")
	ok(t, err)
	eq(t, got, p)
	p2 := core.ConsentPolicy{Realm: "acme"}
	ok(t, c.PutConsentPolicy(ctx, p2)) // replace, lists back to empty
	got, _ = c.GetConsentPolicy(ctx, "acme")
	eq(t, got, p2)
	is(t, c.PutConsentPolicy(ctx, core.ConsentPolicy{Realm: "ghost"}), idp.ErrNotFound)
}

func consentClient(t *testing.T, s core.Store) {
	c := consentOf(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	_, err := c.GetConsentClient(ctx, "acme", "https://a.example/c")
	is(t, err, idp.ErrNotFound)
	in := core.ConsentClient{Realm: "acme", ClientID: "https://a.example/c", Source: core.ConsentClientCIMD, Name: "A",
		ClientURI: "https://a.example", RedirectURIs: []string{"https://a.example/cb"}, Fingerprint: "fp1",
		FetchedAt: t0, ExpiresAt: t0.Add(time.Hour)}
	ok(t, c.PutConsentClient(ctx, in))
	got, err := c.GetConsentClient(ctx, "acme", in.ClientID)
	ok(t, err)
	eq(t, got, in)
	in.Name, in.Fingerprint = "B", "fp2" // upsert
	ok(t, c.PutConsentClient(ctx, in))
	got, _ = c.GetConsentClient(ctx, "acme", in.ClientID)
	eq(t, got, in)
	l, _ := c.ListConsentClients(ctx, "acme")
	eq(t, l, []core.ConsentClient{in})
	_, err = c.GetConsentClient(ctx, "other", in.ClientID)
	is(t, err, idp.ErrNotFound)
}

func mkConsentGrant(user, client string, scopes ...string) core.ConsentGrant {
	return core.ConsentGrant{Realm: "acme", UserID: user, ClientID: client, ClientName: "App", Scopes: scopes,
		Resources: []string{"https://mcp.example/mcp"}, Fingerprint: "fp", ExpiresAt: t0.Add(24 * time.Hour)}
}

func consentGrantLifecycle(t *testing.T, s core.Store) {
	c := consentOf(t, s)
	mkRealm(t, s, "acme")
	g, err := c.PutConsentGrant(ctx, mkConsentGrant("u1", "app", "openid"), t0)
	ok(t, err)
	if g.ID == "" || !g.CreatedAt.Equal(t0) || !g.UpdatedAt.Equal(t0) {
		t.Fatalf("grant not filled: %+v", g)
	}
	got, err := c.GetActiveConsentGrant(ctx, "acme", "u1", "app", t0)
	ok(t, err)
	eq(t, got, g)
	if !got.Covers([]string{"openid"}, nil) || got.Covers([]string{"openid", "email"}, nil) || got.Covers(nil, []string{"https://other"}) {
		t.Fatal("Covers wrong")
	}

	// A second put for the same (user, client) replaces in place.
	later := t0.Add(time.Hour)
	g2, err := c.PutConsentGrant(ctx, mkConsentGrant("u1", "app", "openid", "email"), later)
	ok(t, err)
	if g2.ID != g.ID || !g2.CreatedAt.Equal(t0) || !g2.UpdatedAt.Equal(later) || len(g2.Scopes) != 2 {
		t.Fatalf("upsert: %+v", g2)
	}
	l, _ := c.ListConsentGrants(ctx, "acme", "", "", false, later, 10)
	if len(l) != 1 {
		t.Fatalf("want one active grant, got %d", len(l))
	}

	// Expiry: expired grants are not active, but listed with includeEnded.
	_, err = c.GetActiveConsentGrant(ctx, "acme", "u1", "app", t0.Add(24*time.Hour))
	is(t, err, idp.ErrNotFound)
	l, _ = c.ListConsentGrants(ctx, "acme", "u1", "", false, t0.Add(48*time.Hour), 10)
	if len(l) != 0 {
		t.Fatal("expired grant listed as active")
	}
	l, _ = c.ListConsentGrants(ctx, "acme", "u1", "", true, t0.Add(48*time.Hour), 10)
	if len(l) != 1 {
		t.Fatal("ended grant must be listed with includeEnded")
	}

	// Revoke: once; the next consent creates a NEW grant, history is kept.
	r, err := c.RevokeConsentGrant(ctx, "acme", g.ID, "u1", later)
	ok(t, err)
	if r.RevokedBy != "u1" || !r.RevokedAt.Equal(later) {
		t.Fatalf("revoke: %+v", r)
	}
	_, err = c.RevokeConsentGrant(ctx, "acme", g.ID, "u1", later)
	is(t, err, idp.ErrConflict)
	_, err = c.RevokeConsentGrant(ctx, "acme", "nope", "u1", later)
	is(t, err, idp.ErrNotFound)
	_, err = c.GetActiveConsentGrant(ctx, "acme", "u1", "app", later)
	is(t, err, idp.ErrNotFound)
	g3, err := c.PutConsentGrant(ctx, mkConsentGrant("u1", "app", "openid"), later)
	ok(t, err)
	if g3.ID == g.ID {
		t.Fatal("a revoked grant must not be revived")
	}
	l, _ = c.ListConsentGrants(ctx, "acme", "u1", "app", true, later, 10)
	if len(l) != 2 {
		t.Fatalf("history: want 2 got %d", len(l))
	}

	// Client-wide revoke touches only that client's active grants.
	_, err = c.PutConsentGrant(ctx, mkConsentGrant("u2", "app", "openid"), later)
	ok(t, err)
	_, err = c.PutConsentGrant(ctx, mkConsentGrant("u2", "keep", "openid"), later)
	ok(t, err)
	n, err := c.RevokeClientConsentGrants(ctx, "acme", "app", "admin:root", later)
	ok(t, err)
	if n != 2 { // u1 (g3) and u2
		t.Fatalf("revoked %d, want 2", n)
	}
	_, err = c.GetActiveConsentGrant(ctx, "acme", "u2", "keep", later)
	ok(t, err)
}

func consentGrantIsolation(t *testing.T, s core.Store) {
	c := consentOf(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	g, err := c.PutConsentGrant(ctx, mkConsentGrant("u1", "app", "openid"), t0)
	ok(t, err)
	_, err = c.GetConsentGrant(ctx, "other", g.ID)
	is(t, err, idp.ErrNotFound)
	_, err = c.RevokeConsentGrant(ctx, "other", g.ID, "x", t0)
	is(t, err, idp.ErrNotFound)
	_, err = c.GetActiveConsentGrant(ctx, "other", "u1", "app", t0)
	is(t, err, idp.ErrNotFound)
	n, _ := c.RevokeClientConsentGrants(ctx, "other", "app", "x", t0)
	if n != 0 {
		t.Fatal("cross-realm revoke")
	}
	_, err = c.GetActiveConsentGrant(ctx, "acme", "u1", "app", t0)
	ok(t, err)
}

func consentRevokeRefresh(t *testing.T, s core.Store) {
	c := consentOf(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	put := func(hash, realm, client, user string) {
		ok(t, s.PutRefreshToken(ctx, core.RefreshToken{TokenHash: hash, FamilyID: "f-" + hash, Realm: realm, ClientID: client,
			UserID: user, Scope: "openid", ExpiresAt: t0.Add(time.Hour), CreatedAt: t0}))
	}
	put("h1", "acme", "app", "u1")
	put("h2", "acme", "app", "u2")
	put("h3", "acme", "keep", "u1")
	put("h4", "other", "app", "u1")
	n, err := c.RevokeClientRefreshTokens(ctx, "acme", "app", "u1")
	ok(t, err)
	if n != 1 {
		t.Fatalf("per-user revoke: %d", n)
	}
	n, _ = c.RevokeClientRefreshTokens(ctx, "acme", "app", "")
	if n != 1 { // only h2 still active
		t.Fatalf("client-wide revoke: %d", n)
	}
	for hash, want := range map[string]bool{"h1": true, "h2": true, "h3": false, "h4": false} {
		tk, err := s.GetRefreshToken(ctx, hash)
		ok(t, err)
		if tk.Revoked != want {
			t.Fatalf("%s revoked=%v want %v", hash, tk.Revoked, want)
		}
	}
}

func consentBlocks(t *testing.T, s core.Store) {
	c := consentOf(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	_, err := c.GetConsentBlock(ctx, "acme", "app")
	is(t, err, idp.ErrNotFound)
	b := core.ConsentBlock{Realm: "acme", ClientID: "app", Reason: "bad", By: "admin:x", At: t0}
	ok(t, c.PutConsentBlock(ctx, b))
	ok(t, c.PutConsentBlock(ctx, b)) // idempotent
	got, err := c.GetConsentBlock(ctx, "acme", "app")
	ok(t, err)
	eq(t, got, b)
	_, err = c.GetConsentBlock(ctx, "other", "app")
	is(t, err, idp.ErrNotFound)
	l, _ := c.ListConsentBlocks(ctx, "acme")
	eq(t, l, []core.ConsentBlock{b})
	ok(t, c.DeleteConsentBlock(ctx, "acme", "app"))
	is(t, c.DeleteConsentBlock(ctx, "acme", "app"), idp.ErrNotFound)
}

func consentReceiptChain(t *testing.T, s core.Store) {
	c := consentOf(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	_, err := c.HeadConsentReceipt(ctx, "acme")
	is(t, err, idp.ErrNotFound)
	var all []core.ConsentReceipt
	for i, typ := range []string{core.ReceiptGrant, core.ReceiptRevoke, core.ReceiptKill} {
		user := "u1"
		if i == 2 {
			user = ""
		}
		r, err := c.AppendConsentReceipt(ctx, core.ConsentReceipt{Realm: "acme", Time: t0.Add(time.Duration(i) * time.Minute),
			Type: typ, UserID: user, ClientID: "app", ClientName: "App", Scopes: []string{"openid"}, Actor: "u1", Detail: "d"})
		ok(t, err)
		if r.Seq != int64(i+1) || r.Hash == "" || r.Hash != core.ConsentReceiptHash(r) {
			t.Fatalf("receipt %d: %+v", i, r)
		}
		all = append(all, r)
	}
	if all[0].PrevHash != "" || all[1].PrevHash != all[0].Hash || all[2].PrevHash != all[1].Hash {
		t.Fatal("chain links wrong")
	}
	got, err := c.ListConsentReceipts(ctx, "acme", "", 0, 0)
	ok(t, err)
	ok(t, core.VerifyConsentChain(got, 0, ""))
	if len(got) != 3 || got[2].Hash != all[2].Hash {
		t.Fatalf("list: %+v", got)
	}
	// Reading back must not change what the hash covers (time precision, nil vs empty).
	got2, _ := c.ListConsentReceipts(ctx, "acme", "", 1, 0)
	ok(t, core.VerifyConsentChain(got2, 1, all[0].Hash))
	u1, _ := c.ListConsentReceipts(ctx, "acme", "u1", 0, 0)
	if len(u1) != 2 {
		t.Fatalf("per-user list: %d", len(u1))
	}
	lim, _ := c.ListConsentReceipts(ctx, "acme", "", 0, 2)
	if len(lim) != 2 {
		t.Fatalf("limit: %d", len(lim))
	}
	head, err := c.HeadConsentReceipt(ctx, "acme")
	ok(t, err)
	eq(t, head, got[2])
	// Chains are per realm.
	r, err := c.AppendConsentReceipt(ctx, core.ConsentReceipt{Realm: "other", Time: t0, Type: core.ReceiptGrant})
	ok(t, err)
	if r.Seq != 1 || r.PrevHash != "" {
		t.Fatalf("other realm chain: %+v", r)
	}
	_, err = c.AppendConsentReceipt(ctx, core.ConsentReceipt{Realm: "ghost", Type: core.ReceiptGrant})
	is(t, err, idp.ErrNotFound)
}

func consentReceiptConcurrent(t *testing.T, s core.Store) {
	c := consentOf(t, s)
	mkRealm(t, s, "acme")
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.AppendConsentReceipt(ctx, core.ConsentReceipt{Realm: "acme", Time: t0, Type: core.ReceiptGrant, ClientID: "app"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		ok(t, err)
	}
	got, err := c.ListConsentReceipts(ctx, "acme", "", 0, 0)
	ok(t, err)
	if len(got) != n {
		t.Fatalf("got %d receipts, want %d", len(got), n)
	}
	ok(t, core.VerifyConsentChain(got, 0, "")) // consecutive seqs and intact links under concurrency
}

func consentRealmDelete(t *testing.T, s core.Store) {
	c := consentOf(t, s)
	mkRealm(t, s, "acme")
	_, err := c.PutConsentGrant(ctx, mkConsentGrant("u1", "app", "openid"), t0)
	ok(t, err)
	ok(t, c.PutConsentBlock(ctx, core.ConsentBlock{Realm: "acme", ClientID: "app", At: t0}))
	_, err = c.AppendConsentReceipt(ctx, core.ConsentReceipt{Realm: "acme", Type: core.ReceiptGrant})
	ok(t, err)
	ok(t, s.DeleteRealm(ctx, "acme"))
	mkRealm(t, s, "acme") // same name: nothing may leak into the new realm
	_, err = c.GetActiveConsentGrant(ctx, "acme", "u1", "app", t0)
	is(t, err, idp.ErrNotFound)
	_, err = c.GetConsentBlock(ctx, "acme", "app")
	is(t, err, idp.ErrNotFound)
	_, err = c.HeadConsentReceipt(ctx, "acme")
	is(t, err, idp.ErrNotFound)
}
