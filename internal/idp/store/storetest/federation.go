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
		Case{"FedProviders", fedProviders},
		Case{"FedLinks", fedLinks},
		Case{"FedLinkCascade", fedCascade},
		Case{"FedStateSingleUse", fedStateSingleUse},
	)
}

func fedStore(t *testing.T, st core.Store) core.FedStore {
	t.Helper()
	fs, found := core.StoreAs[core.FedStore](st)
	if !found {
		t.Skip("store does not implement core.FedStore")
	}
	return fs
}

func fedFixture(t *testing.T, st core.Store, realms ...string) {
	t.Helper()
	for _, r := range realms {
		ok(t, st.CreateRealm(ctx, core.Realm{Name: r, Enabled: true}))
		ok(t, st.CreateUser(ctx, core.User{ID: "u-" + r, Realm: r, Username: "alice", Enabled: true}))
		ok(t, st.CreateUser(ctx, core.User{ID: "u2-" + r, Realm: r, Username: "bob", Enabled: true}))
	}
}

func fedProviders(t *testing.T, st core.Store) {
	fs := fedStore(t, st)
	fedFixture(t, st, "acme", "other")
	p := core.FedProvider{Realm: "acme", Alias: "google", DisplayName: "Google", ProviderType: "google", Enabled: true,
		Config: map[string]string{"clientId": "cid", "scopes": "openid email"}, ClientSecretSealed: "v1.sealed"}
	ok(t, fs.CreateFedProvider(ctx, p))
	is(t, fs.CreateFedProvider(ctx, p), idp.ErrConflict)
	// Same alias in another realm is fine.
	p2 := p
	p2.Realm = "other"
	ok(t, fs.CreateFedProvider(ctx, p2))

	got, err := fs.GetFedProvider(ctx, "acme", "google")
	ok(t, err)
	if got.DisplayName != "Google" || got.Config["clientId"] != "cid" || got.ClientSecretSealed != "v1.sealed" || !got.Enabled || got.CreatedAt.IsZero() {
		t.Fatalf("got %+v", got)
	}
	got.Config["clientId"] = "mutated" // a copy: must not leak into the store
	again, _ := fs.GetFedProvider(ctx, "acme", "google")
	if again.Config["clientId"] != "cid" {
		t.Fatal("store returned shared map")
	}

	p.DisplayName, p.Enabled, p.TrustEmail, p.ClientSecretSealed = "G", false, true, ""
	p.Config = map[string]string{"clientId": "cid2"}
	ok(t, fs.UpdateFedProvider(ctx, p))
	got, _ = fs.GetFedProvider(ctx, "acme", "google")
	if got.DisplayName != "G" || got.Enabled || !got.TrustEmail || got.ClientSecretSealed != "" || got.Config["clientId"] != "cid2" || got.CreatedAt.IsZero() {
		t.Fatalf("after update %+v", got)
	}
	is(t, fs.UpdateFedProvider(ctx, core.FedProvider{Realm: "acme", Alias: "nope", ProviderType: "oidc"}), idp.ErrNotFound)
	_, err = fs.GetFedProvider(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)

	ok(t, fs.CreateFedProvider(ctx, core.FedProvider{Realm: "acme", Alias: "aaa", ProviderType: "oidc", Config: map[string]string{}}))
	l, err := fs.ListFedProviders(ctx, "acme")
	ok(t, err)
	if len(l) != 2 || l[0].Alias != "aaa" || l[1].Alias != "google" {
		t.Fatalf("list %+v", l)
	}
	l, _ = fs.ListFedProviders(ctx, "empty")
	if l == nil || len(l) != 0 {
		t.Fatalf("empty list %#v", l)
	}
	ok(t, fs.DeleteFedProvider(ctx, "acme", "aaa"))
	is(t, fs.DeleteFedProvider(ctx, "acme", "aaa"), idp.ErrNotFound)
	if _, err := fs.GetFedProvider(ctx, "other", "google"); err != nil {
		t.Fatal("realm isolation:", err)
	}
}

func fedLinks(t *testing.T, st core.Store) {
	fs := fedStore(t, st)
	fedFixture(t, st, "acme")
	ok(t, fs.CreateFedProvider(ctx, core.FedProvider{Realm: "acme", Alias: "g", ProviderType: "oidc"}))
	ok(t, fs.CreateFedProvider(ctx, core.FedProvider{Realm: "acme", Alias: "m", ProviderType: "oidc"}))
	l := core.FedLink{Realm: "acme", Alias: "g", Subject: "sub-1", UserID: "u-acme", MappedRoles: []string{"r1"}, CreatedAt: t0, LastLoginAt: t0}
	ok(t, fs.CreateFedLink(ctx, l))
	is(t, fs.CreateFedLink(ctx, l), idp.ErrConflict)
	// A different user cannot take the same (alias, subject).
	l2 := l
	l2.UserID = "u2-acme"
	is(t, fs.CreateFedLink(ctx, l2), idp.ErrConflict)
	// Same subject under another alias is a different identity.
	l3 := l
	l3.Alias = "m"
	ok(t, fs.CreateFedLink(ctx, l3))
	// A link to a missing provider is refused.
	l4 := l
	l4.Alias = "ghost"
	if err := fs.CreateFedLink(ctx, l4); err == nil {
		t.Fatal("link to a missing provider accepted")
	}

	got, err := fs.GetFedLink(ctx, "acme", "g", "sub-1")
	ok(t, err)
	if got.UserID != "u-acme" || len(got.MappedRoles) != 1 || !got.LastLoginAt.Equal(t0) {
		t.Fatalf("got %+v", got)
	}
	_, err = fs.GetFedLink(ctx, "acme", "g", "sub-2")
	is(t, err, idp.ErrNotFound)

	l.MappedRoles, l.LastLoginAt = []string{"r2", "r3"}, t0.Add(time.Hour)
	l.UserID = "u2-acme" // UpdateFedLink must not rebind the user
	ok(t, fs.UpdateFedLink(ctx, l))
	got, _ = fs.GetFedLink(ctx, "acme", "g", "sub-1")
	if got.UserID != "u-acme" || len(got.MappedRoles) != 2 || !got.LastLoginAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("after update %+v", got)
	}
	l.Subject = "nope"
	is(t, fs.UpdateFedLink(ctx, l), idp.ErrNotFound)

	byUser, err := fs.ListFedLinksByUser(ctx, "acme", "u-acme")
	ok(t, err)
	if len(byUser) != 2 || byUser[0].Alias != "g" || byUser[1].Alias != "m" {
		t.Fatalf("by user %+v", byUser)
	}
	ok(t, fs.DeleteFedLink(ctx, "acme", "g", "u-acme"))
	is(t, fs.DeleteFedLink(ctx, "acme", "g", "u-acme"), idp.ErrNotFound)
	is(t, fs.DeleteFedLink(ctx, "acme", "m", "u2-acme"), idp.ErrNotFound) // not that user's link
	n, err := fs.DeleteFedLinksForUser(ctx, "acme", "u-acme")
	ok(t, err)
	if n != 1 {
		t.Fatalf("deleted %d", n)
	}
}

// Deleting a provider removes its links, not the users; deleting a user (or
// the realm) removes links, not the provider.
func fedCascade(t *testing.T, st core.Store) {
	fs := fedStore(t, st)
	fedFixture(t, st, "acme")
	for _, a := range []string{"g", "m"} {
		ok(t, fs.CreateFedProvider(ctx, core.FedProvider{Realm: "acme", Alias: a, ProviderType: "oidc"}))
		ok(t, fs.CreateFedLink(ctx, core.FedLink{Realm: "acme", Alias: a, Subject: "s-" + a, UserID: "u-acme"}))
		ok(t, fs.CreateFedLink(ctx, core.FedLink{Realm: "acme", Alias: a, Subject: "t-" + a, UserID: "u2-acme"}))
	}
	ok(t, fs.DeleteFedProvider(ctx, "acme", "g"))
	if _, err := st.GetUser(ctx, "acme", "u-acme"); err != nil {
		t.Fatal("deleting a provider removed a user:", err)
	}
	if _, err := fs.GetFedLink(ctx, "acme", "g", "s-g"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("link survived provider delete: %v", err)
	}
	ls, _ := fs.ListFedLinksByUser(ctx, "acme", "u-acme")
	if len(ls) != 1 || ls[0].Alias != "m" {
		t.Fatalf("links %+v", ls)
	}
	// Deleting a user (store level) leaves no link behind. Stores without an
	// FK cascade are covered by the Admin API hook, so call both.
	ok(t, st.DeleteUser(ctx, "acme", "u-acme"))
	_, _ = fs.DeleteFedLinksForUser(ctx, "acme", "u-acme")
	if _, err := fs.GetFedLink(ctx, "acme", "m", "s-m"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("link survived user delete: %v", err)
	}
	if _, err := fs.GetFedLink(ctx, "acme", "m", "t-m"); err != nil {
		t.Fatal("other user's link lost:", err)
	}
	if _, err := fs.GetFedProvider(ctx, "acme", "m"); err != nil {
		t.Fatal("user delete removed the provider:", err)
	}
	ok(t, st.DeleteRealm(ctx, "acme"))
	ok(t, st.CreateRealm(ctx, core.Realm{Name: "acme", Enabled: true}))
	if l, _ := fs.ListFedProviders(ctx, "acme"); len(l) != 0 {
		t.Fatalf("providers survived realm delete: %+v", l)
	}
}

func fedStateSingleUse(t *testing.T, st core.Store) {
	fs := fedStore(t, st)
	s := core.FedLoginState{StateHash: "h1", Realm: "acme", Alias: "g", BrowserHash: "b", Nonce: "n", AuthQuery: "client_id=x&state=y", ExpiresAt: time.Now().Add(time.Minute).UTC()}
	ok(t, fs.PutFedState(ctx, s))
	got, err := fs.ConsumeFedState(ctx, "h1")
	ok(t, err)
	if got.Realm != "acme" || got.Alias != "g" || got.BrowserHash != "b" || got.Nonce != "n" || got.AuthQuery != s.AuthQuery {
		t.Fatalf("got %+v", got)
	}
	_, err = fs.ConsumeFedState(ctx, "h1")
	is(t, err, idp.ErrNotFound)
	_, err = fs.ConsumeFedState(ctx, "unknown")
	is(t, err, idp.ErrNotFound)

	// Exactly one concurrent consumer wins.
	ok(t, fs.PutFedState(ctx, core.FedLoginState{StateHash: "h2", Realm: "acme", Alias: "g", ExpiresAt: time.Now().Add(time.Minute).UTC()}))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := fs.ConsumeFedState(ctx, "h2"); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d consumers won", wins.Load())
	}
}
