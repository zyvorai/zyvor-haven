// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package storetest is the conformance suite every core.Store must pass.
package storetest

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var ctx = context.Background()

// t0 is a microsecond-aligned UTC base time (pg timestamptz precision).
var t0 = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// Run executes the suite; newStore must return a fresh, empty store each call.
func Run(t *testing.T, newStore func(t *testing.T) core.Store) {
	cases := []struct {
		name string
		fn   func(*testing.T, core.Store)
	}{
		{"Realms", realms},
		{"RealmCaseInsensitive", realmCase},
		{"Users", users},
		{"UsernameCaseInsensitive", usernameCase},
		{"ListUsers", listUsers},
		{"Clients", clients},
		{"RolesGroups", rolesGroups},
		{"SigningKeys", signingKeys},
		{"AuthCodeSingleUse", authCode},
		{"AuthCodeConcurrent", authCodeConcurrent},
		{"RefreshReuse", refreshReuse},
		{"RefreshReuseConcurrent", refreshConcurrent},
		{"RefreshFamilyRevocation", refreshFamily},
		{"RevokeUserRefreshTokens", revokeUserRefresh},
		{"ActionTokenSingleUse", actionTokenSingleUse},
		{"ActionTokenDeleteCount", actionTokenDeleteCount},
		{"ActionTokenPurgeCascade", actionTokenPurgeCascade},
		{"Events", events},
		{"Purge", purge},
		{"CascadeDeleteRealm", cascade},
		{"MissingRealm", missingRealm},
		{"Isolation", isolation},
		{"NoAliasing", noAliasing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.fn(t, newStore(t)) })
	}
}

func is(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got err %v, want %v", err, want)
	}
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func eq(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mismatch:\n got  %+v\n want %+v", got, want)
	}
}

func mkRealm(t *testing.T, s core.Store, name string) {
	t.Helper()
	ok(t, s.CreateRealm(ctx, core.Realm{Name: name, Enabled: true}))
}

func realms(t *testing.T, s core.Store) {
	_, err := s.GetRealm(ctx, "acme")
	is(t, err, idp.ErrNotFound)

	in := core.Realm{
		ID: "r-1", Name: "acme", DisplayName: "Acme", Enabled: true, SelfRegistration: true,
		EmailVerificationRequired: true, BruteForceProtection: true, TransportSecurity: "external",
		PasswordPolicy: "length(12)", AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: 30 * 24 * time.Hour,
		SessionIdleTTL: time.Hour, AuthEventsLogged: true, AdminEventsLogged: true,
		RefreshTokenRotation: true, CreatedAt: t0,
	}
	ok(t, s.CreateRealm(ctx, in))
	got, err := s.GetRealm(ctx, "acme")
	ok(t, err)
	eq(t, got, in)

	is(t, s.CreateRealm(ctx, core.Realm{Name: "acme"}), idp.ErrConflict)

	// Defaults are filled when empty.
	ok(t, s.CreateRealm(ctx, core.Realm{Name: "beta"}))
	b, err := s.GetRealm(ctx, "beta")
	ok(t, err)
	if b.ID == "" || b.CreatedAt.IsZero() {
		t.Fatalf("ID/CreatedAt not filled: %+v", b)
	}

	list, err := s.ListRealms(ctx)
	ok(t, err)
	if len(list) != 2 || list[0].Name != "acme" || list[1].Name != "beta" {
		t.Fatalf("ListRealms = %+v", list)
	}

	up := in
	up.DisplayName = "Acme Inc"
	up.Enabled = false
	up.ID, up.CreatedAt = "ignored", t0.Add(time.Hour)
	ok(t, s.UpdateRealm(ctx, up))
	got, err = s.GetRealm(ctx, "acme")
	ok(t, err)
	if got.DisplayName != "Acme Inc" || got.Enabled || got.ID != "r-1" || !got.CreatedAt.Equal(t0) {
		t.Fatalf("after update: %+v", got)
	}
	is(t, s.UpdateRealm(ctx, core.Realm{Name: "nope"}), idp.ErrNotFound)

	ok(t, s.DeleteRealm(ctx, "acme"))
	_, err = s.GetRealm(ctx, "acme")
	is(t, err, idp.ErrNotFound)
	is(t, s.DeleteRealm(ctx, "acme"), idp.ErrNotFound)
}

func realmCase(t *testing.T, s core.Store) {
	ok(t, s.CreateRealm(ctx, core.Realm{Name: "Acme"}))
	is(t, s.CreateRealm(ctx, core.Realm{Name: "acme"}), idp.ErrConflict)
	r, err := s.GetRealm(ctx, "ACME")
	ok(t, err)
	if r.Name != "Acme" {
		t.Fatalf("name = %q", r.Name)
	}
	ok(t, s.DeleteRealm(ctx, "aCmE"))
	_, err = s.GetRealm(ctx, "Acme")
	is(t, err, idp.ErrNotFound)
}

func users(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	in := core.User{
		ID: "u-1", Realm: "acme", Username: "alice", Email: "alice@example.com", FirstName: "Alice",
		LastName: "A", Enabled: true, EmailVerified: true, PendingActions: []string{"UPDATE_PASSWORD"},
		PasswordHash: "$argon2id$x", Roles: []string{"admin", "dev"}, Groups: []string{"/eng", "/eng/core"},
		FailedLogins: 2, LockedUntil: t0.Add(time.Hour), CreatedAt: t0,
	}
	ok(t, s.CreateUser(ctx, in))
	got, err := s.GetUser(ctx, "acme", "u-1")
	ok(t, err)
	eq(t, got, in)
	got, err = s.GetUserByUsername(ctx, "acme", "alice")
	ok(t, err)
	eq(t, got, in)

	// Zero optional fields round-trip as zero/nil.
	ok(t, s.CreateUser(ctx, core.User{Realm: "acme", Username: "bob"}))
	bob, err := s.GetUserByUsername(ctx, "acme", "bob")
	ok(t, err)
	if bob.ID == "" || bob.CreatedAt.IsZero() || !bob.LockedUntil.IsZero() ||
		bob.Roles != nil || bob.Groups != nil || bob.PendingActions != nil {
		t.Fatalf("bob = %+v", bob)
	}

	is(t, s.CreateUser(ctx, core.User{Realm: "acme", Username: "alice"}), idp.ErrConflict)
	is(t, s.CreateUser(ctx, core.User{ID: "u-1", Realm: "acme", Username: "other"}), idp.ErrConflict)

	_, err = s.GetUser(ctx, "acme", "missing")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetUserByUsername(ctx, "acme", "missing")
	is(t, err, idp.ErrNotFound)

	up := in
	up.Email = "new@example.com"
	up.Roles = nil
	up.LockedUntil = time.Time{}
	up.FailedLogins = 0
	up.CreatedAt = t0.Add(time.Hour)
	ok(t, s.UpdateUser(ctx, up))
	got, err = s.GetUser(ctx, "acme", "u-1")
	ok(t, err)
	if got.Email != "new@example.com" || got.Roles != nil || !got.LockedUntil.IsZero() ||
		got.FailedLogins != 0 || !got.CreatedAt.Equal(t0) {
		t.Fatalf("after update: %+v", got)
	}

	// Rename onto an existing username conflicts; renaming to itself is fine.
	clash := up
	clash.Username = "BOB"
	is(t, s.UpdateUser(ctx, clash), idp.ErrConflict)
	same := up
	same.Username = "ALICE"
	ok(t, s.UpdateUser(ctx, same))

	is(t, s.UpdateUser(ctx, core.User{ID: "nope", Realm: "acme", Username: "x"}), idp.ErrNotFound)

	ok(t, s.DeleteUser(ctx, "acme", "u-1"))
	is(t, s.DeleteUser(ctx, "acme", "u-1"), idp.ErrNotFound)
	_, err = s.GetUser(ctx, "acme", "u-1")
	is(t, err, idp.ErrNotFound)
}

func usernameCase(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, s.CreateUser(ctx, core.User{ID: "u-1", Realm: "acme", Username: "Alice"}))
	is(t, s.CreateUser(ctx, core.User{Realm: "acme", Username: "alice"}), idp.ErrConflict)
	is(t, s.CreateUser(ctx, core.User{Realm: "acme", Username: "ALICE"}), idp.ErrConflict)
	// Same name in another realm is fine.
	ok(t, s.CreateUser(ctx, core.User{Realm: "other", Username: "alice"}))
	for _, name := range []string{"alice", "ALICE", "Alice", "aLiCe"} {
		u, err := s.GetUserByUsername(ctx, "acme", name)
		ok(t, err)
		if u.ID != "u-1" || u.Username != "Alice" {
			t.Fatalf("lookup %q = %+v", name, u)
		}
	}
}

func listUsers(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	for _, n := range []string{"carol", "alice", "bob", "dave", "50%off", "a_b"} {
		ok(t, s.CreateUser(ctx, core.User{Realm: "acme", Username: n, Email: n + "@example.com", FirstName: "F" + n}))
	}
	ok(t, s.CreateUser(ctx, core.User{Realm: "other", Username: "zed"}))

	names := func(us []core.User) []string {
		out := []string{}
		for _, u := range us {
			out = append(out, u.Username)
		}
		return out
	}
	all, err := s.ListUsers(ctx, "acme", "", 0, 0)
	ok(t, err)
	eq(t, names(all), []string{"50%off", "a_b", "alice", "bob", "carol", "dave"})

	page, err := s.ListUsers(ctx, "acme", "", 2, 2)
	ok(t, err)
	eq(t, names(page), []string{"alice", "bob"})
	page, err = s.ListUsers(ctx, "acme", "", 5, 10)
	ok(t, err)
	eq(t, names(page), []string{"dave"})
	page, err = s.ListUsers(ctx, "acme", "", 50, 10)
	ok(t, err)
	eq(t, names(page), []string{})

	hit, err := s.ListUsers(ctx, "acme", "ALI", 0, 0)
	ok(t, err)
	eq(t, names(hit), []string{"alice"})
	hit, err = s.ListUsers(ctx, "acme", "bob@EXAMPLE", 0, 0)
	ok(t, err)
	eq(t, names(hit), []string{"bob"})
	// LIKE metacharacters are literal.
	hit, err = s.ListUsers(ctx, "acme", "%", 0, 0)
	ok(t, err)
	eq(t, names(hit), []string{"50%off"})
	hit, err = s.ListUsers(ctx, "acme", "_", 0, 0)
	ok(t, err)
	eq(t, names(hit), []string{"a_b"})
	hit, err = s.ListUsers(ctx, "acme", "zed", 0, 0)
	ok(t, err)
	eq(t, names(hit), []string{})
}

func clients(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	in := core.Client{
		ID: "c-1", Realm: "acme", ClientID: "web", Name: "Web", Enabled: true, Public: false,
		SecretHash: "abc123", RedirectURIs: []string{"https://a/cb", "https://b/cb"},
		Origins: []string{"https://a"}, AuthCodeFlow: true, PasswordFlow: true,
		ServiceAccount: true, RequirePKCE: true, CreatedAt: t0,
	}
	ok(t, s.CreateClient(ctx, in))
	got, err := s.GetClient(ctx, "acme", "c-1")
	ok(t, err)
	eq(t, got, in)
	got, err = s.GetClientByClientID(ctx, "acme", "web")
	ok(t, err)
	eq(t, got, in)

	is(t, s.CreateClient(ctx, core.Client{Realm: "acme", ClientID: "web"}), idp.ErrConflict)
	// client_id is case-sensitive, and unique per realm only.
	ok(t, s.CreateClient(ctx, core.Client{Realm: "acme", ClientID: "WEB"}))
	ok(t, s.CreateClient(ctx, core.Client{Realm: "other", ClientID: "web"}))

	_, err = s.GetClient(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetClient(ctx, "other", "c-1")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetClientByClientID(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)

	l, err := s.ListClients(ctx, "acme")
	ok(t, err)
	if len(l) != 2 {
		t.Fatalf("ListClients = %+v", l)
	}

	up := in
	up.Name = "Web2"
	up.RedirectURIs = nil
	up.CreatedAt = t0.Add(time.Hour)
	ok(t, s.UpdateClient(ctx, up))
	got, err = s.GetClient(ctx, "acme", "c-1")
	ok(t, err)
	if got.Name != "Web2" || got.RedirectURIs != nil || !got.CreatedAt.Equal(t0) {
		t.Fatalf("after update: %+v", got)
	}
	clash := up
	clash.ClientID = "WEB"
	is(t, s.UpdateClient(ctx, clash), idp.ErrConflict)
	is(t, s.UpdateClient(ctx, core.Client{ID: "nope", Realm: "acme", ClientID: "q"}), idp.ErrNotFound)

	ok(t, s.DeleteClient(ctx, "acme", "c-1"))
	is(t, s.DeleteClient(ctx, "acme", "c-1"), idp.ErrNotFound)
}

func rolesGroups(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	ok(t, s.CreateRole(ctx, core.Role{ID: "r-1", Realm: "acme", Name: "viewer", Description: "read"}))
	ok(t, s.CreateRole(ctx, core.Role{Realm: "acme", Name: "admin"}))
	ok(t, s.CreateRole(ctx, core.Role{Realm: "other", Name: "admin"}))
	is(t, s.CreateRole(ctx, core.Role{Realm: "acme", Name: "admin"}), idp.ErrConflict)
	roles, err := s.ListRoles(ctx, "acme")
	ok(t, err)
	if len(roles) != 2 || roles[0].Name != "admin" || roles[1].Name != "viewer" ||
		roles[1].ID != "r-1" || roles[1].Description != "read" || roles[0].ID == "" {
		t.Fatalf("roles = %+v", roles)
	}

	ok(t, s.CreateGroup(ctx, core.Group{ID: "g-1", Realm: "acme", Name: "eng", Path: "/eng"}))
	ok(t, s.CreateGroup(ctx, core.Group{Realm: "acme", Name: "core", Path: "/eng/core"}))
	ok(t, s.CreateGroup(ctx, core.Group{Realm: "other", Name: "eng", Path: "/eng"}))
	is(t, s.CreateGroup(ctx, core.Group{Realm: "acme", Name: "x", Path: "/eng"}), idp.ErrConflict)
	groups, err := s.ListGroups(ctx, "acme")
	ok(t, err)
	if len(groups) != 2 || groups[0].Path != "/eng" || groups[1].Path != "/eng/core" || groups[0].ID != "g-1" {
		t.Fatalf("groups = %+v", groups)
	}
	empty, err := s.ListRoles(ctx, "nope")
	ok(t, err)
	if len(empty) != 0 {
		t.Fatalf("roles in unknown realm = %+v", empty)
	}
}

func signingKeys(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	old := core.SigningKey{KID: "k1", Realm: "acme", Alg: "ES256", PrivatePEM: []byte("pem1"),
		PublicJWK: []byte(`{"kid":"k1"}`), Active: false, NotAfter: t0.Add(24 * time.Hour), CreatedAt: t0}
	cur := core.SigningKey{KID: "k2", Realm: "acme", Alg: "ES256", PrivatePEM: []byte("pem2"),
		PublicJWK: []byte(`{"kid":"k2"}`), Active: true, CreatedAt: t0.Add(-time.Hour)}
	ok(t, s.PutSigningKey(ctx, old))
	ok(t, s.PutSigningKey(ctx, cur))
	keys, err := s.ListSigningKeys(ctx, "acme")
	ok(t, err)
	if len(keys) != 2 {
		t.Fatalf("keys = %+v", keys)
	}
	eq(t, keys[0], cur) // active first, even though older
	eq(t, keys[1], old)

	// Put with an existing KID replaces (rotation deactivates the old key).
	cur.Active = false
	cur.NotAfter = t0.Add(48 * time.Hour)
	ok(t, s.PutSigningKey(ctx, cur))
	keys, err = s.ListSigningKeys(ctx, "acme")
	ok(t, err)
	if len(keys) != 2 || keys[0].KID != "k1" || keys[1].Active || !keys[1].NotAfter.Equal(cur.NotAfter) {
		t.Fatalf("after replace: %+v", keys)
	}
	none, err := s.ListSigningKeys(ctx, "nope")
	ok(t, err)
	if len(none) != 0 {
		t.Fatalf("keys for unknown realm: %+v", none)
	}
}

func mkCode(hash string) core.AuthCode {
	return core.AuthCode{
		CodeHash: hash, Realm: "acme", ClientID: "web", UserID: "u-1", RedirectURI: "https://a/cb",
		Scope: "openid profile", Nonce: "n", CodeChallenge: "chal", ChallengeMeth: "S256",
		AuthTime: t0, ExpiresAt: t0.Add(time.Minute),
	}
}

func authCode(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	in := mkCode("h1")
	ok(t, s.PutAuthCode(ctx, in))
	is(t, s.PutAuthCode(ctx, in), idp.ErrConflict)
	got, err := s.ConsumeAuthCode(ctx, "h1")
	ok(t, err)
	eq(t, got, in)
	_, err = s.ConsumeAuthCode(ctx, "h1")
	is(t, err, idp.ErrNotFound)
	_, err = s.ConsumeAuthCode(ctx, "never")
	is(t, err, idp.ErrNotFound)
}

func authCodeConcurrent(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	ok(t, s.PutAuthCode(ctx, mkCode("race")))
	const n = 32
	var wins, notFound, other atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.ConsumeAuthCode(ctx, "race")
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, idp.ErrNotFound):
				notFound.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || notFound.Load() != n-1 || other.Load() != 0 {
		t.Fatalf("wins=%d notFound=%d other=%d", wins.Load(), notFound.Load(), other.Load())
	}
}

func mkRefresh(hash, family string) core.RefreshToken {
	return core.RefreshToken{TokenHash: hash, FamilyID: family, Realm: "acme", ClientID: "web",
		UserID: "u-1", Scope: "openid", ExpiresAt: t0.Add(time.Hour), CreatedAt: t0}
}

func refreshReuse(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	in := mkRefresh("t1", "f1")
	ok(t, s.PutRefreshToken(ctx, in))
	is(t, s.PutRefreshToken(ctx, in), idp.ErrConflict)
	got, err := s.GetRefreshToken(ctx, "t1")
	ok(t, err)
	eq(t, got, in)

	ok(t, s.MarkRefreshUsed(ctx, "t1"))
	is(t, s.MarkRefreshUsed(ctx, "t1"), idp.ErrConflict)
	is(t, s.MarkRefreshUsed(ctx, "t1"), idp.ErrConflict)
	is(t, s.MarkRefreshUsed(ctx, "missing"), idp.ErrNotFound)
	got, err = s.GetRefreshToken(ctx, "t1")
	ok(t, err)
	if !got.Used {
		t.Fatal("token not marked used")
	}
	_, err = s.GetRefreshToken(ctx, "missing")
	is(t, err, idp.ErrNotFound)

	// A client_credentials style token has no user.
	cc := mkRefresh("t2", "f2")
	cc.UserID = ""
	ok(t, s.PutRefreshToken(ctx, cc))
	got, err = s.GetRefreshToken(ctx, "t2")
	ok(t, err)
	eq(t, got, cc)
}

func refreshConcurrent(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	ok(t, s.PutRefreshToken(ctx, mkRefresh("race", "f")))
	const n = 32
	var wins, conflicts, other atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := s.MarkRefreshUsed(ctx, "race")
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, idp.ErrConflict):
				conflicts.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != n-1 || other.Load() != 0 {
		t.Fatalf("wins=%d conflicts=%d other=%d", wins.Load(), conflicts.Load(), other.Load())
	}
}

func refreshFamily(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	for _, h := range []string{"a1", "a2", "a3"} {
		ok(t, s.PutRefreshToken(ctx, mkRefresh(h, "famA")))
	}
	ok(t, s.PutRefreshToken(ctx, mkRefresh("b1", "famB")))
	ok(t, s.RevokeRefreshFamily(ctx, "famA"))
	for _, h := range []string{"a1", "a2", "a3"} {
		tok, err := s.GetRefreshToken(ctx, h)
		ok(t, err)
		if !tok.Revoked {
			t.Fatalf("%s not revoked", h)
		}
	}
	b, err := s.GetRefreshToken(ctx, "b1")
	ok(t, err)
	if b.Revoked {
		t.Fatal("other family revoked")
	}
	// Revoking an unknown family is a no-op, and idempotent.
	ok(t, s.RevokeRefreshFamily(ctx, "nope"))
	ok(t, s.RevokeRefreshFamily(ctx, "famA"))
}

func revokeUserRefresh(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	for _, h := range []string{"a1", "a2"} {
		ok(t, s.PutRefreshToken(ctx, mkRefresh(h, "famA")))
	}
	other := mkRefresh("b1", "famB")
	other.UserID = "u-2"
	ok(t, s.PutRefreshToken(ctx, other))
	otherRealm := mkRefresh("c1", "famC")
	otherRealm.Realm = "other"
	ok(t, s.PutRefreshToken(ctx, otherRealm))
	pre := mkRefresh("a3", "famA")
	pre.Revoked = true
	ok(t, s.PutRefreshToken(ctx, pre))

	n, err := s.RevokeUserRefreshTokens(ctx, "acme", "u-1")
	ok(t, err)
	eq(t, n, 2) // a3 was already revoked
	for h, want := range map[string]bool{"a1": true, "a2": true, "a3": true, "b1": false, "c1": false} {
		tok, err := s.GetRefreshToken(ctx, h)
		ok(t, err)
		eq(t, tok.Revoked, want)
	}
	n, err = s.RevokeUserRefreshTokens(ctx, "acme", "u-1")
	ok(t, err)
	eq(t, n, 0)
	n, err = s.RevokeUserRefreshTokens(ctx, "acme", "nobody")
	ok(t, err)
	eq(t, n, 0)
}

func mkAction(hash, purpose string) core.ActionToken {
	return core.ActionToken{TokenHash: hash, Realm: "acme", UserID: "u-1", Purpose: purpose,
		Email: "a@example.com", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
}

func actionTokenSingleUse(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	in := mkAction("h1", core.ActionVerifyEmail)
	ok(t, s.PutActionToken(ctx, in))
	is(t, s.PutActionToken(ctx, in), idp.ErrConflict)
	got, err := s.ConsumeActionToken(ctx, "h1")
	ok(t, err)
	eq(t, got, in)
	_, err = s.ConsumeActionToken(ctx, "h1")
	is(t, err, idp.ErrNotFound)
	_, err = s.ConsumeActionToken(ctx, "never")
	is(t, err, idp.ErrNotFound)

	ghost := mkAction("h2", core.ActionVerifyEmail)
	ghost.Realm = "ghost"
	is(t, s.PutActionToken(ctx, ghost), idp.ErrNotFound)

	// A zero CreatedAt is stamped.
	z := mkAction("h3", core.ActionResetPassword)
	z.CreatedAt = time.Time{}
	ok(t, s.PutActionToken(ctx, z))
	got, err = s.ConsumeActionToken(ctx, "h3")
	ok(t, err)
	if got.CreatedAt.IsZero() {
		t.Fatal("CreatedAt not stamped")
	}
}

func actionTokenDeleteCount(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	put := func(hash, realm, user, purpose string, created time.Time) {
		a := mkAction(hash, purpose)
		a.Realm, a.UserID, a.CreatedAt = realm, user, created
		a.ExpiresAt = created.Add(time.Hour)
		ok(t, s.PutActionToken(ctx, a))
	}
	count := func(realm, user, purpose string, since time.Time) int {
		t.Helper()
		n, err := s.CountActionTokens(ctx, realm, user, purpose, since)
		ok(t, err)
		return n
	}
	put("v-old", "acme", "u-1", core.ActionVerifyEmail, t0)
	put("v-new", "acme", "u-1", core.ActionVerifyEmail, t0.Add(10*time.Minute))
	put("r-1", "acme", "u-1", core.ActionResetPassword, t0.Add(10*time.Minute))
	put("v-u2", "acme", "u-2", core.ActionVerifyEmail, t0.Add(10*time.Minute))
	put("v-other", "other", "u-1", core.ActionVerifyEmail, t0.Add(10*time.Minute))

	eq(t, count("acme", "u-1", core.ActionVerifyEmail, t0.Add(-time.Hour)), 2)
	eq(t, count("acme", "u-1", core.ActionVerifyEmail, t0), 2) // since is inclusive
	eq(t, count("acme", "u-1", core.ActionVerifyEmail, t0.Add(time.Minute)), 1)
	eq(t, count("acme", "u-1", core.ActionVerifyEmail, t0.Add(time.Hour)), 0)
	eq(t, count("acme", "u-1", core.ActionResetPassword, t0), 1)
	eq(t, count("acme", "nobody", core.ActionVerifyEmail, t0), 0)

	n, err := s.DeleteActionTokens(ctx, "acme", "u-1", core.ActionVerifyEmail)
	ok(t, err)
	eq(t, n, 2)
	n, err = s.DeleteActionTokens(ctx, "acme", "u-1", core.ActionVerifyEmail)
	ok(t, err)
	eq(t, n, 0)
	// Other purpose, user and realm are untouched.
	for _, h := range []string{"r-1", "v-u2", "v-other"} {
		_, err := s.ConsumeActionToken(ctx, h)
		ok(t, err)
	}
	for _, h := range []string{"v-old", "v-new"} {
		_, err := s.ConsumeActionToken(ctx, h)
		is(t, err, idp.ErrNotFound)
	}
}

func actionTokenPurgeCascade(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "keep")
	now := t0.Add(time.Hour)
	old, live := mkAction("a-old", core.ActionVerifyEmail), mkAction("a-live", core.ActionVerifyEmail)
	old.ExpiresAt, live.ExpiresAt = now.Add(-time.Second), now.Add(time.Minute)
	ok(t, s.PutActionToken(ctx, old))
	ok(t, s.PutActionToken(ctx, live))
	n, err := s.PurgeExpired(ctx, now)
	ok(t, err)
	eq(t, n, 1)
	_, err = s.ConsumeActionToken(ctx, "a-old")
	is(t, err, idp.ErrNotFound)
	// Re-put the live one (consume above not run on it) and cascade.
	for _, r := range []string{"acme", "keep"} {
		a := mkAction("c-"+r, core.ActionResetPassword)
		a.Realm = r
		ok(t, s.PutActionToken(ctx, a))
	}
	ok(t, s.DeleteRealm(ctx, "acme"))
	_, err = s.ConsumeActionToken(ctx, "a-live")
	is(t, err, idp.ErrNotFound)
	_, err = s.ConsumeActionToken(ctx, "c-acme")
	is(t, err, idp.ErrNotFound)
	_, err = s.ConsumeActionToken(ctx, "c-keep")
	ok(t, err)
}

func events(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	for i := 0; i < 5; i++ {
		ok(t, s.AppendEvent(ctx, core.Event{Time: t0.Add(time.Duration(i) * time.Second), Realm: "acme",
			Type: "LOGIN", UserID: "u", ClientID: "web", IP: "10.0.0.1", Detail: string(rune('a' + i))}))
	}
	ok(t, s.AppendEvent(ctx, core.Event{Time: t0, Realm: "other", Type: "LOGIN"}))
	ev, err := s.ListEvents(ctx, "acme", 3)
	ok(t, err)
	if len(ev) != 3 || ev[0].Detail != "e" || ev[1].Detail != "d" || ev[2].Detail != "c" {
		t.Fatalf("events = %+v", ev)
	}
	want := core.Event{Time: t0.Add(4 * time.Second), Realm: "acme", Type: "LOGIN", UserID: "u",
		ClientID: "web", IP: "10.0.0.1", Detail: "e"}
	eq(t, ev[0], want)
	ev, err = s.ListEvents(ctx, "acme", 100)
	ok(t, err)
	if len(ev) != 5 {
		t.Fatalf("len = %d", len(ev))
	}
	ev, err = s.ListEvents(ctx, "other", 10)
	ok(t, err)
	if len(ev) != 1 {
		t.Fatalf("other len = %d", len(ev))
	}
	// Zero time is stamped.
	ok(t, s.AppendEvent(ctx, core.Event{Realm: "other", Type: "ADMIN_CREATE"}))
	ev, err = s.ListEvents(ctx, "other", 1)
	ok(t, err)
	if len(ev) != 1 || ev[0].Type != "ADMIN_CREATE" || ev[0].Time.IsZero() {
		t.Fatalf("stamped = %+v", ev)
	}
}

func purge(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	now := t0.Add(time.Hour)
	expired, live := mkCode("c-old"), mkCode("c-live")
	expired.ExpiresAt, live.ExpiresAt = now.Add(-time.Second), now.Add(time.Minute)
	ok(t, s.PutAuthCode(ctx, expired))
	ok(t, s.PutAuthCode(ctx, live))
	rOld, rLive := mkRefresh("r-old", "f"), mkRefresh("r-live", "f")
	rOld.ExpiresAt, rLive.ExpiresAt = now.Add(-time.Hour), now.Add(time.Hour)
	ok(t, s.PutRefreshToken(ctx, rOld))
	ok(t, s.PutRefreshToken(ctx, rLive))

	n, err := s.PurgeExpired(ctx, now)
	ok(t, err)
	if n != 2 {
		t.Fatalf("purged %d, want 2", n)
	}
	_, err = s.ConsumeAuthCode(ctx, "c-old")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetRefreshToken(ctx, "r-old")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetRefreshToken(ctx, "r-live")
	ok(t, err)
	_, err = s.ConsumeAuthCode(ctx, "c-live")
	ok(t, err)

	n, err = s.PurgeExpired(ctx, now)
	ok(t, err)
	if n != 0 {
		t.Fatalf("second purge removed %d", n)
	}
}

func cascade(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	mkRealm(t, s, "keep")
	for _, r := range []string{"acme", "keep"} {
		ok(t, s.CreateUser(ctx, core.User{ID: "u-" + r, Realm: r, Username: "alice"}))
		ok(t, s.CreateClient(ctx, core.Client{ID: "c-" + r, Realm: r, ClientID: "web"}))
		ok(t, s.CreateRole(ctx, core.Role{Realm: r, Name: "admin"}))
		ok(t, s.CreateGroup(ctx, core.Group{Realm: r, Name: "eng", Path: "/eng"}))
		ok(t, s.PutSigningKey(ctx, core.SigningKey{KID: "k", Realm: r, Alg: "ES256", Active: true}))
		c := mkCode("code-" + r)
		c.Realm = r
		ok(t, s.PutAuthCode(ctx, c))
		rt := mkRefresh("rt-"+r, "fam-"+r)
		rt.Realm = r
		ok(t, s.PutRefreshToken(ctx, rt))
		ok(t, s.AppendEvent(ctx, core.Event{Realm: r, Type: "LOGIN"}))
	}
	ok(t, s.DeleteRealm(ctx, "acme"))

	_, err := s.GetUser(ctx, "acme", "u-acme")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetClient(ctx, "acme", "c-acme")
	is(t, err, idp.ErrNotFound)
	_, err = s.ConsumeAuthCode(ctx, "code-acme")
	is(t, err, idp.ErrNotFound)
	_, err = s.GetRefreshToken(ctx, "rt-acme")
	is(t, err, idp.ErrNotFound)
	for name, f := range map[string]func() (int, error){
		"roles":  func() (int, error) { l, e := s.ListRoles(ctx, "acme"); return len(l), e },
		"groups": func() (int, error) { l, e := s.ListGroups(ctx, "acme"); return len(l), e },
		"keys":   func() (int, error) { l, e := s.ListSigningKeys(ctx, "acme"); return len(l), e },
		"events": func() (int, error) { l, e := s.ListEvents(ctx, "acme", 10); return len(l), e },
		"users":  func() (int, error) { l, e := s.ListUsers(ctx, "acme", "", 0, 0); return len(l), e },
	} {
		if n, err := f(); err != nil || n != 0 {
			t.Fatalf("%s after cascade: n=%d err=%v", name, n, err)
		}
	}

	// The other realm is untouched.
	_, err = s.GetUser(ctx, "keep", "u-keep")
	ok(t, err)
	_, err = s.GetClient(ctx, "keep", "c-keep")
	ok(t, err)
	_, err = s.GetRefreshToken(ctx, "rt-keep")
	ok(t, err)
	_, err = s.ConsumeAuthCode(ctx, "code-keep")
	ok(t, err)
	if k, _ := s.ListSigningKeys(ctx, "keep"); len(k) != 1 {
		t.Fatalf("keep keys = %v", k)
	}

	// The name can be reused after deletion.
	mkRealm(t, s, "acme")
	ok(t, s.CreateUser(ctx, core.User{Realm: "acme", Username: "alice"}))
}

func missingRealm(t *testing.T, s core.Store) {
	is(t, s.CreateUser(ctx, core.User{Realm: "ghost", Username: "a"}), idp.ErrNotFound)
	is(t, s.CreateClient(ctx, core.Client{Realm: "ghost", ClientID: "a"}), idp.ErrNotFound)
	is(t, s.CreateRole(ctx, core.Role{Realm: "ghost", Name: "a"}), idp.ErrNotFound)
	is(t, s.CreateGroup(ctx, core.Group{Realm: "ghost", Name: "a", Path: "/a"}), idp.ErrNotFound)
	is(t, s.PutSigningKey(ctx, core.SigningKey{Realm: "ghost", KID: "k"}), idp.ErrNotFound)
	c := mkCode("x")
	c.Realm = "ghost"
	is(t, s.PutAuthCode(ctx, c), idp.ErrNotFound)
	r := mkRefresh("x", "f")
	r.Realm = "ghost"
	is(t, s.PutRefreshToken(ctx, r), idp.ErrNotFound)
	is(t, s.AppendEvent(ctx, core.Event{Realm: "ghost", Type: "X"}), idp.ErrNotFound)
}

func isolation(t *testing.T, s core.Store) {
	mkRealm(t, s, "a")
	mkRealm(t, s, "b")
	ok(t, s.CreateUser(ctx, core.User{ID: "u1", Realm: "a", Username: "x"}))
	_, err := s.GetUser(ctx, "b", "u1")
	is(t, err, idp.ErrNotFound)
	is(t, s.DeleteUser(ctx, "b", "u1"), idp.ErrNotFound)
	is(t, s.UpdateUser(ctx, core.User{ID: "u1", Realm: "b", Username: "x"}), idp.ErrNotFound)
	_, err = s.GetUser(ctx, "a", "u1")
	ok(t, err)
}

// noAliasing checks callers cannot mutate stored state through slices they
// passed in or got back.
func noAliasing(t *testing.T, s core.Store) {
	mkRealm(t, s, "acme")
	roles := []string{"admin"}
	uris := []string{"https://a/cb"}
	pem := []byte("secret")
	ok(t, s.CreateUser(ctx, core.User{ID: "u", Realm: "acme", Username: "a", Roles: roles}))
	ok(t, s.CreateClient(ctx, core.Client{ID: "c", Realm: "acme", ClientID: "w", RedirectURIs: uris}))
	ok(t, s.PutSigningKey(ctx, core.SigningKey{KID: "k", Realm: "acme", PrivatePEM: pem, PublicJWK: []byte("{}")}))
	roles[0], uris[0], pem[0] = "evil", "https://evil", 'X'

	u, err := s.GetUser(ctx, "acme", "u")
	ok(t, err)
	if u.Roles[0] != "admin" {
		t.Fatalf("stored user aliased input: %v", u.Roles)
	}
	u.Roles[0] = "evil"
	u2, _ := s.GetUser(ctx, "acme", "u")
	if u2.Roles[0] != "admin" {
		t.Fatalf("stored user aliased output: %v", u2.Roles)
	}

	c, err := s.GetClient(ctx, "acme", "c")
	ok(t, err)
	if c.RedirectURIs[0] != "https://a/cb" {
		t.Fatalf("stored client aliased input: %v", c.RedirectURIs)
	}
	c.RedirectURIs[0] = "https://evil"
	c2, _ := s.GetClientByClientID(ctx, "acme", "w")
	if c2.RedirectURIs[0] != "https://a/cb" {
		t.Fatalf("stored client aliased output: %v", c2.RedirectURIs)
	}
	cl, _ := s.ListClients(ctx, "acme")
	cl[0].RedirectURIs[0] = "https://evil"

	ks, err := s.ListSigningKeys(ctx, "acme")
	ok(t, err)
	if string(ks[0].PrivatePEM) != "secret" {
		t.Fatalf("stored key aliased input: %q", ks[0].PrivatePEM)
	}
	ks[0].PrivatePEM[0] = 'Y'
	ks2, _ := s.ListSigningKeys(ctx, "acme")
	if string(ks2[0].PrivatePEM) != "secret" {
		t.Fatalf("stored key aliased output: %q", ks2[0].PrivatePEM)
	}
	c3, _ := s.GetClient(ctx, "acme", "c")
	if c3.RedirectURIs[0] != "https://a/cb" {
		t.Fatalf("list aliasing: %v", c3.RedirectURIs)
	}
}
