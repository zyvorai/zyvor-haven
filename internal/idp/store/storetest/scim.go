// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"testing"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"SCIMTokenRoundtrip", scimTokenRoundtrip},
		Case{"SCIMTokenCascadeDeleteRealm", scimTokenCascade},
		Case{"SCIMExternalIDs", scimExternalIDs},
		Case{"SCIMExternalIDCascadeDeleteUser", scimExternalIDUserDelete},
	)
}

func scimStore(t *testing.T, s core.Store) core.SCIMStore {
	t.Helper()
	ss, ok := core.StoreAs[core.SCIMStore](s)
	if !ok {
		t.Skip("store does not implement core.SCIMStore")
	}
	return ss
}

func scimTokenRoundtrip(t *testing.T, s core.Store) {
	ss := scimStore(t, s)
	mkRealm(t, s, "acme")
	_, err := ss.GetSCIMToken(ctx, "acme")
	is(t, err, idp.ErrNotFound)
	is(t, ss.DeleteSCIMToken(ctx, "acme"), idp.ErrNotFound)

	in := core.SCIMToken{Realm: "acme", RealmID: "rid-1", TokenHash: "h1", ReadOnly: true, CreatedBy: "user:x", CreatedAt: t0}
	ok(t, ss.PutSCIMToken(ctx, in))
	got, err := ss.GetSCIMToken(ctx, "acme")
	ok(t, err)
	eq(t, got, in)

	// Rotation replaces the one token.
	in2 := core.SCIMToken{Realm: "acme", RealmID: "rid-1", TokenHash: "h2", CreatedBy: "user:y", CreatedAt: t0.Add(1e9)}
	ok(t, ss.PutSCIMToken(ctx, in2))
	got, err = ss.GetSCIMToken(ctx, "acme")
	ok(t, err)
	eq(t, got, in2)

	ok(t, ss.DeleteSCIMToken(ctx, "acme"))
	_, err = ss.GetSCIMToken(ctx, "acme")
	is(t, err, idp.ErrNotFound)
}

func scimTokenCascade(t *testing.T, s core.Store) {
	ss := scimStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, ss.PutSCIMToken(ctx, core.SCIMToken{Realm: "acme", RealmID: "r", TokenHash: "h", CreatedAt: t0}))
	ok(t, s.DeleteRealm(ctx, "acme"))
	mkRealm(t, s, "acme")
	_, err := ss.GetSCIMToken(ctx, "acme")
	is(t, err, idp.ErrNotFound)
}

func mkUser(t *testing.T, s core.Store, realm, id, name string) {
	t.Helper()
	ok(t, s.CreateUser(ctx, core.User{ID: id, Realm: realm, Username: name, Enabled: true, CreatedAt: t0}))
}

func scimExternalIDs(t *testing.T, s core.Store) {
	ss := scimStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	mkUser(t, s, "acme", "u1", "alice")
	mkUser(t, s, "acme", "u2", "bob")
	mkUser(t, s, "beta", "u3", "carol")

	ok(t, ss.SetSCIMExternalID(ctx, "acme", "u1", "ext-1"))
	ok(t, ss.SetSCIMExternalID(ctx, "acme", "u1", "ext-1")) // idempotent
	is(t, ss.SetSCIMExternalID(ctx, "acme", "u2", "ext-1"), idp.ErrConflict)
	ok(t, ss.SetSCIMExternalID(ctx, "beta", "u3", "ext-1")) // per realm

	id, err := ss.FindSCIMExternalID(ctx, "acme", "ext-1")
	ok(t, err)
	eq(t, id, "u1")
	_, err = ss.FindSCIMExternalID(ctx, "acme", "nope")
	is(t, err, idp.ErrNotFound)

	ok(t, ss.SetSCIMExternalID(ctx, "acme", "u2", "ext-2"))
	m, err := ss.SCIMExternalIDs(ctx, "acme", []string{"u1", "u2", "zz"})
	ok(t, err)
	eq(t, m, map[string]string{"u1": "ext-1", "u2": "ext-2"})
	m, err = ss.SCIMExternalIDs(ctx, "acme", nil)
	ok(t, err)
	eq(t, len(m), 2)

	// "" clears; the id becomes free for another user.
	ok(t, ss.SetSCIMExternalID(ctx, "acme", "u1", ""))
	_, err = ss.FindSCIMExternalID(ctx, "acme", "ext-1")
	is(t, err, idp.ErrNotFound)
	ok(t, ss.SetSCIMExternalID(ctx, "acme", "u2", "ext-1"))
}

func scimExternalIDUserDelete(t *testing.T, s core.Store) {
	ss := scimStore(t, s)
	mkRealm(t, s, "acme")
	mkUser(t, s, "acme", "u1", "alice")
	ok(t, ss.SetSCIMExternalID(ctx, "acme", "u1", "ext-1"))
	ok(t, s.DeleteUser(ctx, "acme", "u1"))
	_, err := ss.FindSCIMExternalID(ctx, "acme", "ext-1")
	is(t, err, idp.ErrNotFound)
}
