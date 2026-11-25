// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
)

// A client's authentication method survives a `dev --persist` snapshot.
func TestSnapshotCoversClientAuth(t *testing.T) {
	ctx := context.Background()
	a := New()
	if err := a.CreateRealm(ctx, core.Realm{Name: "demo"}); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateClient(ctx, core.Client{ID: "c1", Realm: "demo", ClientID: "svc"}); err != nil {
		t.Fatal(err)
	}
	want := core.ClientAuth{Realm: "demo", ClientRef: "c1", Method: core.AuthMethodPrivateKeyJWT, JWKSURI: "https://c.example/k"}
	if err := a.PutClientAuth(ctx, want); err != nil {
		t.Fatal(err)
	}
	b, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Restore(b); err != nil {
		t.Fatal(err)
	}
	got, err := c.GetClientAuth(ctx, "demo", "c1")
	if err != nil || got != want {
		t.Fatalf("%+v %v", got, err)
	}
}
