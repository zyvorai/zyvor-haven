// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Migration 0012 must repair a database that already has several active keys
// for a realm (two replicas starting together did this on a real cluster) and
// must then make that state impossible. It runs against real Postgres only.
func TestMigration0012RepairsDuplicateActiveKeys(t *testing.T) {
	dsn := os.Getenv("HAVEN_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("HAVEN_TEST_PG_DSN not set")
	}
	ctx := context.Background()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.pool.Close()
	mig, err := migrationFS.ReadFile("migrations/0012_one_active_signing_key.sql")
	if err != nil {
		t.Fatal(err)
	}
	const realm = "dupkeys"
	_ = st.DeleteRealm(ctx, realm)
	if err := st.CreateRealm(ctx, core.Realm{Name: realm, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Leave the schema exactly as Open made it, whatever happened below.
		_, _ = st.pool.Exec(ctx, string(mig))
		_ = st.DeleteRealm(ctx, realm)
	}()

	// Build the broken state: no index, three active keys and one inactive one.
	if _, err := st.pool.Exec(ctx, `DROP INDEX IF EXISTS signing_keys_one_active`); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	ins := func(kid string, active bool, age time.Duration) {
		t.Helper()
		_, err := st.pool.Exec(ctx, `INSERT INTO signing_keys (realm, kid, alg, private_pem, public_jwk, active, not_after, created_at)
			VALUES ($1,$2,'ES256','\x00','\x7b7d',$3,NULL,$4)`, realm, kid, active, base.Add(age))
		if err != nil {
			t.Fatalf("insert %s: %v", kid, err)
		}
	}
	ins("a-oldest", true, 0)
	ins("b-middle", true, time.Minute)
	ins("c-newest", true, 2*time.Minute)
	ins("d-retired", false, -time.Minute)

	if _, err := st.pool.Exec(ctx, string(mig)); err != nil {
		t.Fatalf("migration failed on a database with duplicates: %v", err)
	}

	keys, err := st.ListSigningKeys(ctx, realm)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 {
		t.Fatalf("the migration deleted keys: %d left, want 4 (demoted keys must stay published)", len(keys))
	}
	var active []string
	for _, k := range keys {
		if k.Active {
			active = append(active, k.KID)
		}
		if !k.NotAfter.IsZero() && k.KID != "d-retired" {
			t.Errorf("%s got an expiry (%v): demoted keys must stay published", k.KID, k.NotAfter)
		}
	}
	if len(active) != 1 || active[0] != "a-oldest" {
		t.Fatalf("active keys after repair = %v, want only the oldest [a-oldest]", active)
	}

	// Running it again changes nothing (migrations may be re-applied on a fresh start).
	if _, err := st.pool.Exec(ctx, string(mig)); err != nil {
		t.Fatalf("migration is not idempotent: %v", err)
	}

	// And the database now refuses the state it just repaired.
	err = st.PutSigningKey(ctx, core.SigningKey{KID: "z-late", Realm: realm, Alg: "ES256",
		PrivatePEM: []byte("x"), PublicJWK: []byte("{}"), Active: true, CreatedAt: time.Now().UTC()})
	if !errors.Is(err, idp.ErrConflict) {
		t.Fatalf("a second active key was not refused after the migration: %v", err)
	}
}
