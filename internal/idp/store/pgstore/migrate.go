// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationLockID is the pg advisory lock key serializing migrations across
// replicas ("haveniDP" as an int64).
const migrationLockID int64 = 0x68617665_6e694450

// Migrate applies every pending migration in one transaction guarded by a
// transaction-scoped advisory lock, so concurrent replicas are safe: the
// losers block, then find nothing left to do.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		num, _, ok := strings.Cut(name, "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil {
			return fmt.Errorf("pgstore: bad migration name %q", name)
		}
		migs = append(migs, mig{v, name})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
			return fmt.Errorf("pgstore: migration lock: %w", err)
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version    integer PRIMARY KEY,
			name       text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return fmt.Errorf("pgstore: schema_migrations: %w", err)
		}
		for _, m := range migs {
			var one int
			err := tx.QueryRow(ctx, `SELECT 1 FROM schema_migrations WHERE version=$1`, m.version).Scan(&one)
			if err == nil {
				continue
			}
			if err != pgx.ErrNoRows {
				return err
			}
			body, err := migrationFS.ReadFile("migrations/" + m.name)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				return fmt.Errorf("pgstore: migration %s: %w", m.name, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1,$2)`, m.version, m.name); err != nil {
				return err
			}
		}
		return nil
	})
}
