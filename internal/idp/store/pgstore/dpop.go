// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.DPoPStore = (*Store)(nil)

// RememberDPoPProof inserts the proof; an expired row for the same key is
// replaced in the same statement, a live one makes it a replay (ErrConflict).
func (s *Store) RememberDPoPProof(ctx context.Context, realm, proofHash string, now, expires time.Time) error {
	tag, err := s.pool.Exec(ctx, `INSERT INTO dpop_proofs (realm, proof_hash, expires_at) VALUES ($1,$2,$3)
		ON CONFLICT (realm, proof_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
		WHERE dpop_proofs.expires_at <= $4`, realm, proofHash, expires.UTC(), now.UTC())
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return idp.ErrConflict
	}
	return nil
}

// BindRefreshToken upserts the binding unless the token is already bound to a
// different key (then the WHERE fails, nothing is returned: ErrConflict).
func (s *Store) BindRefreshToken(ctx context.Context, tokenHash, jkt string, expires time.Time) error {
	var got string
	err := s.pool.QueryRow(ctx, `INSERT INTO dpop_refresh_bindings (token_hash, jkt, expires_at) VALUES ($1,$2,$3)
		ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
		WHERE dpop_refresh_bindings.jkt = EXCLUDED.jkt
		RETURNING jkt`, tokenHash, jkt, expires.UTC()).Scan(&got)
	if err = mapErr(err); err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return idp.ErrConflict
		}
		return err
	}
	return nil
}

func (s *Store) RefreshTokenBinding(ctx context.Context, tokenHash string, now time.Time) (string, error) {
	var jkt string
	err := s.pool.QueryRow(ctx, `SELECT jkt FROM dpop_refresh_bindings WHERE token_hash=$1 AND expires_at > $2`,
		tokenHash, now.UTC()).Scan(&jkt)
	return jkt, mapErr(err)
}

func (s *Store) PurgeExpiredDPoP(ctx context.Context, now time.Time) (int, error) {
	a, err := s.pool.Exec(ctx, `DELETE FROM dpop_proofs WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, err
	}
	b, err := s.pool.Exec(ctx, `DELETE FROM dpop_refresh_bindings WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return int(a.RowsAffected()), err
	}
	return int(a.RowsAffected() + b.RowsAffected()), nil
}
