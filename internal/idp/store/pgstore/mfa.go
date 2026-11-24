// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.MFAStore = (*Store)(nil)

// PutTOTP starts or restarts an enrollment. The conditional DO UPDATE only
// touches an unconfirmed row; a confirmed one makes it affect no row, which is
// a conflict.
func (s *Store) PutTOTP(ctx context.Context, c core.TOTPCredential) error {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO user_totp AS t (realm, user_id, sealed_seed, confirmed, created_at, last_used_step)
		VALUES ($1, $2, $3, false, $4, 0)
		ON CONFLICT (realm, user_id) DO UPDATE
		SET sealed_seed = EXCLUDED.sealed_seed, created_at = EXCLUDED.created_at, last_used_step = 0
		WHERE NOT t.confirmed`, c.Realm, c.UserID, c.SealedSeed, c.CreatedAt)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("totp credential: %w", idp.ErrConflict)
	}
	return nil
}

// GetTOTP implements core.MFAStore.
func (s *Store) GetTOTP(ctx context.Context, realm, userID string) (core.TOTPCredential, error) {
	var c core.TOTPCredential
	err := s.pool.QueryRow(ctx, `SELECT realm, user_id, sealed_seed, confirmed, created_at, last_used_step
		FROM user_totp WHERE realm=$1 AND user_id=$2`, realm, userID).
		Scan(&c.Realm, &c.UserID, &c.SealedSeed, &c.Confirmed, &c.CreatedAt, &c.LastUsedStep)
	if err != nil {
		return core.TOTPCredential{}, mapErr(err)
	}
	c.CreatedAt = c.CreatedAt.UTC()
	return c, nil
}

// ConfirmTOTP is one conditional UPDATE: only the caller that flips
// confirmed false->true gets a row.
func (s *Store) ConfirmTOTP(ctx context.Context, realm, userID string, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE user_totp SET confirmed=true, last_used_step=$3
		WHERE realm=$1 AND user_id=$2 AND NOT confirmed`, realm, userID, step)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

// UseTOTPStep is a compare-and-set in SQL: of parallel callers with the same
// step the row lock serialises them and only the first satisfies
// last_used_step < step.
func (s *Store) UseTOTPStep(ctx context.Context, realm, userID string, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE user_totp SET last_used_step=$3
		WHERE realm=$1 AND user_id=$2 AND confirmed AND last_used_step < $3`, realm, userID, step)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

// DeleteUserMFA implements core.MFAStore.
func (s *Store) DeleteUserMFA(ctx context.Context, realm, userID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM user_totp WHERE realm=$1 AND user_id=$2`, realm, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE realm=$1 AND user_id=$2`, realm, userID)
		return err
	})
}

// ReplaceRecoveryCodes swaps the whole set in one transaction.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, realm, userID string, hashes []string) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE realm=$1 AND user_id=$2`, realm, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := tx.Exec(ctx, `INSERT INTO user_recovery_codes (realm, user_id, code_hash) VALUES ($1,$2,$3)
				ON CONFLICT DO NOTHING`, realm, userID, h); err != nil {
				return err
			}
		}
		return nil
	})
	return mapErr(err)
}

// ConsumeRecoveryCode is a single DELETE: exactly one parallel caller sees a
// row affected.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, realm, userID, hash string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM user_recovery_codes WHERE realm=$1 AND user_id=$2 AND code_hash=$3`,
		realm, userID, hash)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

// CountRecoveryCodes implements core.MFAStore.
func (s *Store) CountRecoveryCodes(ctx context.Context, realm, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM user_recovery_codes WHERE realm=$1 AND user_id=$2`, realm, userID).Scan(&n)
	return n, mapErr(err)
}

// GetMFAPolicy implements core.MFAStore.
func (s *Store) GetMFAPolicy(ctx context.Context, realm string) (core.MFAPolicy, error) {
	var p core.MFAPolicy
	err := s.pool.QueryRow(ctx, `SELECT require_mfa FROM realm_mfa_policy WHERE realm=$1`, realm).Scan(&p.RequireMFA)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.MFAPolicy{}, nil
	}
	return p, mapErr(err)
}

// PutMFAPolicy implements core.MFAStore.
func (s *Store) PutMFAPolicy(ctx context.Context, realm string, p core.MFAPolicy) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO realm_mfa_policy (realm, require_mfa) VALUES ($1,$2)
		ON CONFLICT (realm) DO UPDATE SET require_mfa = EXCLUDED.require_mfa`, realm, p.RequireMFA)
	return mapErr(err)
}
