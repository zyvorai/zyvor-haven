// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.GrantStore = (*Store)(nil)

const grantCols = `id, realm, user_id, role, granted_by, reason, created_at, expires_at, revoked_at, revoked_by`

func scanGrant(row pgx.Row) (core.RoleGrant, error) {
	var g core.RoleGrant
	var rev *time.Time
	err := row.Scan(&g.ID, &g.Realm, &g.UserID, &g.Role, &g.GrantedBy, &g.Reason, &g.CreatedAt, &g.ExpiresAt, &rev, &g.RevokedBy)
	g.CreatedAt, g.ExpiresAt = utc(g.CreatedAt), utc(g.ExpiresAt)
	if rev != nil {
		g.RevokedAt = utc(*rev)
	}
	return g, mapErr(err)
}

func collectGrants(rows pgx.Rows) ([]core.RoleGrant, error) {
	defer rows.Close()
	out := []core.RoleGrant{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, mapErr(rows.Err())
}

// CreateRoleGrant counts and inserts under a per-user advisory lock so
// concurrent creates cannot exceed maxActive.
func (s *Store) CreateRoleGrant(ctx context.Context, g core.RoleGrant, maxActive int, now time.Time) (core.RoleGrant, error) {
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = now
	}
	g.CreatedAt, g.ExpiresAt = g.CreatedAt.UTC(), g.ExpiresAt.UTC()
	g.RevokedAt, g.RevokedBy = time.Time{}, ""
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('role_grants|' || $1 || '|' || $2, 0))`,
			g.Realm, g.UserID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM role_grants
			WHERE realm=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at > $3`, g.Realm, g.UserID, now).Scan(&n); err != nil {
			return err
		}
		if maxActive > 0 && n >= maxActive {
			return core.ErrGrantLimit
		}
		_, err := tx.Exec(ctx, `INSERT INTO role_grants (`+grantCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL,'')`,
			g.ID, g.Realm, g.UserID, g.Role, g.GrantedBy, g.Reason, g.CreatedAt, g.ExpiresAt)
		return err
	})
	if err != nil {
		if errors.Is(err, core.ErrGrantLimit) {
			return core.RoleGrant{}, err
		}
		return core.RoleGrant{}, mapErr(err)
	}
	return g, nil
}

func (s *Store) ListRoleGrants(ctx context.Context, realm, userID string, activeOnly bool, now time.Time, limit int) ([]core.RoleGrant, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `SELECT `+grantCols+` FROM role_grants
		WHERE realm=$1 AND ($2::text = '' OR user_id=$2)
		AND (NOT $3::boolean OR (revoked_at IS NULL AND expires_at > $4))
		ORDER BY created_at DESC, id LIMIT $5`, realm, userID, activeOnly, now, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	return collectGrants(rows)
}

func (s *Store) RevokeRoleGrant(ctx context.Context, realm, userID, id, by string, now time.Time) (core.RoleGrant, error) {
	g, err := scanGrant(s.pool.QueryRow(ctx, `UPDATE role_grants SET revoked_at=$5, revoked_by=$6
		WHERE realm=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL AND expires_at > $4
		RETURNING `+grantCols, realm, userID, id, now, now.UTC(), by))
	if err == nil {
		return g, nil
	}
	if !errors.Is(err, idp.ErrNotFound) {
		return core.RoleGrant{}, err
	}
	var one int
	if qerr := s.pool.QueryRow(ctx, `SELECT 1 FROM role_grants WHERE realm=$1 AND user_id=$2 AND id=$3`,
		realm, userID, id).Scan(&one); qerr == nil {
		return core.RoleGrant{}, fmt.Errorf("grant already ended: %w", idp.ErrConflict)
	}
	return core.RoleGrant{}, err
}

func (s *Store) ActiveRoles(ctx context.Context, realm, userID string, now time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT role FROM role_grants
		WHERE realm=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at > $3 ORDER BY role`, realm, userID, now)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) PurgeExpiredGrants(ctx context.Context, now time.Time) (core.GrantPurge, error) {
	var res core.GrantPurge
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE role_grants SET expiry_reported=true
			WHERE revoked_at IS NULL AND NOT expiry_reported AND expires_at <= $1 RETURNING `+grantCols, now)
		if err != nil {
			return err
		}
		res.Expired, err = collectGrants(rows)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM role_grants
			WHERE LEAST(COALESCE(revoked_at, expires_at), expires_at) <= $1 AND NOT (revoked_at IS NULL AND expires_at > $2)`,
			now.Add(-core.GrantRetention), now)
		res.Deleted = int(tag.RowsAffected())
		return err
	})
	return res, mapErr(err)
}

func (s *Store) GetGrantPolicy(ctx context.Context, realm string) (core.GrantPolicy, error) {
	if _, err := s.GetRealm(ctx, realm); err != nil {
		return core.GrantPolicy{}, err
	}
	var p core.GrantPolicy
	err := s.pool.QueryRow(ctx, `SELECT max_duration_seconds, require_reason, allowed_roles FROM grant_policies WHERE realm=$1`, realm).
		Scan(&p.MaxDurationSeconds, &p.RequireReason, &p.AllowedRoles)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.DefaultGrantPolicy(), nil
	}
	if p.AllowedRoles == nil {
		p.AllowedRoles = []string{}
	}
	return p, mapErr(err)
}

func (s *Store) PutGrantPolicy(ctx context.Context, realm string, p core.GrantPolicy) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO grant_policies (realm, max_duration_seconds, require_reason, allowed_roles)
		VALUES ($1,$2,$3,$4) ON CONFLICT (realm) DO UPDATE SET
		max_duration_seconds=EXCLUDED.max_duration_seconds, require_reason=EXCLUDED.require_reason, allowed_roles=EXCLUDED.allowed_roles`,
		realm, p.MaxDurationSeconds, p.RequireReason, arr(p.AllowedRoles))
	return mapErr(err)
}
