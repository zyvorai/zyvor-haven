// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.PasskeyStore = (*Store)(nil)

// #nosec G101 -- SQL column list, no credential value
const passkeyCols = `realm, user_id, credential_id, public_key, sign_count, transports, aaguid, name,
	backup_eligible, backup_state, created_at, last_used_at`

func scanPasskey(row pgx.Row) (core.Passkey, error) {
	var p core.Passkey
	var sc int64
	var used *time.Time
	if err := row.Scan(&p.Realm, &p.UserID, &p.CredentialID, &p.PublicKey, &sc, &p.Transports, &p.AAGUID, &p.Name,
		&p.BackupEligible, &p.BackupState, &p.CreatedAt, &used); err != nil {
		return core.Passkey{}, mapErr(err)
	}
	if sc < 0 || sc > math.MaxUint32 {
		return core.Passkey{}, errors.New("pgstore: passkey sign_count out of range")
	}
	p.SignCount = uint32(sc)
	if used != nil {
		p.LastUsedAt = used.UTC()
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return p, nil
}

func (s *Store) UserHandle(ctx context.Context, realm, userID, candidate string) (string, error) {
	if candidate == "" {
		return "", errors.New("pgstore: empty passkey user handle")
	}
	// Insert-if-absent, then read: concurrent first calls converge on one row.
	if _, err := s.pool.Exec(ctx, `INSERT INTO passkey_user_handles (realm, user_id, handle)
		SELECT $1, u.id, $3 FROM users u WHERE u.realm=$1 AND u.id=$2
		ON CONFLICT (realm, user_id) DO NOTHING`, realm, userID, candidate); err != nil {
		return "", mapErr(err)
	}
	var h string
	err := s.pool.QueryRow(ctx, `SELECT handle FROM passkey_user_handles WHERE realm=$1 AND user_id=$2`, realm, userID).Scan(&h)
	return h, mapErr(err)
}

func (s *Store) UserByHandle(ctx context.Context, realm, handle string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `SELECT user_id FROM passkey_user_handles WHERE realm=$1 AND handle=$2`, realm, handle).Scan(&id)
	return id, mapErr(err)
}

func (s *Store) AddPasskey(ctx context.Context, p core.Passkey) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO passkeys (`+passkeyCols+`)
		SELECT $1,u.id,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL FROM users u WHERE u.realm=$1 AND u.id=$2`,
		p.Realm, p.UserID, p.CredentialID, p.PublicKey, int64(p.SignCount), arr(p.Transports), p.AAGUID, p.Name,
		p.BackupEligible, p.BackupState, utc(p.CreatedAt))
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return idp.ErrNotFound
	}
	return nil
}

func (s *Store) GetPasskey(ctx context.Context, realm, credentialID string) (core.Passkey, error) {
	return scanPasskey(s.pool.QueryRow(ctx, `SELECT `+passkeyCols+` FROM passkeys WHERE realm=$1 AND credential_id=$2`, realm, credentialID))
}

func (s *Store) ListPasskeys(ctx context.Context, realm, userID string) ([]core.Passkey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+passkeyCols+` FROM passkeys WHERE realm=$1 AND user_id=$2 ORDER BY created_at, credential_id`, realm, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []core.Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) UpdatePasskeyUse(ctx context.Context, realm, credentialID string, signCount uint32, backupState bool, at time.Time) error {
	return s.exec1(ctx, `UPDATE passkeys SET sign_count=$3, backup_state=$4, last_used_at=$5 WHERE realm=$1 AND credential_id=$2`,
		realm, credentialID, int64(signCount), backupState, utc(at))
}

func (s *Store) RenamePasskey(ctx context.Context, realm, userID, credentialID, name string) error {
	return s.exec1(ctx, `UPDATE passkeys SET name=$4 WHERE realm=$1 AND user_id=$2 AND credential_id=$3`, realm, userID, credentialID, name)
}

func (s *Store) DeletePasskey(ctx context.Context, realm, userID, credentialID string, keepLast bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Lock the user's rows so two concurrent deletes cannot both pass the check.
	rows, err := tx.Query(ctx, `SELECT credential_id FROM passkeys WHERE realm=$1 AND user_id=$2 FOR UPDATE`, realm, userID)
	if err != nil {
		return mapErr(err)
	}
	n, found := 0, false
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return mapErr(err)
		}
		n++
		found = found || id == credentialID
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return mapErr(err)
	}
	if !found {
		return idp.ErrNotFound
	}
	if keepLast && n <= 1 {
		return idp.ErrConflict
	}
	if _, err := tx.Exec(ctx, `DELETE FROM passkeys WHERE realm=$1 AND user_id=$2 AND credential_id=$3`, realm, userID, credentialID); err != nil {
		return mapErr(err)
	}
	return mapErr(tx.Commit(ctx))
}

func (s *Store) ConsumeChallenge(ctx context.Context, digest string, now, expires time.Time) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM passkey_challenges WHERE expires_at <= $1`, utc(now)); err != nil {
		return mapErr(err)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO passkey_challenges (digest, expires_at) VALUES ($1,$2)`, digest, utc(expires))
	return mapErr(err)
}

func (s *Store) RealmRequiresPasskeys(ctx context.Context, realm string) (bool, error) {
	var v bool
	err := s.pool.QueryRow(ctx, `SELECT require_passkeys FROM passkey_realm_policy WHERE realm=$1`, realm).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return v, err
}

func (s *Store) SetRealmRequiresPasskeys(ctx context.Context, realm string, v bool) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO passkey_realm_policy (realm, require_passkeys) VALUES ($1,$2)
		ON CONFLICT (realm) DO UPDATE SET require_passkeys=EXCLUDED.require_passkeys`, realm, v)
	return mapErr(err)
}
