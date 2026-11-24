// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"

	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.SCIMStore = (*Store)(nil)

func (s *Store) PutSCIMToken(ctx context.Context, t core.SCIMToken) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO scim_tokens (realm, realm_id, token_hash, read_only, created_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (realm) DO UPDATE SET realm_id=EXCLUDED.realm_id, token_hash=EXCLUDED.token_hash,
			read_only=EXCLUDED.read_only, created_by=EXCLUDED.created_by, created_at=EXCLUDED.created_at`,
		t.Realm, t.RealmID, t.TokenHash, t.ReadOnly, t.CreatedBy, t.CreatedAt.UTC())
	return mapErr(err)
}

func (s *Store) GetSCIMToken(ctx context.Context, realm string) (core.SCIMToken, error) {
	var t core.SCIMToken
	err := s.pool.QueryRow(ctx, `SELECT realm, realm_id, token_hash, read_only, created_by, created_at
		FROM scim_tokens WHERE realm=$1`, realm).
		Scan(&t.Realm, &t.RealmID, &t.TokenHash, &t.ReadOnly, &t.CreatedBy, &t.CreatedAt)
	t.CreatedAt = utc(t.CreatedAt)
	return t, mapErr(err)
}

func (s *Store) DeleteSCIMToken(ctx context.Context, realm string) error {
	return s.exec1(ctx, `DELETE FROM scim_tokens WHERE realm=$1`, realm)
}

func (s *Store) SetSCIMExternalID(ctx context.Context, realm, userID, externalID string) error {
	if externalID == "" {
		_, err := s.pool.Exec(ctx, `DELETE FROM scim_external_ids WHERE realm=$1 AND user_id=$2`, realm, userID)
		return mapErr(err)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO scim_external_ids (realm, user_id, external_id) VALUES ($1,$2,$3)
		ON CONFLICT (realm, user_id) DO UPDATE SET external_id=EXCLUDED.external_id`, realm, userID, externalID)
	return mapErr(err)
}

func (s *Store) SCIMExternalIDs(ctx context.Context, realm string, ids []string) (map[string]string, error) {
	q := `SELECT user_id, external_id FROM scim_external_ids WHERE realm=$1`
	args := []any{realm}
	if len(ids) > 0 {
		q += ` AND user_id = ANY($2)`
		args = append(args, ids)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var u, e string
		if err := rows.Scan(&u, &e); err != nil {
			return nil, mapErr(err)
		}
		out[u] = e
	}
	return out, mapErr(rows.Err())
}

func (s *Store) FindSCIMExternalID(ctx context.Context, realm, externalID string) (string, error) {
	var u string
	err := s.pool.QueryRow(ctx, `SELECT user_id FROM scim_external_ids WHERE realm=$1 AND external_id=$2`, realm, externalID).Scan(&u)
	return u, mapErr(err)
}
