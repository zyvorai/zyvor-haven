// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.FAPIStore = (*Store)(nil)

func (s *Store) GetClientFAPI(ctx context.Context, realm, clientRef string) (core.ClientFAPI, error) {
	c := core.ClientFAPI{Realm: realm, ClientRef: clientRef}
	err := s.pool.QueryRow(ctx, `SELECT require_par, require_dpop, require_signed_request, jwks, authz_detail_types
		FROM client_fapi WHERE realm=$1 AND client_ref=$2`, realm, clientRef).
		Scan(&c.RequirePAR, &c.RequireDPoP, &c.RequireSignedRequest, &c.JWKS, &c.AuthzDetailTypes)
	if err = mapErr(err); err != nil {
		return core.ClientFAPI{}, err
	}
	if len(c.AuthzDetailTypes) == 0 {
		c.AuthzDetailTypes = nil
	}
	return c, nil
}

func (s *Store) PutClientFAPI(ctx context.Context, c core.ClientFAPI) error {
	types := c.AuthzDetailTypes
	if types == nil {
		types = []string{}
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO client_fapi (client_ref, realm, require_par, require_dpop, require_signed_request, jwks, authz_detail_types)
		SELECT id, realm, $3, $4, $5, $6, $7 FROM clients WHERE realm=$1 AND id=$2
		ON CONFLICT (client_ref) DO UPDATE SET require_par=EXCLUDED.require_par, require_dpop=EXCLUDED.require_dpop,
		  require_signed_request=EXCLUDED.require_signed_request, jwks=EXCLUDED.jwks, authz_detail_types=EXCLUDED.authz_detail_types`,
		c.Realm, c.ClientRef, c.RequirePAR, c.RequireDPoP, c.RequireSignedRequest, c.JWKS, types)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return idp.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteClientFAPI(ctx context.Context, realm, clientRef string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM client_fapi WHERE realm=$1 AND client_ref=$2`, realm, clientRef)
	return mapErr(err)
}

func (s *Store) PutFAPIRequest(ctx context.Context, r core.FAPIRequest) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO fapi_requests (kind, id_hash, realm, client_id, params, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, r.Kind, r.IDHash, r.Realm, r.ClientID, r.Params, r.ExpiresAt.UTC())
	return mapErr(err)
}

// ConsumeFAPIRequest is one DELETE ... RETURNING, so exactly one of several
// concurrent callers gets the row.
func (s *Store) ConsumeFAPIRequest(ctx context.Context, realm, kind, idHash string, now time.Time) (core.FAPIRequest, error) {
	r := core.FAPIRequest{Kind: kind, IDHash: idHash, Realm: realm}
	err := s.pool.QueryRow(ctx, `DELETE FROM fapi_requests WHERE kind=$1 AND id_hash=$2 AND realm=$3 AND expires_at > $4
		RETURNING client_id, params, expires_at`, kind, idHash, realm, now.UTC()).Scan(&r.ClientID, &r.Params, &r.ExpiresAt)
	if err = mapErr(err); err != nil {
		return core.FAPIRequest{}, err
	}
	r.ExpiresAt = r.ExpiresAt.UTC()
	return r, nil
}

func (s *Store) GetFAPIRequest(ctx context.Context, realm, kind, idHash string, now time.Time) (core.FAPIRequest, error) {
	r := core.FAPIRequest{Kind: kind, IDHash: idHash, Realm: realm}
	err := s.pool.QueryRow(ctx, `SELECT client_id, params, expires_at FROM fapi_requests
		WHERE kind=$1 AND id_hash=$2 AND realm=$3 AND expires_at > $4`, kind, idHash, realm, now.UTC()).
		Scan(&r.ClientID, &r.Params, &r.ExpiresAt)
	if err = mapErr(err); err != nil {
		return core.FAPIRequest{}, err
	}
	r.ExpiresAt = r.ExpiresAt.UTC()
	return r, nil
}

func (s *Store) PutFAPIBinding(ctx context.Context, b core.FAPIBinding) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO fapi_bindings (kind, key_hash, realm, client_id, details, dpop_jkt, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (kind, key_hash) DO UPDATE SET realm=EXCLUDED.realm, client_id=EXCLUDED.client_id,
		  details=EXCLUDED.details, dpop_jkt=EXCLUDED.dpop_jkt, expires_at=EXCLUDED.expires_at`,
		b.Kind, b.KeyHash, b.Realm, b.ClientID, b.Details, b.DPoPJKT, b.ExpiresAt.UTC())
	return mapErr(err)
}

func (s *Store) GetFAPIBinding(ctx context.Context, kind, keyHash string, now time.Time) (core.FAPIBinding, error) {
	b := core.FAPIBinding{Kind: kind, KeyHash: keyHash}
	err := s.pool.QueryRow(ctx, `SELECT realm, client_id, details, dpop_jkt, expires_at FROM fapi_bindings
		WHERE kind=$1 AND key_hash=$2 AND expires_at > $3`, kind, keyHash, now.UTC()).
		Scan(&b.Realm, &b.ClientID, &b.Details, &b.DPoPJKT, &b.ExpiresAt)
	if err = mapErr(err); err != nil {
		return core.FAPIBinding{}, err
	}
	b.ExpiresAt = b.ExpiresAt.UTC()
	return b, nil
}

func (s *Store) PurgeExpiredFAPI(ctx context.Context, now time.Time) (int, error) {
	a, err := s.pool.Exec(ctx, `DELETE FROM fapi_requests WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, err
	}
	b, err := s.pool.Exec(ctx, `DELETE FROM fapi_bindings WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return int(a.RowsAffected()), err
	}
	return int(a.RowsAffected() + b.RowsAffected()), nil
}
