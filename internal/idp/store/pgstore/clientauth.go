// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.ClientAuthStore = (*Store)(nil)

func (s *Store) GetClientAuth(ctx context.Context, realm, clientRef string) (core.ClientAuth, error) {
	c := core.ClientAuth{Realm: realm, ClientRef: clientRef}
	err := s.pool.QueryRow(ctx, `SELECT method, jwks, jwks_uri, signing_alg, tls_subject_dn, tls_san_dns, tls_san_uri,
		tls_san_ip, tls_san_email, cert_bound_tokens FROM client_auth WHERE realm=$1 AND client_ref=$2`, realm, clientRef).
		Scan(&c.Method, &c.JWKS, &c.JWKSURI, &c.SigningAlg, &c.TLSSubjectDN, &c.TLSSANDNS, &c.TLSSANURI,
			&c.TLSSANIP, &c.TLSSANEmail, &c.CertBoundTokens)
	if err = mapErr(err); err != nil {
		return core.ClientAuth{}, err
	}
	return c, nil
}

func (s *Store) PutClientAuth(ctx context.Context, c core.ClientAuth) error {
	tag, err := s.pool.Exec(ctx, `INSERT INTO client_auth (client_ref, realm, method, jwks, jwks_uri, signing_alg,
		  tls_subject_dn, tls_san_dns, tls_san_uri, tls_san_ip, tls_san_email, cert_bound_tokens)
		SELECT id, realm, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12 FROM clients WHERE realm=$1 AND id=$2
		ON CONFLICT (client_ref) DO UPDATE SET method=EXCLUDED.method, jwks=EXCLUDED.jwks, jwks_uri=EXCLUDED.jwks_uri,
		  signing_alg=EXCLUDED.signing_alg, tls_subject_dn=EXCLUDED.tls_subject_dn, tls_san_dns=EXCLUDED.tls_san_dns,
		  tls_san_uri=EXCLUDED.tls_san_uri, tls_san_ip=EXCLUDED.tls_san_ip, tls_san_email=EXCLUDED.tls_san_email,
		  cert_bound_tokens=EXCLUDED.cert_bound_tokens`,
		c.Realm, c.ClientRef, c.Method, c.JWKS, c.JWKSURI, c.SigningAlg, c.TLSSubjectDN, c.TLSSANDNS, c.TLSSANURI,
		c.TLSSANIP, c.TLSSANEmail, c.CertBoundTokens)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return idp.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteClientAuth(ctx context.Context, realm, clientRef string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM client_auth WHERE realm=$1 AND client_ref=$2`, realm, clientRef)
	return mapErr(err)
}

// RememberClientAssertion inserts the identifier; an expired row is replaced in
// the same statement, a live one makes it a replay (ErrConflict).
func (s *Store) RememberClientAssertion(ctx context.Context, realm, hash string, now, expires time.Time) error {
	tag, err := s.pool.Exec(ctx, `INSERT INTO client_assertions (realm, assertion_hash, expires_at) VALUES ($1,$2,$3)
		ON CONFLICT (realm, assertion_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
		WHERE client_assertions.expires_at <= $4`, realm, hash, expires.UTC(), now.UTC())
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return idp.ErrConflict
	}
	return nil
}

func (s *Store) PurgeExpiredClientAssertions(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM client_assertions WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}
