// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.FedStore = (*Store)(nil)

const fedProvCols = `realm, alias, display_name, provider_type, enabled, trust_email, config, client_secret_sealed, created_at, updated_at`

func scanFedProvider(row pgx.Row) (core.FedProvider, error) {
	var p core.FedProvider
	err := row.Scan(&p.Realm, &p.Alias, &p.DisplayName, &p.ProviderType, &p.Enabled, &p.TrustEmail,
		&p.Config, &p.ClientSecretSealed, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return core.FedProvider{}, mapErr(err)
	}
	if p.Config == nil {
		p.Config = map[string]string{}
	}
	return p, nil
}

func cfgOrEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func (s *Store) CreateFedProvider(ctx context.Context, p core.FedProvider) error {
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO fed_providers (`+fedProvCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		p.Realm, p.Alias, p.DisplayName, p.ProviderType, p.Enabled, p.TrustEmail, cfgOrEmpty(p.Config),
		p.ClientSecretSealed, p.CreatedAt, p.UpdatedAt)
	return mapErr(err)
}

func (s *Store) UpdateFedProvider(ctx context.Context, p core.FedProvider) error {
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now().UTC()
	}
	return s.exec1(ctx, `UPDATE fed_providers SET display_name=$3, provider_type=$4, enabled=$5, trust_email=$6,
		config=$7, client_secret_sealed=$8, updated_at=$9 WHERE realm=$1 AND alias=$2`,
		p.Realm, p.Alias, p.DisplayName, p.ProviderType, p.Enabled, p.TrustEmail, cfgOrEmpty(p.Config),
		p.ClientSecretSealed, p.UpdatedAt)
}

func (s *Store) GetFedProvider(ctx context.Context, realm, alias string) (core.FedProvider, error) {
	return scanFedProvider(s.pool.QueryRow(ctx, `SELECT `+fedProvCols+` FROM fed_providers WHERE realm=$1 AND alias=$2`, realm, alias))
}

func (s *Store) ListFedProviders(ctx context.Context, realm string) ([]core.FedProvider, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+fedProvCols+` FROM fed_providers WHERE realm=$1 ORDER BY alias`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.FedProvider{}
	for rows.Next() {
		p, err := scanFedProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, mapErr(rows.Err())
}

// DeleteFedProvider removes the provider; links and in-flight states go with it.
func (s *Store) DeleteFedProvider(ctx context.Context, realm, alias string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM fed_login_states WHERE realm=$1 AND alias=$2`, realm, alias); err != nil {
			return mapErr(err)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM fed_providers WHERE realm=$1 AND alias=$2`, realm, alias)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return idp.ErrNotFound
		}
		return nil
	})
}

const fedLinkCols = `realm, alias, subject, user_id, mapped_roles, created_at, last_login_at`

func scanFedLink(row pgx.Row) (core.FedLink, error) {
	var l core.FedLink
	err := row.Scan(&l.Realm, &l.Alias, &l.Subject, &l.UserID, &l.MappedRoles, &l.CreatedAt, &l.LastLoginAt)
	return l, mapErr(err)
}

func (s *Store) GetFedLink(ctx context.Context, realm, alias, subject string) (core.FedLink, error) {
	return scanFedLink(s.pool.QueryRow(ctx, `SELECT `+fedLinkCols+` FROM fed_links WHERE realm=$1 AND alias=$2 AND subject=$3`, realm, alias, subject))
}

func (s *Store) CreateFedLink(ctx context.Context, l core.FedLink) error {
	now := time.Now().UTC()
	if l.CreatedAt.IsZero() {
		l.CreatedAt = now
	}
	if l.LastLoginAt.IsZero() {
		l.LastLoginAt = l.CreatedAt
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO fed_links (`+fedLinkCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		l.Realm, l.Alias, l.Subject, l.UserID, arr(l.MappedRoles), l.CreatedAt, l.LastLoginAt)
	return mapErr(err)
}

func (s *Store) UpdateFedLink(ctx context.Context, l core.FedLink) error {
	return s.exec1(ctx, `UPDATE fed_links SET mapped_roles=$4, last_login_at=$5 WHERE realm=$1 AND alias=$2 AND subject=$3`,
		l.Realm, l.Alias, l.Subject, arr(l.MappedRoles), l.LastLoginAt)
}

func (s *Store) ListFedLinksByUser(ctx context.Context, realm, userID string) ([]core.FedLink, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+fedLinkCols+` FROM fed_links WHERE realm=$1 AND user_id=$2 ORDER BY alias`, realm, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.FedLink{}
	for rows.Next() {
		l, err := scanFedLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) DeleteFedLink(ctx context.Context, realm, alias, userID string) error {
	return s.exec1(ctx, `DELETE FROM fed_links WHERE realm=$1 AND alias=$2 AND user_id=$3`, realm, alias, userID)
}

func (s *Store) DeleteFedLinksForUser(ctx context.Context, realm, userID string) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM fed_links WHERE realm=$1 AND user_id=$2`, realm, userID)
	return int(tag.RowsAffected()), mapErr(err)
}

func (s *Store) PutFedState(ctx context.Context, st core.FedLoginState) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM fed_login_states WHERE expires_at <= $1`, time.Now().UTC()); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO fed_login_states (state_hash, realm, alias, browser_hash, nonce, auth_query, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, st.StateHash, st.Realm, st.Alias, st.BrowserHash, st.Nonce, st.AuthQuery, st.ExpiresAt)
		return mapErr(err)
	})
}

func (s *Store) ConsumeFedState(ctx context.Context, stateHash string) (core.FedLoginState, error) {
	var st core.FedLoginState
	err := s.pool.QueryRow(ctx, `DELETE FROM fed_login_states WHERE state_hash=$1
		RETURNING state_hash, realm, alias, browser_hash, nonce, auth_query, expires_at`, stateHash).
		Scan(&st.StateHash, &st.Realm, &st.Alias, &st.BrowserHash, &st.Nonce, &st.AuthQuery, &st.ExpiresAt)
	return st, mapErr(err)
}
