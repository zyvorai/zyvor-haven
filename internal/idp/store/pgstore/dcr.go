// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.DCRStore = (*Store)(nil)

const iatCols = `id, realm, token_hash, note, count, remaining, created_at, expires_at`

func scanIAT(row pgx.Row) (core.InitialAccessToken, error) {
	var t core.InitialAccessToken
	err := row.Scan(&t.ID, &t.Realm, &t.TokenHash, &t.Note, &t.Count, &t.Remaining, &t.CreatedAt, &t.ExpiresAt)
	t.CreatedAt, t.ExpiresAt = utc(t.CreatedAt), utc(t.ExpiresAt)
	return t, mapErr(err)
}

func (s *Store) PutInitialAccessToken(ctx context.Context, t core.InitialAccessToken) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO dcr_initial_tokens (`+iatCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		t.ID, t.Realm, t.TokenHash, t.Note, t.Count, t.Remaining, t.CreatedAt, t.ExpiresAt)
	return mapErr(err)
}

func (s *Store) ListInitialAccessTokens(ctx context.Context, realm string) ([]core.InitialAccessToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+iatCols+` FROM dcr_initial_tokens WHERE realm=$1 ORDER BY created_at, id`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.InitialAccessToken{}
	for rows.Next() {
		t, err := scanIAT(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) DeleteInitialAccessToken(ctx context.Context, realm, id string) error {
	return s.exec1(ctx, `DELETE FROM dcr_initial_tokens WHERE realm=$1 AND id=$2`, realm, id)
}

// ConsumeInitialAccessToken is one conditional UPDATE: two concurrent callers
// on a token with one registration left cannot both succeed.
func (s *Store) ConsumeInitialAccessToken(ctx context.Context, realm, tokenHash string, now time.Time) (core.InitialAccessToken, error) {
	return scanIAT(s.pool.QueryRow(ctx, `UPDATE dcr_initial_tokens SET remaining = remaining - 1
		WHERE realm=$1 AND token_hash=$2 AND remaining > 0 AND expires_at > $3
		RETURNING `+iatCols, realm, tokenHash, now))
}

func (s *Store) RefundInitialAccessToken(ctx context.Context, realm, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE dcr_initial_tokens SET remaining = remaining + 1
		WHERE realm=$1 AND id=$2 AND remaining < count`, realm, id)
	return mapErr(err)
}

const rcCols = `realm, client_id, client_uuid, reg_token_hash, created_via, initial_token_id, application_type,
	token_auth_method, scope, grant_types, contacts, logo_uri, client_uri, policy_uri, tos_uri, created_at, updated_at`

func scanRC(row pgx.Row) (core.RegisteredClient, error) {
	var rc core.RegisteredClient
	err := row.Scan(&rc.Realm, &rc.ClientID, &rc.ClientUUID, &rc.RegTokenHash, &rc.CreatedVia, &rc.InitialTokenID,
		&rc.ApplicationType, &rc.TokenAuthMethod, &rc.Scope, &rc.GrantTypes, &rc.Contacts, &rc.LogoURI,
		&rc.ClientURI, &rc.PolicyURI, &rc.TosURI, &rc.CreatedAt, &rc.UpdatedAt)
	rc.GrantTypes, rc.Contacts = nilIfEmpty(rc.GrantTypes), nilIfEmpty(rc.Contacts)
	rc.CreatedAt, rc.UpdatedAt = utc(rc.CreatedAt), utc(rc.UpdatedAt)
	return rc, mapErr(err)
}

func (s *Store) PutRegisteredClient(ctx context.Context, rc core.RegisteredClient) error {
	if rc.CreatedAt.IsZero() {
		rc.CreatedAt = time.Now().UTC()
	}
	if rc.UpdatedAt.IsZero() {
		rc.UpdatedAt = rc.CreatedAt
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO dcr_clients (`+rcCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		rc.Realm, rc.ClientID, rc.ClientUUID, rc.RegTokenHash, rc.CreatedVia, rc.InitialTokenID,
		rc.ApplicationType, rc.TokenAuthMethod, rc.Scope, arr(rc.GrantTypes), arr(rc.Contacts), rc.LogoURI,
		rc.ClientURI, rc.PolicyURI, rc.TosURI, rc.CreatedAt, rc.UpdatedAt)
	return mapErr(err)
}

func (s *Store) GetRegisteredClient(ctx context.Context, realm, clientID string) (core.RegisteredClient, error) {
	return scanRC(s.pool.QueryRow(ctx, `SELECT `+rcCols+` FROM dcr_clients WHERE realm=$1 AND client_id=$2`, realm, clientID))
}

func (s *Store) UpdateRegisteredClient(ctx context.Context, rc core.RegisteredClient) error {
	return s.exec1(ctx, `UPDATE dcr_clients SET application_type=$3, token_auth_method=$4, scope=$5,
		grant_types=$6, contacts=$7, logo_uri=$8, client_uri=$9, policy_uri=$10, tos_uri=$11, updated_at=$12
		WHERE realm=$1 AND client_id=$2`,
		rc.Realm, rc.ClientID, rc.ApplicationType, rc.TokenAuthMethod, rc.Scope, arr(rc.GrantTypes),
		arr(rc.Contacts), rc.LogoURI, rc.ClientURI, rc.PolicyURI, rc.TosURI, rc.UpdatedAt)
}

func (s *Store) DeleteRegisteredClient(ctx context.Context, realm, clientID string) error {
	return s.exec1(ctx, `DELETE FROM dcr_clients WHERE realm=$1 AND client_id=$2`, realm, clientID)
}

func (s *Store) ListRegisteredClients(ctx context.Context, realm string) ([]core.RegisteredClient, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+rcCols+` FROM dcr_clients WHERE realm=$1 ORDER BY client_id`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.RegisteredClient{}
	for rows.Next() {
		rc, err := scanRC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rc)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) GetRegistrationPolicy(ctx context.Context, realm string) (core.RegistrationPolicy, error) {
	var p core.RegistrationPolicy
	err := s.pool.QueryRow(ctx, `SELECT realm, max_clients, allowed_grant_types FROM dcr_policies WHERE realm=$1`, realm).
		Scan(&p.Realm, &p.MaxClients, &p.AllowedGrantTypes)
	p.AllowedGrantTypes = nilIfEmpty(p.AllowedGrantTypes)
	return p, mapErr(err)
}

func (s *Store) PutRegistrationPolicy(ctx context.Context, p core.RegistrationPolicy) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO dcr_policies (realm, max_clients, allowed_grant_types) VALUES ($1,$2,$3)
		ON CONFLICT (realm) DO UPDATE SET max_clients=EXCLUDED.max_clients, allowed_grant_types=EXCLUDED.allowed_grant_types`,
		p.Realm, p.MaxClients, arr(p.AllowedGrantTypes))
	return mapErr(err)
}
