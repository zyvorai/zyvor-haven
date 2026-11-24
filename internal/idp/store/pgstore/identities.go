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

var (
	_ core.WorkloadStore = (*Store)(nil)
	_ core.AgentStore    = (*Store)(nil)
)

// ---- workload identities ----

const wlCols = `id, realm, name, client_id, issuer, jwks_uri, jwks, audience, subject, allowed_scopes, ttl_seconds, enabled, created_by, created_at`

func scanWL(row pgx.Row) (core.WorkloadIdentity, error) {
	var w core.WorkloadIdentity
	err := row.Scan(&w.ID, &w.Realm, &w.Name, &w.ClientID, &w.Issuer, &w.JWKSURI, &w.JWKS, &w.Audience, &w.Subject,
		&w.AllowedScopes, &w.TTLSeconds, &w.Enabled, &w.CreatedBy, &w.CreatedAt)
	w.CreatedAt = utc(w.CreatedAt)
	if w.AllowedScopes == nil {
		w.AllowedScopes = []string{}
	}
	return w, mapErr(err)
}

func (s *Store) CreateWorkloadIdentity(ctx context.Context, w core.WorkloadIdentity) (core.WorkloadIdentity, error) {
	if w.ID == "" {
		w.ID = uuid.NewString()
	}
	if w.CreatedAt.IsZero() {
		w.CreatedAt = time.Now()
	}
	return scanWL(s.pool.QueryRow(ctx, `INSERT INTO workload_identities (`+wlCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING `+wlCols,
		w.ID, w.Realm, w.Name, w.ClientID, w.Issuer, w.JWKSURI, w.JWKS, w.Audience, w.Subject,
		arr(w.AllowedScopes), w.TTLSeconds, w.Enabled, w.CreatedBy, w.CreatedAt.UTC()))
}

func (s *Store) GetWorkloadIdentity(ctx context.Context, realm, id string) (core.WorkloadIdentity, error) {
	return scanWL(s.pool.QueryRow(ctx, `SELECT `+wlCols+` FROM workload_identities WHERE realm=$1 AND id=$2`, realm, id))
}

func (s *Store) GetWorkloadIdentityByClient(ctx context.Context, realm, clientID string) (core.WorkloadIdentity, error) {
	return scanWL(s.pool.QueryRow(ctx, `SELECT `+wlCols+` FROM workload_identities WHERE realm=$1 AND client_id=$2`, realm, clientID))
}

func (s *Store) ListWorkloadIdentities(ctx context.Context, realm string) ([]core.WorkloadIdentity, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+wlCols+` FROM workload_identities WHERE realm=$1 ORDER BY name`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.WorkloadIdentity{}
	for rows.Next() {
		w, err := scanWL(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) SetWorkloadEnabled(ctx context.Context, realm, id string, enabled bool) (core.WorkloadIdentity, error) {
	return scanWL(s.pool.QueryRow(ctx, `UPDATE workload_identities SET enabled=$3 WHERE realm=$1 AND id=$2 RETURNING `+wlCols,
		realm, id, enabled))
}

func (s *Store) DeleteWorkloadIdentity(ctx context.Context, realm, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM workload_identities WHERE realm=$1 AND id=$2`, realm, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("workload identity: %w", idp.ErrNotFound)
	}
	return nil
}

// ---- agents ----

const agCols = `id, realm, name, kind, client_id, owner_user_id, allowed_scopes, allowed_roles, audiences, token_ttl, enabled, created_by, created_at`

func scanAgent(row pgx.Row) (core.Agent, error) {
	var a core.Agent
	err := row.Scan(&a.ID, &a.Realm, &a.Name, &a.Kind, &a.ClientID, &a.OwnerUserID, &a.AllowedScopes, &a.AllowedRoles,
		&a.Audiences, &a.TokenTTL, &a.Enabled, &a.CreatedBy, &a.CreatedAt)
	a.CreatedAt = utc(a.CreatedAt)
	a.AllowedScopes, a.AllowedRoles, a.Audiences = arr(a.AllowedScopes), arr(a.AllowedRoles), arr(a.Audiences)
	return a, mapErr(err)
}

func (s *Store) CreateAgent(ctx context.Context, a core.Agent) (core.Agent, error) {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	return scanAgent(s.pool.QueryRow(ctx, `INSERT INTO agent_identities (`+agCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING `+agCols,
		a.ID, a.Realm, a.Name, a.Kind, a.ClientID, a.OwnerUserID, arr(a.AllowedScopes), arr(a.AllowedRoles),
		arr(a.Audiences), a.TokenTTL, a.Enabled, a.CreatedBy, a.CreatedAt.UTC()))
}

func (s *Store) GetAgent(ctx context.Context, realm, id string) (core.Agent, error) {
	return scanAgent(s.pool.QueryRow(ctx, `SELECT `+agCols+` FROM agent_identities WHERE realm=$1 AND id=$2`, realm, id))
}

func (s *Store) GetAgentByClient(ctx context.Context, realm, clientID string) (core.Agent, error) {
	return scanAgent(s.pool.QueryRow(ctx, `SELECT `+agCols+` FROM agent_identities WHERE realm=$1 AND client_id=$2`, realm, clientID))
}

func (s *Store) ListAgents(ctx context.Context, realm, ownerID string) ([]core.Agent, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+agCols+` FROM agent_identities
		WHERE realm=$1 AND ($2::text = '' OR owner_user_id=$2) ORDER BY name`, realm, ownerID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) SetAgentEnabled(ctx context.Context, realm, id string, enabled bool) (core.Agent, error) {
	return scanAgent(s.pool.QueryRow(ctx, `UPDATE agent_identities SET enabled=$3 WHERE realm=$1 AND id=$2 RETURNING `+agCols,
		realm, id, enabled))
}

func (s *Store) DeleteAgent(ctx context.Context, realm, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM agent_identities WHERE realm=$1 AND id=$2`, realm, id) // credentials cascade
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent: %w", idp.ErrNotFound)
	}
	return nil
}

// ---- credentials ----

const credCols = `id, realm, agent_id, secret_hash, scopes, note, created_by, created_at, expires_at, revoked_at, revoked_by, last_used_at`

func scanCred(row pgx.Row) (core.AgentCredential, error) {
	var c core.AgentCredential
	var rev, used *time.Time
	err := row.Scan(&c.ID, &c.Realm, &c.AgentID, &c.SecretHash, &c.Scopes, &c.Note, &c.CreatedBy, &c.CreatedAt,
		&c.ExpiresAt, &rev, &c.RevokedBy, &used)
	c.CreatedAt, c.ExpiresAt = utc(c.CreatedAt), utc(c.ExpiresAt)
	c.RevokedAt, c.LastUsedAt = fromNull(rev), fromNull(used)
	c.Scopes = arr(c.Scopes)
	return c, mapErr(err)
}

func (s *Store) CreateAgentCredential(ctx context.Context, c core.AgentCredential, maxActive int, now time.Time) (core.AgentCredential, error) {
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	var out core.AgentCredential
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Lock the agent row: concurrent creations for one agent serialize, so
		// the active-count check and the insert are atomic.
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM agent_identities WHERE realm=$1 AND id=$2 FOR UPDATE`, c.Realm, c.AgentID).Scan(&one); err != nil {
			return err
		}
		if maxActive > 0 {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM agent_credentials
				WHERE realm=$1 AND agent_id=$2 AND revoked_at IS NULL AND expires_at > $3`, c.Realm, c.AgentID, now).Scan(&n); err != nil {
				return err
			}
			if n >= maxActive {
				return core.ErrCredentialLimit
			}
		}
		var err error
		out, err = scanCred(tx.QueryRow(ctx, `INSERT INTO agent_credentials (id, realm, agent_id, secret_hash, scopes, note, created_by, created_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+credCols,
			c.ID, c.Realm, c.AgentID, c.SecretHash, arr(c.Scopes), c.Note, c.CreatedBy, c.CreatedAt.UTC(), c.ExpiresAt.UTC()))
		return err
	})
	if errors.Is(err, core.ErrCredentialLimit) {
		return core.AgentCredential{}, err
	}
	return out, mapErr(err)
}

func (s *Store) GetAgentCredentialBySecret(ctx context.Context, realm, agentID, secretHash string) (core.AgentCredential, error) {
	return scanCred(s.pool.QueryRow(ctx, `SELECT `+credCols+` FROM agent_credentials
		WHERE realm=$1 AND agent_id=$2 AND secret_hash=$3`, realm, agentID, secretHash))
}

func (s *Store) ListAgentCredentials(ctx context.Context, realm, agentID string) ([]core.AgentCredential, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+credCols+` FROM agent_credentials
		WHERE realm=$1 AND agent_id=$2 ORDER BY created_at DESC, id`, realm, agentID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.AgentCredential{}
	for rows.Next() {
		c, err := scanCred(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) RevokeAgentCredential(ctx context.Context, realm, agentID, id, by string, now time.Time) (core.AgentCredential, error) {
	c, err := scanCred(s.pool.QueryRow(ctx, `UPDATE agent_credentials SET revoked_at=$5, revoked_by=$6
		WHERE realm=$1 AND agent_id=$2 AND id=$3 AND revoked_at IS NULL AND expires_at > $4
		RETURNING `+credCols, realm, agentID, id, now, now.UTC(), by))
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, idp.ErrNotFound) {
		return core.AgentCredential{}, err
	}
	var one int
	if qerr := s.pool.QueryRow(ctx, `SELECT 1 FROM agent_credentials WHERE realm=$1 AND agent_id=$2 AND id=$3`,
		realm, agentID, id).Scan(&one); qerr == nil {
		return core.AgentCredential{}, fmt.Errorf("credential already ended: %w", idp.ErrConflict)
	}
	return core.AgentCredential{}, err
}

func (s *Store) RevokeAgentCredentials(ctx context.Context, realm, agentID, by string, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_credentials SET revoked_at=$4, revoked_by=$5
		WHERE realm=$1 AND agent_id=$2 AND revoked_at IS NULL AND expires_at > $3`, realm, agentID, now, now.UTC(), by)
	return int(tag.RowsAffected()), mapErr(err)
}

func (s *Store) TouchAgentCredential(ctx context.Context, realm, agentID, id string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE agent_credentials SET last_used_at=$4 WHERE realm=$1 AND agent_id=$2 AND id=$3`,
		realm, agentID, id, now.UTC())
	return mapErr(err)
}

func (s *Store) PurgeAgentCredentials(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM agent_credentials
		WHERE LEAST(COALESCE(revoked_at, expires_at), expires_at) <= $1 AND NOT (revoked_at IS NULL AND expires_at > $2)`,
		now.Add(-core.CredentialRetention), now)
	return int(tag.RowsAffected()), mapErr(err)
}
