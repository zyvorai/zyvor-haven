// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.ConsentStore = (*Store)(nil)

func (s *Store) GetConsentPolicy(ctx context.Context, realm string) (core.ConsentPolicy, error) {
	var p core.ConsentPolicy
	err := s.pool.QueryRow(ctx, `SELECT realm, cimd_enabled, cimd_hosts, require_all, skip_clients, remember_cimd, grant_ttl_seconds
		FROM consent_policies WHERE realm=$1`, realm).
		Scan(&p.Realm, &p.CIMDEnabled, &p.CIMDHosts, &p.RequireAll, &p.SkipClients, &p.RememberCIMD, &p.GrantTTLSeconds)
	p.CIMDHosts, p.SkipClients = nilIfEmpty(p.CIMDHosts), nilIfEmpty(p.SkipClients)
	return p, mapErr(err)
}

func (s *Store) PutConsentPolicy(ctx context.Context, p core.ConsentPolicy) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO consent_policies (realm, cimd_enabled, cimd_hosts, require_all, skip_clients, remember_cimd, grant_ttl_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (realm) DO UPDATE SET cimd_enabled=$2, cimd_hosts=$3, require_all=$4, skip_clients=$5, remember_cimd=$6, grant_ttl_seconds=$7`,
		p.Realm, p.CIMDEnabled, arr(p.CIMDHosts), p.RequireAll, arr(p.SkipClients), p.RememberCIMD, p.GrantTTLSeconds)
	return mapErr(err)
}

const ccCols = `realm, client_id, source, name, client_uri, redirect_uris, fingerprint, fetched_at, expires_at`

func scanCC(row pgx.Row) (core.ConsentClient, error) {
	var c core.ConsentClient
	err := row.Scan(&c.Realm, &c.ClientID, &c.Source, &c.Name, &c.ClientURI, &c.RedirectURIs, &c.Fingerprint, &c.FetchedAt, &c.ExpiresAt)
	c.RedirectURIs = nilIfEmpty(c.RedirectURIs)
	c.FetchedAt, c.ExpiresAt = utc(c.FetchedAt), utc(c.ExpiresAt)
	return c, mapErr(err)
}

func (s *Store) PutConsentClient(ctx context.Context, c core.ConsentClient) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO consent_clients (`+ccCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (realm, client_id) DO UPDATE SET source=$3, name=$4, client_uri=$5, redirect_uris=$6,
		fingerprint=$7, fetched_at=$8, expires_at=$9`,
		c.Realm, c.ClientID, c.Source, c.Name, c.ClientURI, arr(c.RedirectURIs), c.Fingerprint, c.FetchedAt, c.ExpiresAt)
	return mapErr(err)
}

func (s *Store) GetConsentClient(ctx context.Context, realm, clientID string) (core.ConsentClient, error) {
	return scanCC(s.pool.QueryRow(ctx, `SELECT `+ccCols+` FROM consent_clients WHERE realm=$1 AND client_id=$2`, realm, clientID))
}

func (s *Store) ListConsentClients(ctx context.Context, realm string) ([]core.ConsentClient, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ccCols+` FROM consent_clients WHERE realm=$1 ORDER BY client_id`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.ConsentClient{}
	for rows.Next() {
		c, err := scanCC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, mapErr(rows.Err())
}

const cgCols = `id, realm, user_id, client_id, client_name, scopes, resources, fingerprint, created_at, updated_at, expires_at, revoked_at, revoked_by`

func scanCG(row pgx.Row) (core.ConsentGrant, error) {
	var g core.ConsentGrant
	var rev *time.Time
	err := row.Scan(&g.ID, &g.Realm, &g.UserID, &g.ClientID, &g.ClientName, &g.Scopes, &g.Resources, &g.Fingerprint,
		&g.CreatedAt, &g.UpdatedAt, &g.ExpiresAt, &rev, &g.RevokedBy)
	g.Scopes, g.Resources = nilIfEmpty(g.Scopes), nilIfEmpty(g.Resources)
	g.CreatedAt, g.UpdatedAt, g.ExpiresAt = utc(g.CreatedAt), utc(g.UpdatedAt), utc(g.ExpiresAt)
	if rev != nil {
		g.RevokedAt = rev.UTC()
	}
	return g, mapErr(err)
}

// PutConsentGrant is one upsert against the partial unique index, so two
// concurrent consents of one user for one client cannot create two grants.
func (s *Store) PutConsentGrant(ctx context.Context, g core.ConsentGrant, now time.Time) (core.ConsentGrant, error) {
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = now
	}
	return scanCG(s.pool.QueryRow(ctx, `INSERT INTO consent_grants (id, realm, user_id, client_id, client_name, scopes, resources,
		fingerprint, created_at, updated_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (realm, user_id, client_id) WHERE revoked_at IS NULL DO UPDATE SET
		client_name=EXCLUDED.client_name, scopes=EXCLUDED.scopes, resources=EXCLUDED.resources,
		fingerprint=EXCLUDED.fingerprint, updated_at=EXCLUDED.updated_at, expires_at=EXCLUDED.expires_at
		RETURNING `+cgCols, g.ID, g.Realm, g.UserID, g.ClientID, g.ClientName, arr(g.Scopes), arr(g.Resources),
		g.Fingerprint, g.CreatedAt, now, g.ExpiresAt))
}

func (s *Store) GetActiveConsentGrant(ctx context.Context, realm, userID, clientID string, now time.Time) (core.ConsentGrant, error) {
	return scanCG(s.pool.QueryRow(ctx, `SELECT `+cgCols+` FROM consent_grants
		WHERE realm=$1 AND user_id=$2 AND client_id=$3 AND revoked_at IS NULL AND expires_at > $4`, realm, userID, clientID, now))
}

func (s *Store) GetConsentGrant(ctx context.Context, realm, id string) (core.ConsentGrant, error) {
	return scanCG(s.pool.QueryRow(ctx, `SELECT `+cgCols+` FROM consent_grants WHERE realm=$1 AND id=$2`, realm, id))
}

func (s *Store) ListConsentGrants(ctx context.Context, realm, userID, clientID string, includeEnded bool, now time.Time, limit int) ([]core.ConsentGrant, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT `+cgCols+` FROM consent_grants
		WHERE realm=$1 AND ($2='' OR user_id=$2) AND ($3='' OR client_id=$3)
		AND ($4 OR (revoked_at IS NULL AND expires_at > $5))
		ORDER BY created_at DESC, id LIMIT $6`, realm, userID, clientID, includeEnded, now, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.ConsentGrant{}
	for rows.Next() {
		g, err := scanCG(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) RevokeConsentGrant(ctx context.Context, realm, id, by string, now time.Time) (core.ConsentGrant, error) {
	g, err := scanCG(s.pool.QueryRow(ctx, `UPDATE consent_grants SET revoked_at=$3, revoked_by=$4
		WHERE realm=$1 AND id=$2 AND revoked_at IS NULL RETURNING `+cgCols, realm, id, now, by))
	if errors.Is(err, idp.ErrNotFound) {
		if _, gerr := s.GetConsentGrant(ctx, realm, id); gerr == nil {
			return core.ConsentGrant{}, idp.ErrConflict
		}
	}
	return g, err
}

func (s *Store) RevokeClientConsentGrants(ctx context.Context, realm, clientID, by string, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE consent_grants SET revoked_at=$3, revoked_by=$4
		WHERE realm=$1 AND client_id=$2 AND revoked_at IS NULL`, realm, clientID, now, by)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) RevokeClientRefreshTokens(ctx context.Context, realm, clientID, userID string) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked=true
		WHERE realm=$1 AND client_id=$2 AND ($3='' OR user_id=$3) AND NOT revoked`, realm, clientID, userID)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) PutConsentBlock(ctx context.Context, b core.ConsentBlock) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO consent_blocks (realm, client_id, reason, blocked_by, blocked_at) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (realm, client_id) DO UPDATE SET reason=$3, blocked_by=$4, blocked_at=$5`, b.Realm, b.ClientID, b.Reason, b.By, b.At)
	return mapErr(err)
}

func scanCB(row pgx.Row) (core.ConsentBlock, error) {
	var b core.ConsentBlock
	err := row.Scan(&b.Realm, &b.ClientID, &b.Reason, &b.By, &b.At)
	b.At = utc(b.At)
	return b, mapErr(err)
}

func (s *Store) GetConsentBlock(ctx context.Context, realm, clientID string) (core.ConsentBlock, error) {
	return scanCB(s.pool.QueryRow(ctx, `SELECT realm, client_id, reason, blocked_by, blocked_at FROM consent_blocks WHERE realm=$1 AND client_id=$2`, realm, clientID))
}

func (s *Store) DeleteConsentBlock(ctx context.Context, realm, clientID string) error {
	return s.exec1(ctx, `DELETE FROM consent_blocks WHERE realm=$1 AND client_id=$2`, realm, clientID)
}

func (s *Store) ListConsentBlocks(ctx context.Context, realm string) ([]core.ConsentBlock, error) {
	rows, err := s.pool.Query(ctx, `SELECT realm, client_id, reason, blocked_by, blocked_at FROM consent_blocks WHERE realm=$1 ORDER BY client_id`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.ConsentBlock{}
	for rows.Next() {
		b, err := scanCB(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, mapErr(rows.Err())
}

const crCols = `realm, seq, created_at, type, user_id, client_id, client_name, scopes, resources, actor, detail, prev_hash, hash`

func scanCR(row pgx.Row) (core.ConsentReceipt, error) {
	var r core.ConsentReceipt
	err := row.Scan(&r.Realm, &r.Seq, &r.Time, &r.Type, &r.UserID, &r.ClientID, &r.ClientName, &r.Scopes, &r.Resources,
		&r.Actor, &r.Detail, &r.PrevHash, &r.Hash)
	r.Scopes, r.Resources = nilIfEmpty(r.Scopes), nilIfEmpty(r.Resources)
	r.Time = utc(r.Time)
	return r, mapErr(err)
}

// AppendConsentReceipt serialises appends of one realm with a transaction-scoped
// advisory lock, so concurrent appends (also across replicas) get consecutive
// sequence numbers and a correct previous hash.
func (s *Store) AppendConsentReceipt(ctx context.Context, r core.ConsentReceipt) (core.ConsentReceipt, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return core.ConsentReceipt{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('consent_receipts|' || $1, 0))`, r.Realm); err != nil {
		return core.ConsentReceipt{}, mapErr(err)
	}
	var seq int64
	var prev string
	err = tx.QueryRow(ctx, `SELECT seq, hash FROM consent_receipts WHERE realm=$1 ORDER BY seq DESC LIMIT 1`, r.Realm).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return core.ConsentReceipt{}, mapErr(err)
	}
	r.Seq, r.PrevHash = seq+1, prev
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	r.Time = r.Time.UTC().Truncate(time.Microsecond)
	r.Hash = core.ConsentReceiptHash(r)
	_, err = tx.Exec(ctx, `INSERT INTO consent_receipts (`+crCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		r.Realm, r.Seq, r.Time, r.Type, r.UserID, r.ClientID, r.ClientName, arr(r.Scopes), arr(r.Resources), r.Actor, r.Detail, r.PrevHash, r.Hash)
	if err != nil {
		return core.ConsentReceipt{}, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return core.ConsentReceipt{}, mapErr(err)
	}
	return r, nil
}

func (s *Store) ListConsentReceipts(ctx context.Context, realm, userID string, afterSeq int64, limit int) ([]core.ConsentReceipt, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT `+crCols+` FROM consent_receipts
		WHERE realm=$1 AND seq > $2 AND ($3='' OR user_id=$3) ORDER BY seq LIMIT $4`, realm, afterSeq, userID, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.ConsentReceipt{}
	for rows.Next() {
		r, err := scanCR(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

func (s *Store) HeadConsentReceipt(ctx context.Context, realm string) (core.ConsentReceipt, error) {
	return scanCR(s.pool.QueryRow(ctx, `SELECT `+crCols+` FROM consent_receipts WHERE realm=$1 ORDER BY seq DESC LIMIT 1`, realm))
}
