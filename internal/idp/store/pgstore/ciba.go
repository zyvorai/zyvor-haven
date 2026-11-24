// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.CIBAStore = (*Store)(nil)

const cibaCols = `auth_req_hash, approval_hash, realm, client_id, user_id, scope, binding, resources, status,
	session_id, auth_time, request_ip, interval_secs, last_poll, created_at, expires_at`

func scanCIBA(row pgx.Row, extra ...any) (core.CIBARequest, error) {
	var c core.CIBARequest
	var auth, poll *time.Time
	dst := append([]any{&c.AuthReqHash, &c.ApprovalHash, &c.Realm, &c.ClientID, &c.UserID, &c.Scope, &c.Binding,
		&c.Resources, &c.Status, &c.SessionID, &auth, &c.RequestIP, &c.Interval, &poll,
		&c.CreatedAt, &c.ExpiresAt}, extra...)
	err := row.Scan(dst...)
	c.AuthTime, c.LastPoll = fromNull(auth), fromNull(poll)
	c.CreatedAt, c.ExpiresAt = utc(c.CreatedAt), utc(c.ExpiresAt)
	c.Resources = nilIfEmpty(c.Resources)
	return c, mapErr(err)
}

func (s *Store) CIBAClientEnabled(ctx context.Context, realm, clientUUID string) (bool, error) {
	var on bool
	err := s.pool.QueryRow(ctx, `SELECT enabled FROM ciba_clients WHERE realm=$1 AND client_uuid=$2`,
		realm, clientUUID).Scan(&on)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, mapErr(err)
	}
	return on, nil
}

func (s *Store) SetCIBAClient(ctx context.Context, realm, clientUUID string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `INSERT INTO ciba_clients (client_uuid, realm, enabled)
		SELECT id, realm, $3 FROM clients WHERE realm=$1 AND id=$2
		ON CONFLICT (client_uuid) DO UPDATE SET enabled=EXCLUDED.enabled`, realm, clientUUID, enabled)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return idp.ErrNotFound
	}
	return nil
}

func (s *Store) PutCIBARequest(ctx context.Context, c core.CIBARequest) error {
	if c.Status == "" {
		c.Status = core.CIBAPending
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO ciba_requests (`+cibaCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		c.AuthReqHash, c.ApprovalHash, c.Realm, c.ClientID, c.UserID, c.Scope, c.Binding, arr(c.Resources),
		c.Status, c.SessionID, nullTime(c.AuthTime), c.RequestIP, c.Interval, nullTime(c.LastPoll),
		c.CreatedAt.UTC(), c.ExpiresAt.UTC())
	return mapErr(err)
}

func (s *Store) GetCIBAByApproval(ctx context.Context, realm, approvalHash string) (core.CIBARequest, error) {
	return scanCIBA(s.pool.QueryRow(ctx,
		`SELECT `+cibaCols+` FROM ciba_requests WHERE realm=$1 AND approval_hash=$2`, realm, approvalHash))
}

func (s *Store) DecideCIBA(ctx context.Context, realm, approvalHash, userID string, now time.Time, d core.CIBADecision) (core.CIBARequest, error) {
	if userID == "" {
		return core.CIBARequest{}, idp.ErrNotFound
	}
	status := core.CIBADenied
	var sid string
	var at *time.Time
	if d.Approve {
		status, sid, at = core.CIBAApproved, d.SessionID, nullTime(d.AuthTime)
	}
	// status='pending' makes the transition a compare-and-set; user_id=$3
	// makes it impossible for anyone but the addressee to decide.
	return scanCIBA(s.pool.QueryRow(ctx, `UPDATE ciba_requests SET status=$5, session_id=$6, auth_time=$7
		WHERE realm=$1 AND approval_hash=$2 AND user_id=$3 AND status='pending' AND expires_at > $4
		RETURNING `+cibaCols, realm, approvalHash, userID, now.UTC(), status, sid, at))
}

func (s *Store) PollCIBA(ctx context.Context, realm, clientID, authReqHash string, now time.Time) (core.CIBARequest, bool, error) {
	var fast bool
	c, err := scanCIBA(s.pool.QueryRow(ctx, `WITH cur AS (
			SELECT auth_req_hash AS h,
			       (last_poll IS NOT NULL AND $4 < last_poll + make_interval(secs => interval_secs)) AS fast
			FROM ciba_requests WHERE realm=$1 AND client_id=$2 AND auth_req_hash=$3 FOR UPDATE)
		UPDATE ciba_requests d SET last_poll=$4,
			interval_secs = CASE WHEN cur.fast THEN LEAST(d.interval_secs + $5, $6) ELSE d.interval_secs END
		FROM cur WHERE d.auth_req_hash = cur.h
		RETURNING d.auth_req_hash, d.approval_hash, d.realm, d.client_id, d.user_id, d.scope, d.binding,
			d.resources, d.status, d.session_id, d.auth_time, d.request_ip, d.interval_secs, d.last_poll,
			d.created_at, d.expires_at, cur.fast`,
		realm, clientID, authReqHash, now.UTC(), core.CIBASlowDownStep, core.CIBAMaxInterval), &fast)
	return c, fast, err
}

func (s *Store) ConsumeCIBA(ctx context.Context, realm, clientID, authReqHash string, now time.Time) (core.CIBARequest, error) {
	return scanCIBA(s.pool.QueryRow(ctx, `DELETE FROM ciba_requests
		WHERE realm=$1 AND client_id=$2 AND auth_req_hash=$3 AND status='approved' AND expires_at > $4
		RETURNING `+cibaCols, realm, clientID, authReqHash, now.UTC()))
}

func (s *Store) PurgeExpiredCIBA(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ciba_requests WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}
