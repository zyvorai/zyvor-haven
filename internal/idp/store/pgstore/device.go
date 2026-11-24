// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.DeviceStore = (*Store)(nil)

const deviceCols = `device_code_hash, user_code_hash, realm, client_id, scope, status, user_id, session_id,
	auth_time, request_ip, request_ua, interval_secs, last_poll, created_at, expires_at`

func scanDevice(row pgx.Row, extra ...any) (core.DeviceCode, error) {
	var d core.DeviceCode
	var auth, poll *time.Time
	dst := append([]any{&d.DeviceCodeHash, &d.UserCodeHash, &d.Realm, &d.ClientID, &d.Scope, &d.Status,
		&d.UserID, &d.SessionID, &auth, &d.RequestIP, &d.RequestUA, &d.Interval, &poll,
		&d.CreatedAt, &d.ExpiresAt}, extra...)
	err := row.Scan(dst...)
	d.AuthTime, d.LastPoll = fromNull(auth), fromNull(poll)
	d.CreatedAt, d.ExpiresAt = utc(d.CreatedAt), utc(d.ExpiresAt)
	return d, mapErr(err)
}

func (s *Store) PutDeviceCode(ctx context.Context, d core.DeviceCode) error {
	if d.Status == "" {
		d.Status = core.DevicePending
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO device_codes (`+deviceCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		d.DeviceCodeHash, d.UserCodeHash, d.Realm, d.ClientID, d.Scope, d.Status, d.UserID, d.SessionID,
		nullTime(d.AuthTime), d.RequestIP, d.RequestUA, d.Interval, nullTime(d.LastPoll),
		d.CreatedAt.UTC(), d.ExpiresAt.UTC())
	return mapErr(err)
}

func (s *Store) GetDeviceCodeByUserCode(ctx context.Context, realm, userCodeHash string) (core.DeviceCode, error) {
	return scanDevice(s.pool.QueryRow(ctx,
		`SELECT `+deviceCols+` FROM device_codes WHERE realm=$1 AND user_code_hash=$2`, realm, userCodeHash))
}

func (s *Store) DecideDeviceCode(ctx context.Context, realm, userCodeHash string, now time.Time, d core.DeviceDecision) (core.DeviceCode, error) {
	status := core.DeviceDenied
	var uid, sid string
	var at *time.Time
	if d.Approve {
		status, uid, sid, at = core.DeviceApproved, d.UserID, d.SessionID, nullTime(d.AuthTime)
	}
	// The status='pending' predicate makes the transition a compare-and-set:
	// concurrent decisions serialize on the row and only the first matches.
	return scanDevice(s.pool.QueryRow(ctx, `UPDATE device_codes SET status=$4, user_id=$5, session_id=$6, auth_time=$7
		WHERE realm=$1 AND user_code_hash=$2 AND status='pending' AND expires_at > $3
		RETURNING `+deviceCols, realm, userCodeHash, now.UTC(), status, uid, sid, at))
}

func (s *Store) PollDeviceCode(ctx context.Context, realm, clientID, deviceCodeHash string, now time.Time) (core.DeviceCode, bool, error) {
	var fast bool
	d, err := scanDevice(s.pool.QueryRow(ctx, `WITH cur AS (
			SELECT device_code_hash AS h,
			       (last_poll IS NOT NULL AND $4 < last_poll + make_interval(secs => interval_secs)) AS fast
			FROM device_codes WHERE realm=$1 AND client_id=$2 AND device_code_hash=$3 FOR UPDATE)
		UPDATE device_codes d SET last_poll=$4,
			interval_secs = CASE WHEN cur.fast THEN LEAST(d.interval_secs + $5, $6) ELSE d.interval_secs END
		FROM cur WHERE d.device_code_hash = cur.h
		RETURNING d.device_code_hash, d.user_code_hash, d.realm, d.client_id, d.scope, d.status, d.user_id,
			d.session_id, d.auth_time, d.request_ip, d.request_ua, d.interval_secs, d.last_poll,
			d.created_at, d.expires_at, cur.fast`,
		realm, clientID, deviceCodeHash, now.UTC(), core.DeviceSlowDownStep, core.DeviceMaxInterval), &fast)
	return d, fast, err
}

func (s *Store) ConsumeDeviceCode(ctx context.Context, realm, clientID, deviceCodeHash string, now time.Time) (core.DeviceCode, error) {
	return scanDevice(s.pool.QueryRow(ctx, `DELETE FROM device_codes
		WHERE realm=$1 AND client_id=$2 AND device_code_hash=$3 AND status='approved' AND expires_at > $4
		RETURNING `+deviceCols, realm, clientID, deviceCodeHash, now.UTC()))
}

func (s *Store) PurgeExpiredDeviceCodes(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM device_codes WHERE expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}
