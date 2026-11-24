// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.StepUpStore = (*Store)(nil)

// GetStepUpPolicy implements core.StepUpStore.
func (s *Store) GetStepUpPolicy(ctx context.Context, realm string) (core.StepUpPolicy, error) {
	var p core.StepUpPolicy
	var idle, maxAge int64
	err := s.pool.QueryRow(ctx, `SELECT allow_fallback, enabled, enforce, on_new_device, on_ip_change,
		idle_after_seconds, on_max_age, sensitive_scopes, sensitive_auth_max_age_seconds
		FROM realm_stepup_policy WHERE realm=$1`, realm).
		Scan(&p.AllowFallback, &p.Enabled, &p.Enforce, &p.OnNewDevice, &p.OnIPChange, &idle, &p.OnMaxAge, &p.SensitiveScopes, &maxAge)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.StepUpPolicy{}, nil
	}
	if err != nil {
		return core.StepUpPolicy{}, mapErr(err)
	}
	p.IdleAfter = time.Duration(idle) * time.Second
	p.SensitiveAuthMaxAge = time.Duration(maxAge) * time.Second
	if len(p.SensitiveScopes) == 0 {
		p.SensitiveScopes = nil
	}
	return p, nil
}

// PutStepUpPolicy implements core.StepUpStore.
func (s *Store) PutStepUpPolicy(ctx context.Context, realm string, p core.StepUpPolicy) error {
	scopes := p.SensitiveScopes
	if scopes == nil {
		scopes = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO realm_stepup_policy (realm, allow_fallback, enabled, enforce, on_new_device,
		on_ip_change, idle_after_seconds, on_max_age, sensitive_scopes, sensitive_auth_max_age_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (realm) DO UPDATE SET allow_fallback=EXCLUDED.allow_fallback, enabled=EXCLUDED.enabled,
		enforce=EXCLUDED.enforce, on_new_device=EXCLUDED.on_new_device, on_ip_change=EXCLUDED.on_ip_change,
		idle_after_seconds=EXCLUDED.idle_after_seconds, on_max_age=EXCLUDED.on_max_age,
		sensitive_scopes=EXCLUDED.sensitive_scopes, sensitive_auth_max_age_seconds=EXCLUDED.sensitive_auth_max_age_seconds`,
		realm, p.AllowFallback, p.Enabled, p.Enforce, p.OnNewDevice, p.OnIPChange, int64(p.IdleAfter/time.Second),
		p.OnMaxAge, scopes, int64(p.SensitiveAuthMaxAge/time.Second))
	return mapErr(err)
}

const knownDeviceCols = `realm, user_id, device_hash, ip_hash, first_seen, last_seen`

func scanKnownDevice(row pgx.Row) (core.KnownDevice, error) {
	var d core.KnownDevice
	if err := row.Scan(&d.Realm, &d.UserID, &d.Hash, &d.IPHash, &d.FirstSeen, &d.LastSeen); err != nil {
		return core.KnownDevice{}, mapErr(err)
	}
	d.FirstSeen, d.LastSeen = d.FirstSeen.UTC(), d.LastSeen.UTC()
	return d, nil
}

// GetDevice implements core.StepUpStore.
func (s *Store) GetDevice(ctx context.Context, realm, userID, hash string) (core.KnownDevice, error) {
	return scanKnownDevice(s.pool.QueryRow(ctx, `SELECT `+knownDeviceCols+` FROM known_devices
		WHERE realm=$1 AND user_id=$2 AND device_hash=$3`, realm, userID, hash))
}

// LatestDevice implements core.StepUpStore.
func (s *Store) LatestDevice(ctx context.Context, realm, userID string) (core.KnownDevice, error) {
	return scanKnownDevice(s.pool.QueryRow(ctx, `SELECT `+knownDeviceCols+` FROM known_devices
		WHERE realm=$1 AND user_id=$2 ORDER BY last_seen DESC, device_hash LIMIT 1`, realm, userID))
}

// TouchDevice upserts the device and trims the user's oldest ones, in one
// transaction so a burst of logins cannot leave more than max rows behind.
func (s *Store) TouchDevice(ctx context.Context, d core.KnownDevice, max int) error {
	if d.FirstSeen.IsZero() {
		d.FirstSeen = d.LastSeen
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Serialise concurrent touches of one user so the trim is exact.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "known_devices|"+d.Realm+"|"+d.UserID); err != nil {
			return mapErr(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO known_devices (`+knownDeviceCols+`) VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (realm, user_id, device_hash) DO UPDATE SET ip_hash=EXCLUDED.ip_hash, last_seen=EXCLUDED.last_seen`,
			d.Realm, d.UserID, d.Hash, d.IPHash, d.FirstSeen.UTC(), d.LastSeen.UTC()); err != nil {
			return mapErr(err)
		}
		if max > 0 {
			_, err := tx.Exec(ctx, `DELETE FROM known_devices WHERE realm=$1 AND user_id=$2 AND device_hash IN (
				SELECT device_hash FROM known_devices WHERE realm=$1 AND user_id=$2
				ORDER BY last_seen DESC, device_hash OFFSET $3)`, d.Realm, d.UserID, max)
			return mapErr(err)
		}
		return nil
	})
}

// ListDevices implements core.StepUpStore.
func (s *Store) ListDevices(ctx context.Context, realm, userID string) ([]core.KnownDevice, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+knownDeviceCols+` FROM known_devices WHERE realm=$1 AND user_id=$2
		ORDER BY last_seen DESC, device_hash`, realm, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []core.KnownDevice
	for rows.Next() {
		d, err := scanKnownDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, mapErr(rows.Err())
}

// DeleteDevice implements core.StepUpStore.
func (s *Store) DeleteDevice(ctx context.Context, realm, userID, hash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM known_devices WHERE realm=$1 AND user_id=$2 AND device_hash=$3`, realm, userID, hash)
	return mapErr(err)
}

// DeleteUserDevices implements core.StepUpStore.
func (s *Store) DeleteUserDevices(ctx context.Context, realm, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM known_devices WHERE realm=$1 AND user_id=$2`, realm, userID)
	return mapErr(err)
}
