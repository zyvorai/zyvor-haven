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

// Session controls, passkey-only and front-channel logout (migration 0025).

var (
	_ core.SessionPolicyStore = (*Store)(nil)
	_ core.PasskeyOnlyStore   = (*Store)(nil)
	_ core.FrontchannelStore  = (*Store)(nil)
)

// GetSessionPolicy implements core.SessionPolicyStore.
func (s *Store) GetSessionPolicy(ctx context.Context, realm string) (core.SessionPolicy, error) {
	var p core.SessionPolicy
	var idle, absolute int64
	err := s.pool.QueryRow(ctx, `SELECT max_sessions, on_limit, remember_me, remember_idle_seconds, remember_max_seconds
		FROM session_policies WHERE realm=$1`, realm).Scan(&p.MaxSessions, &p.OnLimit, &p.RememberMe, &idle, &absolute)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.SessionPolicy{}, nil
	}
	if err != nil {
		return core.SessionPolicy{}, mapErr(err)
	}
	p.RememberIdle, p.RememberMax = time.Duration(idle)*time.Second, time.Duration(absolute)*time.Second
	return p, nil
}

// PutSessionPolicy implements core.SessionPolicyStore.
func (s *Store) PutSessionPolicy(ctx context.Context, realm string, p core.SessionPolicy) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO session_policies
		(realm, max_sessions, on_limit, remember_me, remember_idle_seconds, remember_max_seconds) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (realm) DO UPDATE SET max_sessions=EXCLUDED.max_sessions, on_limit=EXCLUDED.on_limit,
		remember_me=EXCLUDED.remember_me, remember_idle_seconds=EXCLUDED.remember_idle_seconds,
		remember_max_seconds=EXCLUDED.remember_max_seconds`,
		realm, p.MaxSessions, p.OnLimit, p.RememberMe, int64(p.RememberIdle/time.Second), int64(p.RememberMax/time.Second))
	return mapErr(err)
}

// CreateLimitedSession implements core.SessionPolicyStore. A transaction-level
// advisory lock on (realm, user) serialises the logins of one user across all
// replicas, so the count it reads cannot change before it inserts.
func (s *Store) CreateLimitedSession(ctx context.Context, x core.Session, o core.NewSessionOptions) ([]core.Session, error) {
	if x.CreatedAt.IsZero() {
		x.CreatedAt = time.Now().UTC()
	}
	var evicted []core.Session
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		evicted = nil
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
			"haven-session-limit|"+x.Realm, x.UserID); err != nil {
			return err
		}
		// Refuse a duplicate before evicting: otherwise the session holding
		// that id or cookie could be evicted and silently replaced.
		var dup bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sessions WHERE id=$1 OR cookie_hash=$2)`,
			x.ID, x.CookieHash).Scan(&dup); err != nil {
			return err
		}
		if dup {
			return idp.ErrConflict
		}
		if o.MaxLive > 0 {
			rows, err := tx.Query(ctx, `SELECT id FROM sessions WHERE realm=$1 AND user_id=$2 AND id<>$3
				AND expires_at > $4 AND idle_expires > $4 ORDER BY created_at, id`,
				x.Realm, x.UserID, o.Replaces, utc(o.Now))
			if err != nil {
				return err
			}
			live, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			if over := len(live) + 1 - o.MaxLive; over > 0 {
				if o.DenyNew {
					return core.ErrSessionLimit
				}
				for _, id := range live[:min(over, len(live))] {
					old, err := scanSession(tx.QueryRow(ctx,
						`DELETE FROM sessions WHERE realm=$1 AND id=$2 RETURNING `+sessionCols, x.Realm, id))
					if errors.Is(err, idp.ErrNotFound) {
						continue // ended by someone else meanwhile
					}
					if err != nil {
						return err
					}
					evicted = append(evicted, old)
				}
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO sessions (`+sessionCols+`, remember_idle_seconds)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			x.ID, x.CookieHash, x.Realm, x.UserID, x.AuthTime, x.LastSeen, x.IdleExpires, x.ExpiresAt,
			x.IP, x.UserAgent, arr(x.Clients), x.CreatedAt, int64(o.RememberIdle/time.Second))
		return err
	})
	if errors.Is(err, core.ErrSessionLimit) {
		return nil, core.ErrSessionLimit
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return evicted, nil
}

// SessionRememberIdle implements core.SessionPolicyStore.
func (s *Store) SessionRememberIdle(ctx context.Context, realm, id string) (time.Duration, error) {
	var sec int64
	err := s.pool.QueryRow(ctx, `SELECT remember_idle_seconds FROM sessions WHERE realm=$1 AND id=$2`, realm, id).Scan(&sec)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, mapErr(err)
	}
	return time.Duration(sec) * time.Second, nil
}

// PasskeyOnly implements core.PasskeyOnlyStore.
func (s *Store) PasskeyOnly(ctx context.Context, realm string) (bool, error) {
	var v bool
	err := s.pool.QueryRow(ctx, `SELECT passkey_only FROM passkey_signin_policies WHERE realm=$1`, realm).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return v, mapErr(err)
}

// SetPasskeyOnly implements core.PasskeyOnlyStore.
func (s *Store) SetPasskeyOnly(ctx context.Context, realm string, v bool) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO passkey_signin_policies (realm, passkey_only) VALUES ($1,$2)
		ON CONFLICT (realm) DO UPDATE SET passkey_only=EXCLUDED.passkey_only`, realm, v)
	return mapErr(err)
}

// MarkPasswordlessPasskey implements core.PasskeyOnlyStore.
func (s *Store) MarkPasswordlessPasskey(ctx context.Context, realm, credentialID string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO passkey_passwordless (realm, credential_id, first_used_at) VALUES ($1,$2,$3)
		ON CONFLICT (realm, credential_id) DO NOTHING`, realm, credentialID, utc(at))
	return mapErr(err) // an unknown credential violates the foreign key: ErrNotFound
}

// PasswordlessPasskeys implements core.PasskeyOnlyStore.
func (s *Store) PasswordlessPasskeys(ctx context.Context, realm, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT w.credential_id FROM passkey_passwordless w
		JOIN passkeys p ON p.realm=w.realm AND p.credential_id=w.credential_id
		WHERE p.realm=$1 AND p.user_id=$2 ORDER BY w.credential_id COLLATE "C"`, realm, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if len(out) == 0 {
		out = nil
	}
	return out, mapErr(err)
}

// FrontchannelLogoutURI implements core.FrontchannelStore.
func (s *Store) FrontchannelLogoutURI(ctx context.Context, realm, clientUUID string) (string, error) {
	var uri string
	err := s.pool.QueryRow(ctx, `SELECT f.uri FROM client_frontchannel_logout f JOIN clients c ON c.id=f.client_uuid
		WHERE c.realm=$1 AND c.id=$2`, realm, clientUUID).Scan(&uri)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return uri, mapErr(err)
}

// SetFrontchannelLogoutURI implements core.FrontchannelStore.
func (s *Store) SetFrontchannelLogoutURI(ctx context.Context, realm, clientUUID, uri string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM clients WHERE realm=$1 AND id=$2 FOR SHARE`, realm, clientUUID).Scan(&one); err != nil {
			return mapErr(err)
		}
		if uri == "" {
			_, err := tx.Exec(ctx, `DELETE FROM client_frontchannel_logout WHERE client_uuid=$1`, clientUUID)
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO client_frontchannel_logout (client_uuid, uri) VALUES ($1,$2)
			ON CONFLICT (client_uuid) DO UPDATE SET uri=EXCLUDED.uri`, clientUUID, uri)
		return mapErr(err)
	})
}
