// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.AccountStore = (*Store)(nil)

// ListUserEvents implements core.AccountStore (index: migration 0024).
func (s *Store) ListUserEvents(ctx context.Context, realm, userID string, types []string, limit int) ([]core.Event, error) {
	if limit <= 0 || limit > core.MaxUserEvents {
		limit = core.MaxUserEvents
	}
	out := []core.Event{}
	if userID == "" || len(types) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT time, realm, type, user_id, client_id, ip, detail FROM events
		WHERE realm=$1 AND user_id=$2 AND type = ANY($3::text[]) ORDER BY time DESC, seq DESC LIMIT $4`,
		realm, userID, types, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var e core.Event
		if err := rows.Scan(&e.Time, &e.Realm, &e.Type, &e.UserID, &e.ClientID, &e.IP, &e.Detail); err != nil {
			return nil, mapErr(err)
		}
		e.Time = utc(e.Time)
		out = append(out, e)
	}
	return out, mapErr(rows.Err())
}

// RotateSessionCookie implements core.AccountStore: one UPDATE keyed by realm,
// session id AND owner, so it can never touch another user's session.
func (s *Store) RotateSessionCookie(ctx context.Context, realm, userID, sessionID, cookieHash string) error {
	if cookieHash == "" {
		var one int
		if err := s.pool.QueryRow(ctx, `SELECT 1 FROM sessions WHERE realm=$1 AND id=$2 AND user_id=$3`,
			realm, sessionID, userID).Scan(&one); err != nil {
			return mapErr(err)
		}
		return idp.ErrConflict
	}
	return s.exec1(ctx, `UPDATE sessions SET cookie_hash=$4 WHERE realm=$1 AND id=$2 AND user_id=$3`,
		realm, sessionID, userID, cookieHash)
}
