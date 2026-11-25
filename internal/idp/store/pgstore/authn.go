// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.AuthnStore = (*Store)(nil)

// GetACRPolicy implements core.AuthnStore.
func (s *Store) GetACRPolicy(ctx context.Context, realm string) (core.ACRPolicy, error) {
	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT policy FROM realm_acr_policy WHERE realm=$1`, realm).Scan(&raw); err != nil {
		return core.ACRPolicy{}, mapErr(err)
	}
	var p core.ACRPolicy
	if err := json.Unmarshal(raw, &p); err != nil {
		return core.ACRPolicy{}, fmt.Errorf("pgstore: stored acr policy: %w", err)
	}
	return p, nil
}

// PutACRPolicy implements core.AuthnStore.
func (s *Store) PutACRPolicy(ctx context.Context, realm string, p core.ACRPolicy) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO realm_acr_policy (realm, policy) VALUES ($1,$2)
		ON CONFLICT (realm) DO UPDATE SET policy=EXCLUDED.policy`, realm, raw)
	return mapErr(err)
}

// DeleteACRPolicy implements core.AuthnStore.
func (s *Store) DeleteACRPolicy(ctx context.Context, realm string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM realm_acr_policy WHERE realm=$1`, realm)
	return mapErr(err)
}

// PutSessionAuthn implements core.AuthnStore. The session must belong to the
// realm: the insert selects from sessions, so no row means ErrNotFound.
func (s *Store) PutSessionAuthn(ctx context.Context, a core.SessionAuthn) error {
	amr := a.AMR
	if amr == nil {
		amr = []string{}
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO session_authn (session_id, realm, amr)
		SELECT id, realm, $3 FROM sessions WHERE id=$1 AND realm=$2`, a.SessionID, a.Realm, amr)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return idp.ErrNotFound
	}
	return nil
}

// GetSessionAuthn implements core.AuthnStore.
func (s *Store) GetSessionAuthn(ctx context.Context, realm, sessionID string) (core.SessionAuthn, error) {
	a := core.SessionAuthn{Realm: realm, SessionID: sessionID}
	err := s.pool.QueryRow(ctx, `SELECT amr FROM session_authn WHERE session_id=$1 AND realm=$2`, sessionID, realm).Scan(&a.AMR)
	if err != nil {
		return core.SessionAuthn{}, mapErr(err)
	}
	a.AMR = nilIfEmpty(a.AMR)
	return a, nil
}
