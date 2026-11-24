// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package sessions ends SSO sessions. The OIDC logout endpoint, the Admin API
// and password changes all go through it, so "ending a session" always means
// the same thing: the session row is removed (once), the refresh tokens issued
// in it are revoked (except offline ones), and the clients that took part are
// told (back-channel logout).
package sessions

import (
	"context"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Notifier tells the clients of an ended session that it is over. It must not
// block the caller for long and must never fail the logout: implementations
// do their own timeouts, retries and logging. Nil means "notify nobody".
type Notifier interface {
	Notify(ctx context.Context, realm string, s core.Session)
}

// Service ends sessions.
type Service struct {
	Store    core.Store
	Notifier Notifier
}

// End ends one session. It returns idp.ErrNotFound (via the store) when the
// session is already gone, which makes a second logout a no-op for callers.
func (s *Service) End(ctx context.Context, realm, id string) (core.Session, error) {
	sess, err := s.Store.TakeSession(ctx, realm, id)
	if err != nil {
		return core.Session{}, err
	}
	s.after(ctx, realm, sess)
	return sess, nil
}

// EndUser ends every session of a user and returns how many there were.
func (s *Service) EndUser(ctx context.Context, realm, userID string) (int, error) {
	all, err := s.Store.TakeUserSessions(ctx, realm, userID)
	if err != nil {
		return 0, err
	}
	for _, sess := range all {
		s.after(ctx, realm, sess)
	}
	return len(all), nil
}

func (s *Service) after(ctx context.Context, realm string, sess core.Session) {
	// Revocation failures must not stop the notification, and vice versa:
	// the session row is already gone, so this is best effort by design.
	_, _ = s.Store.RevokeSessionRefreshTokens(ctx, realm, sess.ID)
	if s.Notifier != nil {
		s.Notifier.Notify(ctx, realm, sess)
	}
}
