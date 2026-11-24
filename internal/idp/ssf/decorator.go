// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package ssf

import (
	"context"
	"slices"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Wrap returns st with the SSF hooks: it sees every user update and every
// session end, whichever code path performs them (login, admin API, password
// reset, logout), and emits signals for them. Without the hook a new
// "revoke" code path would silently not signal; with it that cannot happen.
// A nil Transmitter returns st unchanged.
func Wrap(st core.Store, t *Transmitter) core.Store {
	if t == nil {
		return st
	}
	return &store{Store: st, t: t}
}

type store struct {
	core.Store
	t *Transmitter
}

// Unwrap lets core.StoreAs find feature stores behind the decorator.
func (s *store) Unwrap() core.Store { return s.Store }

// SSFPolicy marks the transmitter as running (see core.SSFPolicyProvider).
func (s *store) SSFPolicy() core.SSFPolicy { return core.SSFPolicy{AllowPrivate: s.t.AllowPrivate} }

// EmitSignal implements core.SignalEmitter.
func (s *store) EmitSignal(ctx context.Context, sig core.Signal) { s.t.Emit(ctx, sig) }

// UpdateUser emits account-disabled/enabled, credential-change (password) and
// token-claims-change when those fields changed. Failed-login counters and
// lock times are ignored.
func (s *store) UpdateUser(ctx context.Context, u core.User) error {
	old, oerr := s.Store.GetUser(ctx, u.Realm, u.ID)
	if err := s.Store.UpdateUser(ctx, u); err != nil {
		return err
	}
	if oerr == nil {
		s.t.userChanged(ctx, old, u)
	}
	return nil
}

func (t *Transmitter) userChanged(ctx context.Context, old, cur core.User) {
	sig := func(kind string, attrs map[string]any) {
		t.Emit(ctx, core.Signal{Realm: cur.Realm, UserID: cur.ID, Kind: kind, Attrs: attrs})
	}
	if old.Enabled != cur.Enabled {
		if cur.Enabled {
			sig(EvAccountEnabled, nil)
		} else {
			sig(EvAccountDisabled, nil)
		}
	}
	if old.PasswordHash != cur.PasswordHash {
		change := "update"
		switch {
		case old.PasswordHash == "":
			change = "create"
		case cur.PasswordHash == "":
			change = "delete"
		}
		sig(EvCredentialChange, map[string]any{"credential_type": "password", "change_type": change})
	}
	claims := map[string]any{}
	if old.Email != cur.Email {
		claims["email"] = cur.Email
	}
	if old.EmailVerified != cur.EmailVerified {
		claims["email_verified"] = cur.EmailVerified
	}
	if old.Username != cur.Username {
		claims["preferred_username"] = cur.Username
	}
	if old.FirstName != cur.FirstName {
		claims["given_name"] = cur.FirstName
	}
	if old.LastName != cur.LastName {
		claims["family_name"] = cur.LastName
	}
	if !sameSet(old.Roles, cur.Roles) {
		roles := slices.Clone(cur.Roles)
		slices.Sort(roles)
		if roles == nil {
			roles = []string{}
		}
		claims["realm_access"] = map[string]any{"roles": roles}
	}
	if len(claims) > 0 {
		sig(EvTokenClaimsChange, map[string]any{"claims": claims})
	}
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// TakeSession emits session-revoked for the ended session.
func (s *store) TakeSession(ctx context.Context, realm, id string) (core.Session, error) {
	sess, err := s.Store.TakeSession(ctx, realm, id)
	if err != nil {
		return sess, err
	}
	s.t.Emit(ctx, core.Signal{Realm: realm, UserID: sess.UserID, SessionID: sess.ID, Kind: EvSessionRevoked})
	return sess, nil
}

// TakeUserSessions emits session-revoked per session and, if any ended, the
// RISC sessions-revoked event once.
func (s *store) TakeUserSessions(ctx context.Context, realm, userID string) ([]core.Session, error) {
	all, err := s.Store.TakeUserSessions(ctx, realm, userID)
	if err != nil {
		return all, err
	}
	for _, sess := range all {
		s.t.Emit(ctx, core.Signal{Realm: realm, UserID: userID, SessionID: sess.ID, Kind: EvSessionRevoked})
	}
	if len(all) > 0 {
		s.t.Emit(ctx, core.Signal{Realm: realm, UserID: userID, Kind: EvSessionsRevoked})
	}
	return all, nil
}
