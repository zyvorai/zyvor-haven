// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"slices"
	"sort"

	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.AccountStore = (*Store)(nil)

// ListUserEvents implements core.AccountStore.
func (s *Store) ListUserEvents(_ context.Context, realm, userID string, types []string, limit int) ([]core.Event, error) {
	if limit <= 0 || limit > core.MaxUserEvents {
		limit = core.MaxUserEvents
	}
	out := []core.Event{}
	if userID == "" || len(types) == 0 {
		return out, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Walk backwards so later appends win ties in the stable sort.
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if e.Realm == realm && e.UserID == userID && slices.Contains(types, e.Type) {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// RotateSessionCookie implements core.AccountStore.
func (s *Store) RotateSessionCookie(_ context.Context, realm, userID, sessionID, cookieHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sess[sessionID]
	if !ok || x.Realm != realm || x.UserID != userID {
		return nf("session")
	}
	if cookieHash == "" {
		return dup("empty cookie hash")
	}
	for id, other := range s.sess {
		if id != sessionID && other.CookieHash == cookieHash {
			return dup("session cookie")
		}
	}
	x.CookieHash = cookieHash
	s.sess[sessionID] = x
	return nil
}
