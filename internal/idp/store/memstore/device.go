// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"context"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// deviceState holds the device-flow rows; its zero value is ready to use. It
// is guarded by Store.mu. (Deleting a realm does not cascade to these rows in
// the in-memory store; they expire on their own and are realm-scoped.)
type deviceState struct {
	rows map[string]core.DeviceCode // key: device code hash
}

var _ core.DeviceStore = (*Store)(nil)

func (s *Store) PutDeviceCode(_ context.Context, d core.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dev.rows == nil {
		s.dev.rows = map[string]core.DeviceCode{}
	}
	if _, dup := s.dev.rows[d.DeviceCodeHash]; dup {
		return idp.ErrConflict
	}
	for _, x := range s.dev.rows {
		if x.Realm == d.Realm && x.UserCodeHash == d.UserCodeHash {
			return idp.ErrConflict
		}
	}
	if d.Status == "" {
		d.Status = core.DevicePending
	}
	s.dev.rows[d.DeviceCodeHash] = d
	return nil
}

func (s *Store) GetDeviceCodeByUserCode(_ context.Context, realm, userCodeHash string) (core.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.dev.rows {
		if x.Realm == realm && x.UserCodeHash == userCodeHash {
			return x, nil
		}
	}
	return core.DeviceCode{}, idp.ErrNotFound
}

func (s *Store) DecideDeviceCode(_ context.Context, realm, userCodeHash string, now time.Time, d core.DeviceDecision) (core.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, x := range s.dev.rows {
		if x.Realm != realm || x.UserCodeHash != userCodeHash {
			continue
		}
		if x.Status != core.DevicePending || !now.Before(x.ExpiresAt) {
			return core.DeviceCode{}, idp.ErrNotFound
		}
		x.Status = core.DeviceDenied
		if d.Approve {
			x.Status = core.DeviceApproved
			x.UserID, x.SessionID, x.AuthTime = d.UserID, d.SessionID, d.AuthTime
		}
		s.dev.rows[k] = x
		return x, nil
	}
	return core.DeviceCode{}, idp.ErrNotFound
}

func (s *Store) PollDeviceCode(_ context.Context, realm, clientID, deviceCodeHash string, now time.Time) (core.DeviceCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.dev.rows[deviceCodeHash]
	if !ok || x.Realm != realm || x.ClientID != clientID {
		return core.DeviceCode{}, false, idp.ErrNotFound
	}
	fast := !x.LastPoll.IsZero() && now.Before(x.LastPoll.Add(time.Duration(x.Interval)*time.Second))
	if fast {
		x.Interval = min(x.Interval+core.DeviceSlowDownStep, core.DeviceMaxInterval)
	}
	x.LastPoll = now
	s.dev.rows[deviceCodeHash] = x
	return x, fast, nil
}

func (s *Store) ConsumeDeviceCode(_ context.Context, realm, clientID, deviceCodeHash string, now time.Time) (core.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.dev.rows[deviceCodeHash]
	if !ok || x.Realm != realm || x.ClientID != clientID || x.Status != core.DeviceApproved || !now.Before(x.ExpiresAt) {
		return core.DeviceCode{}, idp.ErrNotFound
	}
	delete(s.dev.rows, deviceCodeHash)
	return x, nil
}

func (s *Store) PurgeExpiredDeviceCodes(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, x := range s.dev.rows {
		if !x.ExpiresAt.After(now) {
			delete(s.dev.rows, k)
			n++
		}
	}
	return n, nil
}
