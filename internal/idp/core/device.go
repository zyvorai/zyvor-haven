// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// Device authorization grant (RFC 8628) states.
const (
	DevicePending  = "pending"
	DeviceApproved = "approved"
	DeviceDenied   = "denied"
)

// Device poll interval bookkeeping: a client that polls faster than Interval
// is told to slow_down and its stored interval grows by DeviceSlowDownStep
// (RFC 8628 section 3.5), up to DeviceMaxInterval seconds.
const (
	DeviceSlowDownStep = 5
	DeviceMaxInterval  = 300
)

// DeviceCode is one pending or decided device authorization request. Neither
// the device code nor the user code is stored, only their sha256 hex.
type DeviceCode struct {
	DeviceCodeHash string // sha256 hex of the device_code (primary key)
	UserCodeHash   string // sha256 hex of the normalised user code; unique per realm
	Realm          string
	ClientID       string
	Scope          string
	Status         string // DevicePending | DeviceApproved | DeviceDenied

	// Set when the code is decided (approved or denied).
	UserID    string
	SessionID string    // SSO session the approving user was signed in with
	AuthTime  time.Time // that session's AuthTime (zero until approved)

	// Where the request came from, shown to the approver.
	RequestIP string
	RequestUA string

	Interval  int       // seconds between polls the client must respect
	LastPoll  time.Time // zero = never polled
	CreatedAt time.Time
	ExpiresAt time.Time
}

// DeviceDecision is the outcome applied by DecideDeviceCode.
type DeviceDecision struct {
	Approve   bool
	UserID    string
	SessionID string
	AuthTime  time.Time
}

// DeviceStore is the optional storage feature behind the device flow. Stores
// that do not implement it (see StoreAs) simply do not offer the flow.
// Implementations: store/memstore, store/pgstore. Safe for concurrent use.
type DeviceStore interface {
	// PutDeviceCode inserts a request. idp.ErrConflict if the device code hash
	// or the (realm, user code hash) pair already exists (the caller retries
	// with a fresh user code).
	PutDeviceCode(ctx context.Context, d DeviceCode) error

	// GetDeviceCodeByUserCode looks a request up by the sha256 hex of the
	// normalised user code. idp.ErrNotFound when none. Expiry is the caller's
	// to check: the row stays until purged.
	GetDeviceCodeByUserCode(ctx context.Context, realm, userCodeHash string) (DeviceCode, error)

	// DecideDeviceCode atomically moves a still-pending, unexpired request
	// (at now) to approved or denied. Exactly one of several concurrent
	// decisions wins; the others, and any decision on a missing, expired or
	// already decided request, get idp.ErrNotFound. Returns the updated row.
	DecideDeviceCode(ctx context.Context, realm, userCodeHash string, now time.Time, d DeviceDecision) (DeviceCode, error)

	// PollDeviceCode records a poll by the client that owns the request, in
	// one atomic step: it returns the row and reports tooFast when now is
	// earlier than LastPoll+Interval. A too-fast poll also raises the stored
	// Interval by DeviceSlowDownStep (capped at DeviceMaxInterval). LastPoll
	// is set to now either way. idp.ErrNotFound when no request with this
	// device code hash exists for (realm, clientID).
	PollDeviceCode(ctx context.Context, realm, clientID, deviceCodeHash string, now time.Time) (d DeviceCode, tooFast bool, err error)

	// ConsumeDeviceCode atomically deletes and returns an approved, unexpired
	// request owned by (realm, clientID): token issuance happens at most once.
	// idp.ErrNotFound for anything else (missing, pending, denied, expired,
	// already consumed).
	ConsumeDeviceCode(ctx context.Context, realm, clientID, deviceCodeHash string, now time.Time) (DeviceCode, error)

	// PurgeExpiredDeviceCodes deletes requests that expired at or before now
	// and returns how many.
	PurgeExpiredDeviceCodes(ctx context.Context, now time.Time) (int, error)
}
