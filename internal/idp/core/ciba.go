// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// CIBA (OpenID Client-Initiated Backchannel Authentication, poll mode)
// request states.
const (
	CIBAPending  = "pending"
	CIBAApproved = "approved"
	CIBADenied   = "denied"
)

// CIBA poll interval bookkeeping, as for the device flow: a client that polls
// faster than Interval is told slow_down and its stored interval grows by
// CIBASlowDownStep, up to CIBAMaxInterval seconds.
const (
	CIBASlowDownStep = 5
	CIBAMaxInterval  = 300
)

// CIBARequest is one pending or decided backchannel authentication request.
// Neither the auth_req_id nor the approval token is stored, only their sha256
// hex. UserID is empty when the login_hint did not resolve to a user the
// request can be delivered to; such a request is stored anyway so that the
// client cannot tell it from a real one (it can never be approved).
type CIBARequest struct {
	AuthReqHash  string // sha256 hex of the auth_req_id (primary key)
	ApprovalHash string // sha256 hex of the approval token mailed to the user; unique per realm
	Realm        string
	ClientID     string
	UserID       string // "" = unresolved (never approvable)
	Scope        string
	Binding      string   // binding_message shown to the approver
	Resources    []string // RFC 8707 resource indicators requested

	Status string // CIBAPending | CIBAApproved | CIBADenied

	// Set when approved.
	SessionID string
	AuthTime  time.Time

	// Where the request came from, shown to the approver.
	RequestIP string

	Interval  int       // seconds between polls the client must respect
	LastPoll  time.Time // zero = never polled
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CIBADecision is the outcome applied by DecideCIBA.
type CIBADecision struct {
	Approve   bool
	SessionID string
	AuthTime  time.Time
}

// CIBAStore is the optional storage feature behind CIBA. Stores that do not
// implement it (see StoreAs) simply do not offer the flow. Implementations:
// store/memstore, store/pgstore. Safe for concurrent use.
type CIBAStore interface {
	// CIBAClientEnabled reports whether the client (by its opaque Client.ID)
	// has been opted in to CIBA. Unknown clients are not enabled.
	CIBAClientEnabled(ctx context.Context, realm, clientUUID string) (bool, error)
	// SetCIBAClient opts a client in or out. idp.ErrNotFound when the client
	// does not exist in the realm.
	SetCIBAClient(ctx context.Context, realm, clientUUID string, enabled bool) error

	// PutCIBARequest inserts a request. idp.ErrConflict if the auth_req_id
	// hash or the (realm, approval hash) pair already exists.
	PutCIBARequest(ctx context.Context, r CIBARequest) error

	// GetCIBAByApproval looks a request up by the sha256 hex of the approval
	// token. idp.ErrNotFound when none. Expiry is the caller's to check.
	GetCIBAByApproval(ctx context.Context, realm, approvalHash string) (CIBARequest, error)

	// DecideCIBA atomically moves a still-pending, unexpired request (at now)
	// that belongs to userID (non-empty) to approved or denied. Exactly one of
	// several concurrent decisions wins; the others, a decision by another
	// user, and any decision on a missing, expired, unresolved or already
	// decided request, get idp.ErrNotFound. Returns the updated row.
	DecideCIBA(ctx context.Context, realm, approvalHash, userID string, now time.Time, d CIBADecision) (CIBARequest, error)

	// PollCIBA records a poll by the client that owns the request, in one
	// atomic step: it returns the row and reports tooFast when now is earlier
	// than LastPoll+Interval. A too-fast poll also raises the stored Interval
	// by CIBASlowDownStep (capped at CIBAMaxInterval). LastPoll is set to now
	// either way. idp.ErrNotFound when no request with this hash exists for
	// (realm, clientID).
	PollCIBA(ctx context.Context, realm, clientID, authReqHash string, now time.Time) (r CIBARequest, tooFast bool, err error)

	// ConsumeCIBA atomically deletes and returns an approved, unexpired
	// request owned by (realm, clientID): token issuance happens at most once.
	// idp.ErrNotFound for anything else.
	ConsumeCIBA(ctx context.Context, realm, clientID, authReqHash string, now time.Time) (CIBARequest, error)

	// PurgeExpiredCIBA deletes requests that expired at or before now.
	PurgeExpiredCIBA(ctx context.Context, now time.Time) (int, error)
}
