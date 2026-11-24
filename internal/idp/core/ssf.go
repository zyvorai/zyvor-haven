// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"errors"
	"time"
)

// OpenID Shared Signals Framework (SSF 1.0) transmitter state. The store
// interface is a feature store (see StoreAs): a store without it simply does
// not offer shared signals and the endpoints answer 404.

// SSF limits.
const (
	SSFMaxStreamsPerReceiver = 5
	SSFMaxEndpointURL        = 2048
	SSFMaxDescription        = 256
	SSFMaxAuthHeader         = 1024
	// SSFOutboxRetention bounds how long an undelivered (pending) SET is kept;
	// delivered and dead rows are pruned much sooner (see ssf.Worker).
	SSFOutboxRetention = 24 * time.Hour
)

// Stream status values (SSF 1.0 section 8.1.2).
const (
	SSFStatusEnabled  = "enabled"
	SSFStatusPaused   = "paused"
	SSFStatusDisabled = "disabled"
)

// Outbox states.
const (
	SSFOutboxPending   = "pending"
	SSFOutboxDelivered = "delivered"
	SSFOutboxDead      = "dead"
)

// ErrSSFStreamLimit: the receiver already has SSFMaxStreamsPerReceiver streams.
var ErrSSFStreamLimit = errors.New("idp: too many streams for this receiver")

// SSFReceiver is a registered event receiver. The admin creates it and hands
// the bearer token to the receiver; only its sha256 hex is stored.
type SSFReceiver struct {
	ID        string
	Realm     string
	Name      string // unique per realm
	Audience  string // "aud" of every SET sent to this receiver
	TokenHash string
	// AllSubjects: events for every user of the realm are delivered, no
	// subject registration needed. Off = only subjects the receiver added.
	AllSubjects bool
	// AllowEmail lets the receiver's streams ask for email subject
	// identifiers (a privacy decision the admin makes, not the receiver).
	AllowEmail bool
	// Events lists the event type URIs the receiver may get; empty = all.
	Events    []string
	Disabled  bool
	CreatedAt time.Time
}

// SSFStream is one stream of events from the transmitter to a receiver.
type SSFStream struct {
	ID              string
	Realm           string
	ReceiverID      string
	Audience        string // copied from the receiver (read only)
	Status          string
	EndpointURL     string // push delivery target (RFC 8935)
	SealedAuth      string // secretbox-sealed Authorization header value, "" = none
	EventsRequested []string
	EventsDelivered []string
	Description     string
	SubjectFormat   string // "opaque" | "email" | "iss_sub"
	AllSubjects     bool   // from the receiver, read only
	ReceiverOff     bool   // receiver disabled, read only
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// SSFOutbox is one signed SET waiting for push delivery. The SET carries no
// secrets (see the ssf package), so it is stored as is.
type SSFOutbox struct {
	ID          string
	Realm       string
	StreamID    string
	JTI         string
	EventType   string
	SET         string
	Attempts    int
	NextAttempt time.Time
	CreatedAt   time.Time
	State       string
	LastOutcome string // enum label, never a URL or body
}

// SSFStore persists receivers, streams, stream subjects and the outbox.
// Streams, subjects and outbox rows are deleted with their receiver and realm.
type SSFStore interface {
	// CreateSSFReceiver returns idp.ErrConflict for a duplicate name/token.
	CreateSSFReceiver(ctx context.Context, r SSFReceiver) (SSFReceiver, error)
	GetSSFReceiver(ctx context.Context, realm, id string) (SSFReceiver, error)
	// GetSSFReceiverByTokenHash is the authentication lookup (all realms; the
	// caller checks the realm).
	GetSSFReceiverByTokenHash(ctx context.Context, tokenHash string) (SSFReceiver, error)
	ListSSFReceivers(ctx context.Context, realm string) ([]SSFReceiver, error)
	SetSSFReceiverToken(ctx context.Context, realm, id, tokenHash string) error
	SetSSFReceiverDisabled(ctx context.Context, realm, id string, disabled bool) error
	DeleteSSFReceiver(ctx context.Context, realm, id string) error

	// CreateSSFStream enforces maxStreams per receiver (ErrSSFStreamLimit).
	CreateSSFStream(ctx context.Context, s SSFStream, maxStreams int) (SSFStream, error)
	GetSSFStream(ctx context.Context, realm, id string) (SSFStream, error)
	ListSSFStreams(ctx context.Context, realm, receiverID string) ([]SSFStream, error) // receiverID "" = all
	UpdateSSFStream(ctx context.Context, s SSFStream) error
	DeleteSSFStream(ctx context.Context, realm, id string) error

	// AddSSFSubject is idempotent. RemoveSSFSubject of an unknown subject is a no-op.
	AddSSFSubject(ctx context.Context, realm, streamID, userID string, now time.Time) error
	RemoveSSFSubject(ctx context.Context, realm, streamID, userID string) error
	// SSFStreamsFor returns the non-disabled streams of non-disabled receivers
	// that should hear about userID: AllSubjects receivers plus streams the
	// user was added to. userID "" returns nothing.
	SSFStreamsFor(ctx context.Context, realm, userID string) ([]SSFStream, error)

	EnqueueSSF(ctx context.Context, items []SSFOutbox) error
	// ClaimSSFOutbox leases up to limit pending rows that are due, of ENABLED
	// streams of enabled receivers. A leased row is not returned again until
	// the lease ends, so replicas do not double-send.
	ClaimSSFOutbox(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]SSFOutbox, error)
	// FinishSSFOutbox records one attempt: state delivered/dead (final) or
	// pending with the next attempt time.
	FinishSSFOutbox(ctx context.Context, id, state string, next time.Time, outcome string) error
	CountSSFOutbox(ctx context.Context, realm string) (map[string]int, error)
	// PruneSSFOutbox deletes delivered rows created before delivered, dead rows
	// before dead, and pending rows before pending. Returns rows removed.
	PruneSSFOutbox(ctx context.Context, delivered, dead, pending time.Time) (int, error)
}

// Signal is something that happened to a user that receivers may care about.
// Kind is the full event type URI; Attrs are the event's own members (never
// secrets), and the subject is derived per stream from Realm/UserID.
type Signal struct {
	Realm     string
	UserID    string
	SessionID string // session-revoked only
	Kind      string
	Attrs     map[string]any
	Time      time.Time // zero = now
}

// SignalEmitter is implemented by the SSF store decorator. Call sites that
// change things the decorator cannot see (TOTP, passkeys) use EmitSignal.
type SignalEmitter interface {
	EmitSignal(ctx context.Context, s Signal)
}

// EmitSignal sends s to the SSF transmitter if the store has one. It is a
// no-op otherwise and never fails the caller.
func EmitSignal(ctx context.Context, st Store, s Signal) {
	if e, ok := StoreAs[SignalEmitter](st); ok {
		e.EmitSignal(ctx, s)
	}
}

// SSFPolicy is the transmitter's deployment policy, reachable through the
// store decorator so handlers need no extra wiring.
type SSFPolicy struct {
	AllowPrivate bool // dev only: permit http to loopback and private targets
}

// SSFPolicyProvider is implemented by the SSF store decorator. A store without
// it means the transmitter is not running: SSF endpoints answer 404.
type SSFPolicyProvider interface{ SSFPolicy() SSFPolicy }

// TypedSigner signs with a specific JOSE "typ" (SETs use "secevent+jwt").
type TypedSigner interface {
	SignTyp(ctx context.Context, realm, typ string, claims Claims) (string, error)
}
