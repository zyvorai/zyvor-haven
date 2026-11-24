// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package ssf

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Builder builds and signs SETs.
type Builder struct {
	Signer  core.Signer
	BaseURL string // public base; issuer = BaseURL/realms/{realm}
	Clock   func() time.Time
}

func (b Builder) now() time.Time {
	if b.Clock != nil {
		return b.Clock()
	}
	return time.Now()
}

// Issuer is the SET issuer and the transmitter issuer of a realm.
func (b Builder) Issuer(realm string) string {
	return strings.TrimRight(b.BaseURL, "/") + "/realms/" + realm
}

func (b Builder) sign(ctx context.Context, realm string, claims core.Claims) (string, error) {
	if ts, ok := b.Signer.(core.TypedSigner); ok {
		return ts.SignTyp(ctx, realm, SETType, claims)
	}
	return b.Signer.Sign(ctx, realm, claims)
}

// UserSubject renders a user as a subject identifier in the stream's format.
// Email falls back to opaque when the user has no email: a stream never gets
// a format it did not ask for, nor an empty identifier.
func (b Builder) UserSubject(realm string, u core.User, format string) map[string]any {
	switch format {
	case FormatEmail:
		if u.Email != "" {
			return map[string]any{"format": FormatEmail, "email": u.Email}
		}
	case FormatIssSub:
		return map[string]any{"format": FormatIssSub, "iss": b.Issuer(realm), "sub": u.ID}
	}
	return map[string]any{"format": FormatOpaque, "id": u.ID}
}

func jti() (string, error) {
	r := make([]byte, 16)
	if _, err := rand.Read(r); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(r), nil
}

// SET signs one event for one stream and returns the outbox row (not yet
// stored). subID is the top-level sub_id; evSubject is the event's own
// "subject" member (nil omits it). The "sub" claim is never set (SSF 1.0).
func (b Builder) SET(ctx context.Context, st core.SSFStream, subID, evSubject map[string]any, uri string, payload map[string]any, at time.Time) (core.SSFOutbox, error) {
	id, err := jti()
	if err != nil {
		return core.SSFOutbox{}, err
	}
	ev := map[string]any{}
	maps.Copy(ev, payload)
	if evSubject != nil {
		ev["subject"] = evSubject
	}
	ev["event_timestamp"] = at.Unix()
	now := b.now()
	claims := core.Claims{
		"iss":    b.Issuer(st.Realm),
		"aud":    st.Audience,
		"iat":    now.Unix(),
		"jti":    id,
		"sub_id": subID,
		"events": map[string]any{uri: ev},
	}
	tok, err := b.sign(ctx, st.Realm, claims)
	if err != nil {
		return core.SSFOutbox{}, err
	}
	return core.SSFOutbox{Realm: st.Realm, StreamID: st.ID, JTI: id, EventType: uri, SET: tok,
		NextAttempt: now.UTC(), CreatedAt: now.UTC(), State: core.SSFOutboxPending}, nil
}

// Verification builds the SSF verification SET for a stream (section 8.1.4.1):
// sub_id is the stream id as an opaque identifier, state is echoed.
func (b Builder) Verification(ctx context.Context, st core.SSFStream, state string) (core.SSFOutbox, error) {
	sub := map[string]any{"format": FormatOpaque, "id": st.ID}
	payload := map[string]any{}
	if state != "" {
		payload["state"] = state
	}
	return b.SET(ctx, st, sub, nil, EvVerification, payload, b.now())
}

// Transmitter turns Signals into outbox rows.
type Transmitter struct {
	Builder
	Store        core.Store // the UNDECORATED store
	Logger       *slog.Logger
	AllowPrivate bool
}

func (t *Transmitter) logger() *slog.Logger {
	if t.Logger != nil {
		return t.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// piiClaims are token claims that identify a person: only streams that
// asked for email subjects (and so already get the email) receive them.
var piiClaims = map[string]bool{"email": true, "email_verified": true, "preferred_username": true, "given_name": true, "family_name": true}

// Emit signs sig for every stream that should hear about it and stores the
// SETs in the outbox. It never fails the caller; problems are logged.
func (t *Transmitter) Emit(ctx context.Context, sig core.Signal) {
	defer func() {
		if r := recover(); r != nil {
			t.logger().Error("ssf: panic while emitting", "realm", sig.Realm)
		}
	}()
	ss, ok := core.StoreAs[core.SSFStore](t.Store)
	if !ok || sig.UserID == "" || sig.Realm == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	streams, err := ss.SSFStreamsFor(ctx, sig.Realm, sig.UserID)
	if err != nil {
		t.logger().Warn("ssf: list streams failed", "realm", sig.Realm)
		return
	}
	var want []core.SSFStream
	for _, s := range streams {
		if slices.Contains(s.EventsDelivered, sig.Kind) {
			want = append(want, s)
		}
	}
	if len(want) == 0 {
		return
	}
	u, err := t.Store.GetUser(ctx, sig.Realm, sig.UserID)
	if err != nil {
		t.logger().Warn("ssf: load user failed", "realm", sig.Realm)
		return
	}
	at := sig.Time
	if at.IsZero() {
		at = t.now()
	}
	var rows []core.SSFOutbox
	for _, s := range want {
		sub := t.UserSubject(sig.Realm, u, s.SubjectFormat)
		evSub := any(sub)
		payload := maps.Clone(sig.Attrs)
		if payload == nil {
			payload = map[string]any{}
		}
		if sig.Kind == EvSessionRevoked && sig.SessionID != "" {
			evSub = map[string]any{"format": "complex", "session": map[string]any{"format": FormatOpaque, "id": sig.SessionID}, "user": sub}
		}
		if sig.Kind == EvTokenClaimsChange {
			claims, _ := sig.Attrs["claims"].(map[string]any)
			kept := map[string]any{}
			for k, v := range claims {
				if !piiClaims[k] || s.SubjectFormat == FormatEmail {
					kept[k] = v
				}
			}
			if len(kept) == 0 {
				continue
			}
			payload["claims"] = kept
		}
		row, err := t.SET(ctx, s, sub, evSub.(map[string]any), sig.Kind, payload, at)
		if err != nil {
			t.logger().Warn("ssf: sign failed", "realm", sig.Realm)
			continue
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return
	}
	if err := ss.EnqueueSSF(ctx, rows); err != nil {
		if !errors.Is(err, context.Canceled) {
			t.logger().Warn("ssf: enqueue failed", "realm", sig.Realm)
		}
	}
}
