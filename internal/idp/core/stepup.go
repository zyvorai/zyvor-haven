// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"slices"
	"time"
)

// StepUpPolicy is the per-realm login policy of migration 0013: the
// "use another method" fallback between enrolled second factors, and
// risk-based step-up. The zero value is everything off, which is exactly the
// behaviour before the feature existed.
type StepUpPolicy struct {
	// AllowFallback shows "use another method" on the passkey and TOTP login
	// steps for users who have both enrolled. It only chooses among enrolled
	// methods; it never skips a step.
	AllowFallback bool

	// Enabled turns signal evaluation on. With Enforce false the decision is
	// only written to the audit log (report-only / shadow mode) and devices
	// are still learned, so a realm can see what the policy would do.
	Enabled bool
	Enforce bool

	OnNewDevice bool          // no known-device cookie for this user
	OnIPChange  bool          // client network differs from the last login / the session's
	IdleAfter   time.Duration // 0 = off: idle at least this long since the last login / activity
	OnMaxAge    bool          // the client sent max_age (it asked for fresh authentication)

	// SensitiveScopes force step-up when requested. Authentication older than
	// SensitiveAuthMaxAge no longer counts for them (0 = every request).
	SensitiveScopes     []string
	SensitiveAuthMaxAge time.Duration
}

// Step-up reasons. They are fixed strings: they end up in audit events and
// must never carry user data.
const (
	ReasonNewDevice      = "new_device"
	ReasonIPChanged      = "ip_changed"
	ReasonIdle           = "idle"
	ReasonSensitiveScope = "sensitive_scope"
	ReasonMaxAge         = "max_age"
)

// RiskSignals is everything DecideStepUp looks at. Nothing else is used (no
// geolocation, no ASN/reputation, no user-agent or device fingerprint, no
// velocity): see docs/login-fallback-and-stepup.md.
type RiskSignals struct {
	NewDevice       bool          // no matching known-device record for this user
	IPChanged       bool          // different network prefix than last time, or unknown
	IdleFor         time.Duration // time since last login or activity; 0 = unknown/none
	Scopes          []string      // scopes the client requested (already filtered)
	AuthAge         time.Duration // age of the authentication being relied on; 0 for a fresh login
	MaxAgeRequested bool          // the client sent max_age
}

// StepUpDecision is the outcome. Required says whether policy asks for
// stronger authentication; Reasons lists every signal that fired, in a fixed
// order, whether or not the policy is enforcing.
type StepUpDecision struct {
	Required bool
	Reasons  []string
}

// DecideStepUp is the pure decision function: policy x signals -> decision.
// It does no I/O and has no clock; callers compute the signals. A disabled
// policy never fires. Enforce is NOT consulted here (the caller decides
// whether to act or only to report), so shadow mode shows the real decision.
func DecideStepUp(p StepUpPolicy, s RiskSignals) StepUpDecision {
	if !p.Enabled {
		return StepUpDecision{}
	}
	var why []string
	if p.OnNewDevice && s.NewDevice {
		why = append(why, ReasonNewDevice)
	}
	if p.OnIPChange && s.IPChanged {
		why = append(why, ReasonIPChanged)
	}
	if p.IdleAfter > 0 && s.IdleFor >= p.IdleAfter {
		why = append(why, ReasonIdle)
	}
	if len(p.SensitiveScopes) > 0 && sharesAny(p.SensitiveScopes, s.Scopes) &&
		(p.SensitiveAuthMaxAge <= 0 || s.AuthAge > p.SensitiveAuthMaxAge) {
		why = append(why, ReasonSensitiveScope)
	}
	if p.OnMaxAge && s.MaxAgeRequested {
		why = append(why, ReasonMaxAge)
	}
	return StepUpDecision{Required: len(why) > 0, Reasons: why}
}

func sharesAny(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// KnownDevice is one remembered browser of one user. Hash is the sha256 (hex)
// of the random device cookie, never the cookie itself; IPHash is a salted
// hash of the network prefix of the login that last used it.
type KnownDevice struct {
	Realm     string
	UserID    string
	Hash      string
	IPHash    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// MaxDevicesPerUser bounds the remembered devices; the least recently seen
// are dropped first.
const MaxDevicesPerUser = 20

// StepUpStore is the optional store feature behind the fallback flag,
// step-up policy and known devices. A store without it leaves the feature
// off (core.StoreAs).
type StepUpStore interface {
	// GetStepUpPolicy returns the realm policy (zero value when never set).
	GetStepUpPolicy(ctx context.Context, realm string) (StepUpPolicy, error)
	// PutStepUpPolicy replaces the realm policy; the realm must exist.
	PutStepUpPolicy(ctx context.Context, realm string, p StepUpPolicy) error

	// GetDevice returns the device or idp.ErrNotFound.
	GetDevice(ctx context.Context, realm, userID, hash string) (KnownDevice, error)
	// LatestDevice returns the most recently seen device of the user, or
	// idp.ErrNotFound when there is none.
	LatestDevice(ctx context.Context, realm, userID string) (KnownDevice, error)
	// TouchDevice inserts the device or updates LastSeen and IPHash (FirstSeen
	// is kept), then drops the user's least recently seen devices beyond max.
	TouchDevice(ctx context.Context, d KnownDevice, max int) error
	// ListDevices returns the user's devices, most recently seen first.
	ListDevices(ctx context.Context, realm, userID string) ([]KnownDevice, error)
	// DeleteDevice forgets one device (idempotent); DeleteUserDevices all.
	DeleteDevice(ctx context.Context, realm, userID, hash string) error
	DeleteUserDevices(ctx context.Context, realm, userID string) error
}
