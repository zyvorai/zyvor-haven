// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"errors"
	"time"
)

// Per-realm session controls (docs/sso-and-logout.md): a cap on concurrent
// SSO sessions per user and the optional "keep me signed in" lifetime.

// What happens when a login would exceed SessionPolicy.MaxSessions.
const (
	SessionLimitRevokeOldest = "revoke_oldest"
	SessionLimitDenyNew      = "deny_new"
)

// Bounds of a SessionPolicy.
const (
	MaxSessionLimit = 1000

	DefaultRememberIdle = 7 * 24 * time.Hour
	DefaultRememberMax  = 30 * 24 * time.Hour
	MinRememberIdle     = time.Hour
	// MinRememberMax is above the ordinary absolute session cap, so a
	// remembered session is always recognisable by its lifetime.
	MinRememberMax = 24 * time.Hour
	MaxRememberMax = 90 * 24 * time.Hour
)

// ErrSessionLimit: the user already has the maximum number of live sessions
// and the realm refuses new ones.
var ErrSessionLimit = errors.New("core: session limit reached")

// SessionPolicy is the realm's session control. The zero value (never set)
// means no limit and no "keep me signed in".
type SessionPolicy struct {
	MaxSessions  int    // live sessions per user; 0 = unlimited
	OnLimit      string // SessionLimitRevokeOldest (also when empty) | SessionLimitDenyNew
	RememberMe   bool   // offer "keep me signed in" on the login page
	RememberIdle time.Duration
	RememberMax  time.Duration
}

// RememberLifetimes returns the idle and absolute lifetime of a remembered
// session: defaults filled in and clamped to the bounds, so a bad stored value
// can never produce an unbounded session.
func (p SessionPolicy) RememberLifetimes() (idle, absolute time.Duration) {
	idle, absolute = p.RememberIdle, p.RememberMax
	if absolute <= 0 {
		absolute = DefaultRememberMax
	}
	absolute = max(min(absolute, MaxRememberMax), MinRememberMax)
	if idle <= 0 {
		idle = DefaultRememberIdle
	}
	idle = min(max(idle, MinRememberIdle), absolute)
	return idle, absolute
}

// Validate checks a policy an administrator wants to store. Zero lifetimes
// mean "use the default".
func (p SessionPolicy) Validate() error {
	if p.MaxSessions < 0 || p.MaxSessions > MaxSessionLimit {
		return errors.New("maxSessions must be between 0 (unlimited) and 1000")
	}
	if p.OnLimit != "" && p.OnLimit != SessionLimitRevokeOldest && p.OnLimit != SessionLimitDenyNew {
		return errors.New("onLimit must be revoke_oldest or deny_new")
	}
	if p.RememberMax != 0 && (p.RememberMax < MinRememberMax || p.RememberMax > MaxRememberMax) {
		return errors.New("rememberMaxSeconds must be 0 (default) or between 1 and 90 days")
	}
	if p.RememberIdle != 0 && (p.RememberIdle < MinRememberIdle || p.RememberIdle > MaxRememberMax) {
		return errors.New("rememberIdleSeconds must be 0 (default) or between 1 hour and 90 days")
	}
	absolute := p.RememberMax
	if absolute == 0 {
		absolute = DefaultRememberMax
	}
	if p.RememberIdle > absolute {
		return errors.New("rememberIdleSeconds must not exceed the remember maximum")
	}
	return nil
}

// NewSessionOptions controls SessionPolicyStore.CreateLimitedSession.
type NewSessionOptions struct {
	Now     time.Time // decides which existing sessions are still live
	MaxLive int       // live sessions the user may have, the new one included; 0 = unlimited
	DenyNew bool      // over the limit: refuse instead of removing the oldest
	// Replaces is the id of a session of the same user that the caller ends
	// right after (the browser signing in again). It is neither counted nor
	// evicted.
	Replaces     string
	RememberIdle time.Duration // > 0 marks the new session as remembered
}

// SessionPolicyStore is the optional store feature behind session controls. A
// store without it has them switched off.
type SessionPolicyStore interface {
	// GetSessionPolicy returns the zero value for a realm that never set one.
	GetSessionPolicy(ctx context.Context, realm string) (SessionPolicy, error)
	// PutSessionPolicy returns idp.ErrNotFound for an unknown realm.
	PutSessionPolicy(ctx context.Context, realm string, p SessionPolicy) error

	// CreateLimitedSession stores s like Store.PutSession and enforces the
	// limit in the same atomic step, also across replicas: concurrent logins
	// of one user never leave more than MaxLive live sessions. It removes the
	// oldest live sessions (by creation time) that no longer fit and returns
	// them so the caller can finish ending them (refresh tokens, logout
	// notifications). With DenyNew it stores nothing and returns
	// ErrSessionLimit instead.
	CreateLimitedSession(ctx context.Context, s Session, o NewSessionOptions) (evicted []Session, err error)
	// SessionRememberIdle returns the idle window of a remembered session, or
	// 0 for an ordinary or unknown one.
	SessionRememberIdle(ctx context.Context, realm, id string) (time.Duration, error)
}
