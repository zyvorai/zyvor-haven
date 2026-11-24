// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// TOTPCredential is a user's authenticator-app credential. SealedSeed is the
// seed encrypted with the secretbox bound to "totp|realm|userID"; the store
// never sees the plaintext. A credential is only used for login once Confirmed
// (the user proved the authenticator works by entering a valid code).
type TOTPCredential struct {
	Realm      string
	UserID     string
	SealedSeed string
	Confirmed  bool
	CreatedAt  time.Time
	// LastUsedStep is the time step of the last accepted code (0 = none). A
	// code from a step at or below it is a replay.
	LastUsedStep int64
}

// MFAPolicy is the per-realm second-factor policy. It lives next to the TOTP
// tables, not in Realm, so the realm row stays untouched.
type MFAPolicy struct {
	// RequireMFA forces every user without a confirmed TOTP credential to
	// enroll one during login.
	RequireMFA bool
}

// MFAStore is the feature store for TOTP and recovery codes. A Store that does
// not implement it (see StoreAs) leaves the feature off.
//
// Every method that flips state is atomic: two parallel callers can never both
// win the same step or the same recovery code.
type MFAStore interface {
	// PutTOTP starts an enrollment: it inserts the credential, or replaces an
	// existing UNCONFIRMED one (fresh seed, LastUsedStep 0). It returns
	// idp.ErrConflict when a confirmed credential exists (disable it first).
	// c.Confirmed is ignored (always stored false).
	PutTOTP(ctx context.Context, c TOTPCredential) error
	// GetTOTP returns the credential or idp.ErrNotFound.
	GetTOTP(ctx context.Context, realm, userID string) (TOTPCredential, error)
	// ConfirmTOTP atomically flips Confirmed false->true and records step as
	// LastUsedStep. It reports false (no error) when the credential is missing
	// or already confirmed.
	ConfirmTOTP(ctx context.Context, realm, userID string, step int64) (bool, error)
	// UseTOTPStep atomically sets LastUsedStep=step if the credential is
	// confirmed and step > LastUsedStep. It reports whether it won; of two
	// parallel calls with the same step exactly one returns true.
	UseTOTPStep(ctx context.Context, realm, userID string, step int64) (bool, error)
	// DeleteUserMFA removes the user's credential and all recovery codes
	// (idempotent).
	DeleteUserMFA(ctx context.Context, realm, userID string) error

	// ReplaceRecoveryCodes atomically replaces the user's whole set with the
	// given sha256 hashes: the old set stops working.
	ReplaceRecoveryCodes(ctx context.Context, realm, userID string, hashes []string) error
	// ConsumeRecoveryCode atomically deletes one hash; it reports whether it
	// was present. Of N parallel calls with the same hash exactly one wins.
	ConsumeRecoveryCode(ctx context.Context, realm, userID, hash string) (bool, error)
	// CountRecoveryCodes returns how many unused codes the user has.
	CountRecoveryCodes(ctx context.Context, realm, userID string) (int, error)

	// GetMFAPolicy returns the realm policy (zero value when never set).
	GetMFAPolicy(ctx context.Context, realm string) (MFAPolicy, error)
	// PutMFAPolicy stores the realm policy; the realm must exist.
	PutMFAPolicy(ctx context.Context, realm string, p MFAPolicy) error
}
