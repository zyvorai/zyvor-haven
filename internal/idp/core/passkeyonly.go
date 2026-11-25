// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// PasskeyOnlyStore is the optional store feature behind the realm option
// "passkey-only for users who have a passkey" (docs/passkeys.md). It is off
// unless an administrator turns it on.
type PasskeyOnlyStore interface {
	// PasskeyOnly reports whether the realm option is on (false when never set).
	PasskeyOnly(ctx context.Context, realm string) (bool, error)
	// SetPasskeyOnly returns idp.ErrNotFound for an unknown realm.
	SetPasskeyOnly(ctx context.Context, realm string, v bool) error

	// MarkPasswordlessPasskey records that this credential has completed a
	// sign-in without a password (it is discoverable and verifies the user).
	// Idempotent; idp.ErrNotFound for an unknown credential.
	MarkPasswordlessPasskey(ctx context.Context, realm, credentialID string, at time.Time) error
	// PasswordlessPasskeys returns the sorted ids of the user's CURRENT
	// passkeys that carry that mark. A deleted credential loses it, also when
	// the same credential id is registered again.
	PasswordlessPasskeys(ctx context.Context, realm, userID string) ([]string, error)
}
