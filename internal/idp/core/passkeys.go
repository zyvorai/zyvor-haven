// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// Passkey is a registered WebAuthn credential. CredentialID and UserHandle are
// base64url (no padding) strings. PublicKey is the original COSE_Key bytes.
type Passkey struct {
	Realm          string
	UserID         string
	CredentialID   string // unique per realm
	PublicKey      []byte
	SignCount      uint32
	Transports     []string
	AAGUID         string // hex, 32 chars
	Name           string
	BackupEligible bool
	BackupState    bool
	CreatedAt      time.Time
	LastUsedAt     time.Time // zero = never used
}

// PasskeyStore is the optional store feature behind WebAuthn. A store that
// does not implement it has passkeys switched off (core.StoreAs).
type PasskeyStore interface {
	// UserHandle returns the user's random opaque WebAuthn user handle,
	// storing candidate if the user has none yet (so concurrent first calls
	// agree). The handle is never the username or email.
	UserHandle(ctx context.Context, realm, userID, candidate string) (string, error)
	// UserByHandle returns the user id for a handle, or idp.ErrNotFound.
	UserByHandle(ctx context.Context, realm, handle string) (string, error)

	// AddPasskey stores a credential; idp.ErrConflict if the credential id is
	// already registered in the realm (to any user).
	AddPasskey(ctx context.Context, p Passkey) error
	GetPasskey(ctx context.Context, realm, credentialID string) (Passkey, error)
	ListPasskeys(ctx context.Context, realm, userID string) ([]Passkey, error) // oldest first
	// UpdatePasskeyUse records a successful assertion.
	UpdatePasskeyUse(ctx context.Context, realm, credentialID string, signCount uint32, backupState bool, at time.Time) error
	// RenamePasskey renames a credential of userID; idp.ErrNotFound otherwise.
	RenamePasskey(ctx context.Context, realm, userID, credentialID, name string) error
	// DeletePasskey removes a credential of userID. With keepLast it fails
	// with idp.ErrConflict instead of removing the user's last credential
	// (atomically with respect to concurrent deletes).
	DeletePasskey(ctx context.Context, realm, userID, credentialID string, keepLast bool) error

	// ConsumeChallenge records a challenge digest as used. The second call
	// for the same digest returns idp.ErrConflict, so a captured registration
	// or assertion cannot be verified twice. Rows past expires may be purged.
	ConsumeChallenge(ctx context.Context, digest string, now, expires time.Time) error

	// RealmRequiresPasskeys / SetRealmRequiresPasskeys: realm policy. When
	// set, a user cannot remove their last passkey.
	RealmRequiresPasskeys(ctx context.Context, realm string) (bool, error)
	SetRealmRequiresPasskeys(ctx context.Context, realm string, v bool) error
}
