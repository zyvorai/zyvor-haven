// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import "context"

// Claims is a JWT claim set.
type Claims map[string]any

// Signer issues and verifies realm-scoped JWTs and publishes the realm JWKS.
// Implementation: internal/idp/keys.
type Signer interface {
	// EnsureKey makes sure the realm has an active signing key, creating one
	// if needed.
	EnsureKey(ctx context.Context, realm string) error
	// Sign returns a compact JWS (typ "JWT") signed with the realm's active key.
	Sign(ctx context.Context, realm string, claims Claims) (string, error)
	// Verify checks signature (against any published key), alg pinning and
	// exp/nbf, and returns the claims. Issuer/audience checks are the caller's.
	Verify(ctx context.Context, realm, token string) (Claims, error)
	// JWKS returns the realm's public key set as JSON.
	JWKS(ctx context.Context, realm string) ([]byte, error)
	// Rotate adds a new active key and keeps the previous one published until
	// the grace period has elapsed.
	Rotate(ctx context.Context, realm string) error
}

// PasswordHasher hashes and verifies local passwords. Implementation:
// internal/idp/password.
type PasswordHasher interface {
	Hash(password string) (string, error)
	// Verify returns (ok, needsRehash).
	Verify(password, encoded string) (bool, bool)
}
