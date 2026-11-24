// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// DCRDeviceGrant is the RFC 8628 grant type URN. Dynamic client registration
// accepts it only when the realm's registration policy lists it explicitly
// (it is not part of DCRGrantTypes, so existing policies and the default
// policy are unchanged).
const DCRDeviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// DPoPStore is the optional storage behind DPoP (RFC 9449): the proof replay
// cache and the binding of refresh tokens to a key. A store that does not
// implement it (see StoreAs) leaves DPoP off, and the handlers then reject
// any request that carries a DPoP proof (fail closed).
//
// Neither the proof jti nor the refresh token is stored, only sha256 hex.
type DPoPStore interface {
	// RememberDPoPProof records a proof identifier (the sha256 hex of
	// "jkt|jti") in realm until expires. It returns idp.ErrConflict when the
	// same identifier is already remembered and not yet expired at now (a
	// replay). Exactly one of several concurrent calls with the same
	// identifier succeeds. Expired entries may be removed at any time.
	RememberDPoPProof(ctx context.Context, realm, proofHash string, now, expires time.Time) error

	// BindRefreshToken binds the refresh token (sha256 hex) to the key with
	// thumbprint jkt until expires. Binding a token that is already bound to
	// a different key is idp.ErrConflict; to the same key it is a no-op.
	BindRefreshToken(ctx context.Context, tokenHash, jkt string, expires time.Time) error

	// RefreshTokenBinding returns the key thumbprint a refresh token is bound
	// to. idp.ErrNotFound means "not bound" (or the binding expired).
	RefreshTokenBinding(ctx context.Context, tokenHash string, now time.Time) (jkt string, err error)

	// PurgeExpiredDPoP deletes proofs and bindings that expired at or before
	// now and returns how many rows went.
	PurgeExpiredDPoP(ctx context.Context, now time.Time) (int, error)
}
