// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// FAPI building blocks: pushed authorization requests (RFC 9126), signed
// request objects (RFC 9101), rich authorization requests (RFC 9396) and the
// per-client "require PAR / require DPoP" switches. See docs/fapi-par-jar-rar.md.

// Kinds of FAPIRequest and FAPIBinding rows.
const (
	FAPIKindPAR     = "par"     // a pushed request, redeemed once at /auth via request_uri
	FAPIKindCtx     = "ctx"     // the same parameters kept for the login steps after redemption
	FAPIKindCode    = "code"    // extras bound to an authorization code
	FAPIKindRefresh = "refresh" // extras bound to a refresh token
)

// ClientFAPI is the FAPI configuration of one client, keyed by the client's
// internal ID (Client.ID, not ClientID) so a deleted and re-created client_id
// never inherits keys or switches.
type ClientFAPI struct {
	Realm     string
	ClientRef string // core.Client.ID
	// RequirePAR: /auth refuses anything but a request_uri from /par.
	RequirePAR bool
	// RequireDPoP: the token endpoint refuses every request without a valid
	// DPoP proof, so all tokens of the client are sender-constrained.
	RequireDPoP bool
	// RequireSignedRequest: /par and /auth accept only a signed request object.
	RequireSignedRequest bool
	// JWKS is the public key set (inline JSON) that verifies request objects.
	JWKS string
	// AuthzDetailTypes are the RFC 9396 "type" values the client may request.
	// Empty = the client may not send authorization_details at all.
	AuthzDetailTypes []string
}

// FAPIRequest is a pushed authorization request (kind par) or the context a
// login continues with after the request_uri was redeemed (kind ctx). Only the
// sha256 hex of the identifier is stored. Params is a JSON object of strings.
type FAPIRequest struct {
	Kind      string
	IDHash    string
	Realm     string
	ClientID  string // client_id (not the internal ID)
	Params    string
	ExpiresAt time.Time
}

// FAPIBinding carries extras from the authorization request to the tokens:
// RFC 9396 authorization_details (a JSON array) and a DPoP key thumbprint
// (dpop_jkt, RFC 9449 section 10). KeyHash is the sha256 hex of the code or
// refresh token.
type FAPIBinding struct {
	Kind      string
	KeyHash   string
	Realm     string
	ClientID  string
	Details   string
	DPoPJKT   string
	ExpiresAt time.Time
}

// FAPIStore is the optional storage behind the FAPI building blocks. A store
// without it (see StoreAs) leaves the feature off: /par answers 501, and the
// authorization and token endpoints reject every request that uses it.
type FAPIStore interface {
	// GetClientFAPI returns the client's settings; idp.ErrNotFound means all
	// defaults (nothing required, no keys, no detail types).
	GetClientFAPI(ctx context.Context, realm, clientRef string) (ClientFAPI, error)
	// PutClientFAPI replaces the settings; idp.ErrNotFound if the client does not exist.
	PutClientFAPI(ctx context.Context, c ClientFAPI) error
	DeleteClientFAPI(ctx context.Context, realm, clientRef string) error

	// PutFAPIRequest stores a request; an identifier already in use is idp.ErrConflict.
	PutFAPIRequest(ctx context.Context, r FAPIRequest) error
	// ConsumeFAPIRequest returns and deletes the request in one atomic step:
	// exactly one of several concurrent callers gets it. Unknown, used or
	// expired (at now) is idp.ErrNotFound.
	ConsumeFAPIRequest(ctx context.Context, realm, kind, idHash string, now time.Time) (FAPIRequest, error)
	// GetFAPIRequest reads without consuming; unknown or expired is idp.ErrNotFound.
	GetFAPIRequest(ctx context.Context, realm, kind, idHash string, now time.Time) (FAPIRequest, error)

	// PutFAPIBinding upserts a binding.
	PutFAPIBinding(ctx context.Context, b FAPIBinding) error
	// GetFAPIBinding reads a binding; unknown or expired is idp.ErrNotFound.
	GetFAPIBinding(ctx context.Context, kind, keyHash string, now time.Time) (FAPIBinding, error)

	// PurgeExpiredFAPI deletes requests and bindings that expired at or before
	// now and returns how many rows went.
	PurgeExpiredFAPI(ctx context.Context, now time.Time) (int, error)
}
