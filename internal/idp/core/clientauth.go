// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// Strong client authentication: private_key_jwt (RFC 7523, OIDC Core section
// 9), mutual TLS client authentication and certificate-bound access tokens
// (RFC 8705). See docs/client-authentication.md.

// Client authentication methods (the registered values of
// token_endpoint_auth_method).
const (
	AuthMethodNone          = "none"
	AuthMethodSecretBasic   = "client_secret_basic"
	AuthMethodSecretPost    = "client_secret_post"
	AuthMethodPrivateKeyJWT = "private_key_jwt"
	AuthMethodTLS           = "tls_client_auth"
	AuthMethodSelfSignedTLS = "self_signed_tls_client_auth"
)

// ClientAuth is the authentication configuration of one client, keyed by the
// client's internal ID (Client.ID) so a deleted and re-created client_id never
// inherits a method or keys. A client without one authenticates as before: a
// confidential client with its secret (basic or post), a public client with
// its client_id only.
type ClientAuth struct {
	Realm     string
	ClientRef string // core.Client.ID
	// Method is the only way this client may authenticate.
	Method string
	// JWKS (inline JSON) or JWKSURI (https) holds the public keys of
	// private_key_jwt, or the certificates (x5c) of self_signed_tls_client_auth.
	JWKS    string
	JWKSURI string
	// SigningAlg, when set, is the only assertion algorithm accepted.
	SigningAlg string
	// Exactly one of these identifies the certificate of tls_client_auth.
	TLSSubjectDN string
	TLSSANDNS    string
	TLSSANURI    string
	TLSSANIP     string
	TLSSANEmail  string
	// CertBoundTokens: access tokens are bound to the client certificate of
	// the token request (cnf.x5t#S256); a request without one is refused.
	CertBoundTokens bool
}

// StrongClientAuth reports whether method proves possession of a private key
// instead of presenting a shared secret (or nothing).
func StrongClientAuth(method string) bool {
	return method == AuthMethodPrivateKeyJWT || method == AuthMethodTLS || method == AuthMethodSelfSignedTLS
}

// ClientAuthStore is the optional storage behind strong client authentication.
// A store without it (see StoreAs) leaves the feature off: no client can be
// given a method, and every client assertion is refused.
type ClientAuthStore interface {
	// GetClientAuth returns the client's configuration; idp.ErrNotFound means
	// none was set (or the client no longer exists).
	GetClientAuth(ctx context.Context, realm, clientRef string) (ClientAuth, error)
	// PutClientAuth replaces it; idp.ErrNotFound if the client does not exist
	// in that realm.
	PutClientAuth(ctx context.Context, c ClientAuth) error
	// DeleteClientAuth removes it; a missing one is not an error.
	DeleteClientAuth(ctx context.Context, realm, clientRef string) error

	// RememberClientAssertion records a client assertion identifier (sha256
	// hex of the client's internal id and the jti; neither is stored in
	// clear) in realm until expires. idp.ErrConflict means it is already
	// remembered and not expired at now (a replay). Exactly one of several
	// concurrent calls with the same identifier succeeds.
	RememberClientAssertion(ctx context.Context, realm, hash string, now, expires time.Time) error
	// PurgeExpiredClientAssertions deletes entries that expired at or before
	// now and returns how many went.
	PurgeExpiredClientAssertions(ctx context.Context, now time.Time) (int, error)
}
