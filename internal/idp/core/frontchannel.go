// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import "context"

// FrontchannelStore is the optional store feature behind OIDC Front-Channel
// Logout 1.0: the per-client frontchannel_logout_uri. Clients are addressed by
// their internal id (Client.ID), so a re-created client_id never inherits the
// URI of a deleted client.
type FrontchannelStore interface {
	// FrontchannelLogoutURI returns "" when the client has none (or is unknown).
	FrontchannelLogoutURI(ctx context.Context, realm, clientUUID string) (string, error)
	// SetFrontchannelLogoutURI sets or, with "", removes the URI. It returns
	// idp.ErrNotFound for an unknown client. The caller validates the URI.
	SetFrontchannelLogoutURI(ctx context.Context, realm, clientUUID, uri string) error
}
