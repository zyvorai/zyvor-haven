// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import "context"

// MaxUserEvents bounds one ListUserEvents call.
const MaxUserEvents = 200

// AccountStore is the optional store feature behind the user-facing account
// console (docs/account-console.md). A store without it leaves the console off
// (core.StoreAs). Both methods are scoped to one user on purpose: there is no
// way to ask them about anybody else.
type AccountStore interface {
	// ListUserEvents returns the newest audit events of one user in one realm
	// whose Type is one of types, newest first. At most limit rows (capped at
	// MaxUserEvents; limit <= 0 means MaxUserEvents). An empty userID or an
	// empty types list returns nothing, never everything.
	ListUserEvents(ctx context.Context, realm, userID string, types []string, limit int) ([]Event, error)

	// RotateSessionCookie replaces the cookie hash of one SSO session, so the
	// old cookie stops working while the session id (the OIDC sid) stays.
	// ErrNotFound when no session with that id belongs to userID in realm;
	// ErrConflict when another session already uses the hash. An empty hash is
	// refused (ErrConflict): it must never become a usable cookie.
	RotateSessionCookie(ctx context.Context, realm, userID, sessionID, cookieHash string) error
}
