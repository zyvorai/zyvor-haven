// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// SCIMToken is the single bearer credential of a realm's SCIM 2.0 endpoint.
// Only the sha256 hex of the token is stored. RealmID is the realm's opaque
// UUID at the time the token was issued: a realm that is deleted and created
// again under the same name does not inherit the old token.
type SCIMToken struct {
	Realm     string
	RealmID   string
	TokenHash string // sha256 hex
	ReadOnly  bool   // GET only
	CreatedBy string // admin actor, for audit
	CreatedAt time.Time
}

// SCIMStore is the optional storage behind the SCIM server. Stores that do not
// implement it (see StoreAs) simply do not offer SCIM.
type SCIMStore interface {
	// PutSCIMToken stores the realm's token, replacing any previous one (rotation).
	PutSCIMToken(ctx context.Context, t SCIMToken) error
	// GetSCIMToken returns idp.ErrNotFound when the realm has no token.
	GetSCIMToken(ctx context.Context, realm string) (SCIMToken, error)
	// DeleteSCIMToken revokes the token; idp.ErrNotFound when there is none.
	DeleteSCIMToken(ctx context.Context, realm string) error

	// SetSCIMExternalID records the provisioning client's externalId for a
	// user ("" removes it). An id already held by another user of the realm
	// is idp.ErrConflict.
	SetSCIMExternalID(ctx context.Context, realm, userID, externalID string) error
	// SCIMExternalIDs returns externalId by user id for the given users (users
	// without one are absent). An empty ids slice returns every user's.
	SCIMExternalIDs(ctx context.Context, realm string, ids []string) (map[string]string, error)
	// FindSCIMExternalID returns the user id holding externalID
	// (idp.ErrNotFound when none).
	FindSCIMExternalID(ctx context.Context, realm, externalID string) (string, error)
}
