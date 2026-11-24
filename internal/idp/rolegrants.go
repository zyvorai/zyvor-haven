// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import "time"

// RoleGrant is a time-boxed role assignment as the Admin API reports it.
type RoleGrant struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`
	Role      string     `json:"role"`
	GrantedBy string     `json:"grantedBy"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	RevokedBy string     `json:"revokedBy,omitempty"`
	// State is "active", "expired" or "revoked" at the time of the call.
	State string `json:"state"`
}

// RoleGrantRequest creates a grant. Exactly one of ExpiresAt and
// DurationSeconds must be set.
type RoleGrantRequest struct {
	Role            string     `json:"role"`
	ExpiresAt       *time.Time `json:"expiresAt,omitempty"`
	DurationSeconds int        `json:"durationSeconds,omitempty"`
	Reason          string     `json:"reason,omitempty"`
}
