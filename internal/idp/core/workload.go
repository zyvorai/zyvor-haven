// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"regexp"
	"time"
)

// Workload identity: a registered workload client (no secret) exchanges a
// platform-issued JWT (for example a Kubernetes projected service-account
// token) for a short-lived Haven access token. One WorkloadIdentity pins ONE
// issuer, ONE audience and ONE subject to ONE client; nothing is matched by
// pattern. See docs/workload-identity.md.

// Workload limits.
const (
	MaxWorkloadsPerRealm      = 500
	DefaultWorkloadTTLSeconds = 600
	MaxWorkloadTTLSeconds     = 3600
	MaxWorkloadScopes         = 32
	MaxWorkloadJWKSBytes      = 64 << 10
)

// ScopeRE is the shape of one scope allowed on workload and agent identities.
// It deliberately excludes space, so a scope can never smuggle a second one.
var ScopeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/-]{0,63}$`)

// WorkloadIdentity binds a trusted external token (issuer, audience, subject,
// all exact) to a Haven client. Exactly one of JWKSURI and JWKS is set.
type WorkloadIdentity struct {
	ID            string
	Realm         string
	Name          string // unique per realm
	ClientID      string // the registered workload client (public, no flows); unique per realm
	Issuer        string // exact iss of the external token
	JWKSURI       string // https URL of the issuer's keys (fetched through safehttp)
	JWKS          string // inline JWKS JSON (alternative to JWKSURI; for private cluster issuers)
	Audience      string // the external token's aud must contain exactly this
	Subject       string // the external token's sub must equal exactly this
	AllowedScopes []string
	TTLSeconds    int // lifetime of the issued Haven token
	Enabled       bool
	CreatedBy     string
	CreatedAt     time.Time
}

// WorkloadStore is the optional store extension for workload identities;
// reach it with StoreAs[WorkloadStore]. Absent = feature off.
type WorkloadStore interface {
	// CreateWorkloadIdentity inserts w (ID/CreatedAt filled when empty).
	// ErrConflict when the name or the client is already bound in the realm;
	// ErrNotFound when the realm does not exist.
	CreateWorkloadIdentity(ctx context.Context, w WorkloadIdentity) (WorkloadIdentity, error)
	GetWorkloadIdentity(ctx context.Context, realm, id string) (WorkloadIdentity, error)
	GetWorkloadIdentityByClient(ctx context.Context, realm, clientID string) (WorkloadIdentity, error)
	ListWorkloadIdentities(ctx context.Context, realm string) ([]WorkloadIdentity, error)
	SetWorkloadEnabled(ctx context.Context, realm, id string, enabled bool) (WorkloadIdentity, error)
	DeleteWorkloadIdentity(ctx context.Context, realm, id string) error
}
