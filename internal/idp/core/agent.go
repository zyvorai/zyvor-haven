// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"errors"
	"time"
)

// Agent / MCP identities: a non-human actor (an AI agent, an MCP server)
// owned by a user. It holds scoped, short-lived, revocable credentials and
// obtains access tokens that act on behalf of the owner and carry an RFC 8693
// `act` claim naming the agent. See docs/agent-identities.md.

// Agent limits and defaults.
const (
	MaxAgentsPerRealm            = 1000
	MaxActiveCredentialsPerAgent = 5
	DefaultCredentialTTLSeconds  = 3600
	MaxCredentialTTLSeconds      = 7 * 24 * 3600
	DefaultAgentTokenTTLSeconds  = 300
	MaxAgentTokenTTLSeconds      = 900
	MaxAgentScopes               = 32
	MaxAgentAudiences            = 16
	// CredentialRetention is how long an ended credential row is kept for
	// audit before PurgeAgentCredentials deletes it.
	CredentialRetention = 30 * 24 * time.Hour
)

// ErrCredentialLimit: the agent already holds MaxActiveCredentialsPerAgent.
var ErrCredentialLimit = errors.New("idp: too many active credentials for this agent")

// Agent is a registered agent identity. Kind is always "agent"; the backing
// OAuth client (ClientID) is public, secretless and has no browser flows.
type Agent struct {
	ID            string
	Realm         string
	Name          string // unique per realm
	Kind          string // "agent"
	ClientID      string // generated, unique per realm
	OwnerUserID   string // the user the agent acts for
	AllowedScopes []string
	AllowedRoles  []string // realm roles the agent may carry; effective = these AND the owner's current roles
	Audiences     []string // allowed `audience` values; empty = only the agent's own client id
	TokenTTL      int      // seconds, <= MaxAgentTokenTTLSeconds
	Enabled       bool
	CreatedBy     string
	CreatedAt     time.Time
}

// AgentCredential is one revocable bearer credential of an agent. Only the
// sha256 of the secret is stored.
type AgentCredential struct {
	ID         string
	Realm      string
	AgentID    string
	SecretHash string
	Scopes     []string // subset of the agent's AllowedScopes
	Note       string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time // zero = not revoked
	RevokedBy  string
	LastUsedAt time.Time
}

// Active reports whether the credential can be used at now.
func (c AgentCredential) Active(now time.Time) bool {
	return c.RevokedAt.IsZero() && now.Before(c.ExpiresAt)
}

// EndedAt is when the credential stopped being usable.
func (c AgentCredential) EndedAt() time.Time {
	if !c.RevokedAt.IsZero() && c.RevokedAt.Before(c.ExpiresAt) {
		return c.RevokedAt
	}
	return c.ExpiresAt
}

// AgentStore is the optional store extension for agent identities; reach it
// with StoreAs[AgentStore]. Absent = feature off.
type AgentStore interface {
	// CreateAgent inserts a (ID/CreatedAt filled when empty). ErrConflict on a
	// duplicate name or client id; ErrNotFound when the realm does not exist.
	CreateAgent(ctx context.Context, a Agent) (Agent, error)
	GetAgent(ctx context.Context, realm, id string) (Agent, error)
	GetAgentByClient(ctx context.Context, realm, clientID string) (Agent, error)
	// ListAgents lists a realm's agents, filtered by owner when ownerID != "".
	ListAgents(ctx context.Context, realm, ownerID string) ([]Agent, error)
	SetAgentEnabled(ctx context.Context, realm, id string, enabled bool) (Agent, error)
	// DeleteAgent removes the agent and, atomically, all its credentials.
	DeleteAgent(ctx context.Context, realm, id string) error

	// CreateAgentCredential inserts c unless the agent already has maxActive
	// active credentials at now (ErrCredentialLimit); check+insert are atomic.
	// ErrNotFound when the agent does not exist in the realm.
	CreateAgentCredential(ctx context.Context, c AgentCredential, maxActive int, now time.Time) (AgentCredential, error)
	// GetAgentCredentialBySecret finds a credential by sha256(secret) within a
	// realm and agent; ErrNotFound if none. The caller checks Active.
	GetAgentCredentialBySecret(ctx context.Context, realm, agentID, secretHash string) (AgentCredential, error)
	ListAgentCredentials(ctx context.Context, realm, agentID string) ([]AgentCredential, error) // newest first
	// RevokeAgentCredential ends an active credential. ErrNotFound if absent;
	// ErrConflict if it already ended.
	RevokeAgentCredential(ctx context.Context, realm, agentID, id, by string, now time.Time) (AgentCredential, error)
	// RevokeAgentCredentials revokes every active credential of the agent and
	// returns how many.
	RevokeAgentCredentials(ctx context.Context, realm, agentID, by string, now time.Time) (int, error)
	// TouchAgentCredential records a use (best effort).
	TouchAgentCredential(ctx context.Context, realm, agentID, id string, now time.Time) error
	// PurgeAgentCredentials deletes credentials that ended before
	// now-CredentialRetention and returns how many.
	PurgeAgentCredentials(ctx context.Context, now time.Time) (int, error)
}
