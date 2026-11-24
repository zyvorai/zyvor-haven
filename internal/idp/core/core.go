// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package core holds the domain types and storage contract of Haven's own
// identity server (haven-idp). The OIDC handlers, the admin API and the
// storage backends all meet here; none of them import each other.
package core

import (
	"context"
	"time"
)

// Realm is a tenant: its users, clients and signing keys are isolated.
type Realm struct {
	ID          string // opaque UUID
	Name        string // URL-safe slug, unique
	DisplayName string
	Enabled     bool

	SelfRegistration          bool
	EmailVerificationRequired bool
	BruteForceProtection      bool
	TransportSecurity         string // "none" | "external" | "all"
	PasswordPolicy            string // e.g. "length(12) and digits(1)"
	AccessTokenTTL            time.Duration
	RefreshTokenTTL           time.Duration
	SessionIdleTTL            time.Duration
	AuthEventsLogged          bool
	AdminEventsLogged         bool
	RefreshTokenRotation      bool

	CreatedAt time.Time
}

// User is an account. PasswordHash is a PHC-format argon2id string.
type User struct {
	ID             string
	Realm          string // realm name
	Username       string // unique per realm, case-insensitive
	Email          string
	FirstName      string
	LastName       string
	Enabled        bool
	EmailVerified  bool
	PendingActions []string
	PasswordHash   string // empty = no local password
	Roles          []string
	Groups         []string // group paths
	FailedLogins   int
	LockedUntil    time.Time // zero = not locked
	CreatedAt      time.Time
}

// Client is an OAuth2/OIDC application.
type Client struct {
	ID             string // opaque UUID
	Realm          string
	ClientID       string // unique per realm
	Name           string
	Enabled        bool
	Public         bool
	SecretHash     string // sha256 hex of the secret; empty for public clients
	RedirectURIs   []string
	Origins        []string
	AuthCodeFlow   bool
	PasswordFlow   bool
	ServiceAccount bool
	RequirePKCE    bool
	CreatedAt      time.Time
}

// Role and Group are realm-scoped names/paths.
type Role struct {
	ID          string
	Realm       string
	Name        string
	Description string
}

type Group struct {
	ID    string
	Realm string
	Name  string
	Path  string
}

// SigningKey is a realm's JWT signing key. PrivatePEM is PKCS#8; the store
// treats it as an opaque secret.
type SigningKey struct {
	KID        string
	Realm      string
	Alg        string // "ES256"
	PrivatePEM []byte
	PublicJWK  []byte    // JSON JWK, safe to publish
	Active     bool      // signs new tokens
	NotAfter   time.Time // zero = published until deleted
	CreatedAt  time.Time
}

// AuthCode is a single-use authorization code bound to a PKCE challenge.
type AuthCode struct {
	CodeHash      string // sha256 hex of the code
	Realm         string
	ClientID      string
	UserID        string
	RedirectURI   string
	Scope         string
	Nonce         string
	CodeChallenge string
	ChallengeMeth string // "S256"
	AuthTime      time.Time
	ExpiresAt     time.Time
}

// RefreshToken is stored hashed. FamilyID links a rotation chain so reuse of
// an already-rotated token revokes the whole family.
type RefreshToken struct {
	TokenHash string
	FamilyID  string
	Realm     string
	ClientID  string
	UserID    string // empty for client_credentials
	Scope     string
	Used      bool
	Revoked   bool
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Action token purposes.
const (
	ActionVerifyEmail   = "verify_email"
	ActionResetPassword = "reset_password"
)

// ActionToken is a single-use, emailed capability (verify an address, reset a
// password). Only the sha256 hex of the token is stored. Email is the address
// the token was issued to: a verify token stops working if the user's address
// changed since, and a reset token is only ever sent to the address on file.
type ActionToken struct {
	TokenHash string
	Realm     string
	UserID    string
	Purpose   string // ActionVerifyEmail | ActionResetPassword
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Event is an audit record (login, admin change).
type Event struct {
	Time     time.Time
	Realm    string
	Type     string // "LOGIN", "LOGIN_ERROR", "ADMIN_CREATE", ...
	UserID   string
	ClientID string
	IP       string
	Detail   string // never contains secrets
}

// Store is the persistence contract. Errors use idp.ErrNotFound for missing
// rows and idp.ErrConflict for unique violations. All methods must be safe for
// concurrent use. Implementations: store/memstore, store/pgstore.
type Store interface {
	// Realms
	CreateRealm(ctx context.Context, r Realm) error
	GetRealm(ctx context.Context, name string) (Realm, error)
	ListRealms(ctx context.Context) ([]Realm, error)
	UpdateRealm(ctx context.Context, r Realm) error
	DeleteRealm(ctx context.Context, name string) error

	// Users (Username lookups are case-insensitive)
	CreateUser(ctx context.Context, u User) error // fills ID/CreatedAt if empty
	GetUser(ctx context.Context, realm, id string) (User, error)
	GetUserByUsername(ctx context.Context, realm, username string) (User, error)
	ListUsers(ctx context.Context, realm, search string, offset, limit int) ([]User, error)
	UpdateUser(ctx context.Context, u User) error
	DeleteUser(ctx context.Context, realm, id string) error

	// Clients
	CreateClient(ctx context.Context, c Client) error
	GetClient(ctx context.Context, realm, id string) (Client, error)
	GetClientByClientID(ctx context.Context, realm, clientID string) (Client, error)
	ListClients(ctx context.Context, realm string) ([]Client, error)
	UpdateClient(ctx context.Context, c Client) error
	DeleteClient(ctx context.Context, realm, id string) error

	// Roles and groups
	CreateRole(ctx context.Context, r Role) error
	ListRoles(ctx context.Context, realm string) ([]Role, error)
	CreateGroup(ctx context.Context, g Group) error
	ListGroups(ctx context.Context, realm string) ([]Group, error)

	// Signing keys
	PutSigningKey(ctx context.Context, k SigningKey) error
	ListSigningKeys(ctx context.Context, realm string) ([]SigningKey, error) // active first

	// Authorization codes: ConsumeAuthCode returns the code and deletes it
	// atomically; a second call returns idp.ErrNotFound.
	PutAuthCode(ctx context.Context, c AuthCode) error
	ConsumeAuthCode(ctx context.Context, codeHash string) (AuthCode, error)

	// Refresh tokens
	PutRefreshToken(ctx context.Context, t RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (RefreshToken, error)
	// MarkRefreshUsed atomically flips Used false->true; it returns
	// idp.ErrConflict if it was already used (reuse detection).
	MarkRefreshUsed(ctx context.Context, tokenHash string) error
	RevokeRefreshFamily(ctx context.Context, familyID string) error

	// RevokeUserRefreshTokens revokes every refresh token of a user (used
	// after a password reset). Returns the number revoked.
	RevokeUserRefreshTokens(ctx context.Context, realm, userID string) (int, error)

	// Action tokens: ConsumeActionToken returns the token and deletes it
	// atomically; a second call returns idp.ErrNotFound. Expiry is checked by
	// the caller, the store only deletes (PurgeExpired removes stale rows).
	PutActionToken(ctx context.Context, t ActionToken) error
	ConsumeActionToken(ctx context.Context, tokenHash string) (ActionToken, error)
	// DeleteActionTokens removes every outstanding token of a user for a
	// purpose (issuing a new one or changing the password invalidates the
	// rest). Returns the number removed.
	DeleteActionTokens(ctx context.Context, realm, userID, purpose string) (int, error)
	// CountActionTokens counts tokens of a user for a purpose created at or
	// after since: used to rate-limit emails per user.
	CountActionTokens(ctx context.Context, realm, userID, purpose string, since time.Time) (int, error)

	// Events
	AppendEvent(ctx context.Context, e Event) error
	ListEvents(ctx context.Context, realm string, limit int) ([]Event, error) // newest first

	// HitRateLimit atomically records one hit for key in a fixed window and
	// reports whether it is within max hits per window. A window starts at the
	// first hit after the previous one ended and lasts window; hits beyond max
	// are denied until it ends. key is opaque: callers hash it so raw
	// identifiers (IPs) are never stored. Shared across replicas.
	HitRateLimit(ctx context.Context, key string, now time.Time, window time.Duration, max int) (allowed bool, err error)

	// Housekeeping: delete expired codes/tokens (incl. action tokens) and
	// finished rate-limit windows, returns rows removed.
	PurgeExpired(ctx context.Context, now time.Time) (int, error)
}
