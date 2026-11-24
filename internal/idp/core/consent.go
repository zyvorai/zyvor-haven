// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

// MCP clients and consent: OAuth Client ID Metadata Documents (CIMD), the
// consent screen for third-party / dynamically registered clients, remembered
// and revocable grants, hash-chained consent receipts and the client kill
// switch. See docs/mcp-clients-and-consent.md. This is a feature store: reach
// it with StoreAs[ConsentStore]; a store without it has the feature OFF.

// Consent limits and defaults.
const (
	ConsentDefaultGrantTTL = 90 * 24 * time.Hour
	ConsentMaxGrantTTL     = 365 * 24 * time.Hour
	MaxConsentSkipClients  = 100
	MaxConsentHosts        = 100
	MaxConsentScopes       = 32
	MaxConsentResources    = 16
	// ConsentClientCIMD marks a client materialised from a metadata document.
	ConsentClientCIMD = "cimd"
)

// Receipt types.
const (
	ReceiptGrant  = "grant"  // a user allowed a client (new or changed grant)
	ReceiptDeny   = "deny"   // a user refused at the consent screen
	ReceiptRevoke = "revoke" // a grant ended (user or admin)
	ReceiptKill   = "kill"   // kill switch pulled for a client / agent
	ReceiptUnkill = "unkill" // kill switch released
)

// ConsentPolicy is the per-realm policy. The zero policy (no row) is the safe
// default: CIMD off, consent for CIMD and dynamically registered clients only.
type ConsentPolicy struct {
	Realm string
	// CIMDEnabled lets https client_id URLs resolve through a metadata
	// document. Off by default.
	CIMDEnabled bool
	// CIMDHosts restricts which hosts a metadata document may be fetched from
	// (exact, lower-case). Empty = any public https host.
	CIMDHosts []string
	// RequireAll asks consent for every client (admin-created ones too), except
	// those in SkipClients. CIMD and dynamically registered clients are never
	// skippable.
	RequireAll  bool
	SkipClients []string
	// RememberCIMD lets a remembered grant skip the consent screen for CIMD
	// clients. Off (default): a CIMD client sees the consent screen on every
	// authorization, because anyone can publish a document. The grant is still
	// recorded, listed and revocable.
	RememberCIMD bool
	// GrantTTLSeconds is how long a remembered grant stays valid (0 = default).
	GrantTTLSeconds int
}

// GrantTTL returns the remembered-grant lifetime.
func (p ConsentPolicy) GrantTTL() time.Duration {
	if p.GrantTTLSeconds <= 0 {
		return ConsentDefaultGrantTTL
	}
	return time.Duration(p.GrantTTLSeconds) * time.Second
}

// ConsentClient is the side record of a client materialised from a Client ID
// Metadata Document. Its existence is what marks the client row as CIMD.
type ConsentClient struct {
	Realm        string
	ClientID     string // the metadata document URL
	Source       string // ConsentClientCIMD
	Name         string
	ClientURI    string
	RedirectURIs []string
	Fingerprint  string // ClientFingerprint at fetch time
	FetchedAt    time.Time
	ExpiresAt    time.Time // cache lifetime; refetched after this
}

// ConsentGrant is a user's remembered consent for one client. At most one
// active (not revoked, not expired) grant exists per (realm, user, client).
type ConsentGrant struct {
	ID          string
	Realm       string
	UserID      string
	ClientID    string
	ClientName  string // as shown at consent time
	Scopes      []string
	Resources   []string
	Fingerprint string // client identity the user consented to; a change re-asks
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   time.Time // zero = active
	RevokedBy   string
}

// Active reports whether the grant can be used at now.
func (g ConsentGrant) Active(now time.Time) bool {
	return g.RevokedAt.IsZero() && now.Before(g.ExpiresAt)
}

// Covers reports whether the grant already includes every scope and resource.
func (g ConsentGrant) Covers(scopes, resources []string) bool {
	for _, s := range scopes {
		if !slices.Contains(g.Scopes, s) {
			return false
		}
	}
	for _, r := range resources {
		if !slices.Contains(g.Resources, r) {
			return false
		}
	}
	return true
}

// ConsentBlock is a kill-switch record: while it exists the client cannot start
// new authorizations and a CIMD client is not re-resolved.
type ConsentBlock struct {
	Realm    string
	ClientID string
	Reason   string
	By       string
	At       time.Time
}

// ConsentReceipt is one append-only, hash-chained record of a consent event.
// The chain is per realm: Seq counts from 1 and PrevHash is the Hash of the
// previous receipt ("" for the first), so removing or editing a row breaks
// every later hash. It holds no secrets and no tokens.
type ConsentReceipt struct {
	Realm      string
	Seq        int64
	Time       time.Time
	Type       string
	UserID     string // the consenting / affected user; "" for client-wide events
	ClientID   string
	ClientName string
	Scopes     []string
	Resources  []string
	Actor      string // user id, or "admin:<subject>" for admin actions
	Detail     string
	PrevHash   string
	Hash       string
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ConsentReceiptHash computes the hash a receipt must carry.
func ConsentReceiptHash(r ConsentReceipt) string {
	b, _ := json.Marshal([]any{r.PrevHash, r.Realm, r.Seq, r.Time.UTC().UnixMicro(), r.Type, r.UserID,
		r.ClientID, r.ClientName, nz(r.Scopes), nz(r.Resources), r.Actor, r.Detail})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ErrReceiptChain: the receipt chain does not verify.
var ErrReceiptChain = errors.New("idp: consent receipt chain is broken")

// VerifyConsentChain checks consecutive receipts: sequence numbers, links and
// hashes. prevSeq/prevHash describe the receipt before rs[0] (0, "" at the
// start of a realm's chain).
func VerifyConsentChain(rs []ConsentReceipt, prevSeq int64, prevHash string) error {
	for _, r := range rs {
		if r.Seq != prevSeq+1 || r.PrevHash != prevHash || r.Hash != ConsentReceiptHash(r) {
			return fmt.Errorf("%w at seq %d", ErrReceiptChain, r.Seq)
		}
		prevSeq, prevHash = r.Seq, r.Hash
	}
	return nil
}

// ClientFingerprint identifies what a user consented to: the client id, its
// display name and its exact redirect URIs. If a metadata document changes any
// of them, remembered grants stop applying.
func ClientFingerprint(clientID, name string, redirectURIs []string) string {
	u := slices.Clone(redirectURIs)
	sort.Strings(u)
	b, _ := json.Marshal([]any{clientID, name, nz(u)})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ConsentStore persists the consent feature. All methods are scoped by realm.
type ConsentStore interface {
	// GetConsentPolicy returns ErrNotFound when none was set.
	GetConsentPolicy(ctx context.Context, realm string) (ConsentPolicy, error)
	PutConsentPolicy(ctx context.Context, p ConsentPolicy) error

	// PutConsentClient upserts the CIMD side record.
	PutConsentClient(ctx context.Context, c ConsentClient) error
	GetConsentClient(ctx context.Context, realm, clientID string) (ConsentClient, error)
	ListConsentClients(ctx context.Context, realm string) ([]ConsentClient, error)

	// PutConsentGrant stores g as the active grant of (realm, user, client):
	// an existing active grant is replaced in place (ID and CreatedAt kept).
	// ID and CreatedAt are filled when empty.
	PutConsentGrant(ctx context.Context, g ConsentGrant, now time.Time) (ConsentGrant, error)
	// GetActiveConsentGrant returns ErrNotFound unless an active grant exists.
	GetActiveConsentGrant(ctx context.Context, realm, userID, clientID string, now time.Time) (ConsentGrant, error)
	GetConsentGrant(ctx context.Context, realm, id string) (ConsentGrant, error)
	// ListConsentGrants lists newest first. userID / clientID "" = any; ended
	// grants (revoked or expired) only when includeEnded.
	ListConsentGrants(ctx context.Context, realm, userID, clientID string, includeEnded bool, now time.Time, limit int) ([]ConsentGrant, error)
	// RevokeConsentGrant ends an active grant (ErrNotFound if absent,
	// ErrConflict if already revoked).
	RevokeConsentGrant(ctx context.Context, realm, id, by string, now time.Time) (ConsentGrant, error)
	// RevokeClientConsentGrants ends every active grant of a client.
	RevokeClientConsentGrants(ctx context.Context, realm, clientID, by string, now time.Time) (int, error)

	// RevokeClientRefreshTokens revokes every refresh token issued to a client
	// (userID "" = all users) and returns how many were newly revoked.
	RevokeClientRefreshTokens(ctx context.Context, realm, clientID, userID string) (int, error)

	// Kill switch records.
	PutConsentBlock(ctx context.Context, b ConsentBlock) error
	GetConsentBlock(ctx context.Context, realm, clientID string) (ConsentBlock, error)
	DeleteConsentBlock(ctx context.Context, realm, clientID string) error
	ListConsentBlocks(ctx context.Context, realm string) ([]ConsentBlock, error)

	// AppendConsentReceipt atomically assigns Seq, PrevHash and Hash (and Time
	// when zero) and appends r. Receipts are never updated or deleted, except
	// with their realm.
	AppendConsentReceipt(ctx context.Context, r ConsentReceipt) (ConsentReceipt, error)
	// ListConsentReceipts returns receipts with Seq > afterSeq in ascending
	// order. userID "" = all.
	ListConsentReceipts(ctx context.Context, realm, userID string, afterSeq int64, limit int) ([]ConsentReceipt, error)
	// HeadConsentReceipt returns the latest receipt (ErrNotFound when none).
	HeadConsentReceipt(ctx context.Context, realm string) (ConsentReceipt, error)
}

// KillResult says what a kill-switch pull did.
type KillResult struct {
	ClientID       string `json:"clientId"`
	ClientDisabled bool   `json:"clientDisabled"`
	GrantsRevoked  int    `json:"grantsRevoked"`
	RefreshRevoked int    `json:"refreshTokensRevoked"`
	AgentDisabled  bool   `json:"agentDisabled"`
	CredentialsEnd int    `json:"agentCredentialsRevoked"`
	ReceiptSeq     int64  `json:"receiptSeq"`
}

// KillClient pulls the kill switch for a client (and the agent behind it, when
// the client belongs to an agent): it blocks the client, disables its client
// row, revokes every remembered grant and refresh token, and disables the
// agent and revokes its credentials. Access tokens already issued stay valid
// until they expire (at most the realm's access token TTL). Idempotent. On a
// partial failure it keeps going and returns the first error with the result
// of what did happen.
func KillClient(ctx context.Context, st Store, cs ConsentStore, realm, clientID, by, reason string, now time.Time) (KillResult, error) {
	res := KillResult{ClientID: clientID}
	// The block goes first: it alone stops new authorizations.
	if err := cs.PutConsentBlock(ctx, ConsentBlock{Realm: realm, ClientID: clientID, Reason: reason, By: by, At: now}); err != nil {
		return res, err
	}
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	if cl, err := st.GetClientByClientID(ctx, realm, clientID); err == nil {
		if cl.Enabled {
			cl.Enabled = false
			keep(st.UpdateClient(ctx, cl))
		}
		res.ClientDisabled = true
	}
	n, err := cs.RevokeClientConsentGrants(ctx, realm, clientID, by, now)
	keep(err)
	res.GrantsRevoked = n
	n, err = cs.RevokeClientRefreshTokens(ctx, realm, clientID, "")
	keep(err)
	res.RefreshRevoked = n
	name := ""
	if as, ok := StoreAs[AgentStore](st); ok {
		if ag, err := as.GetAgentByClient(ctx, realm, clientID); err == nil {
			name = ag.Name
			if _, err := as.SetAgentEnabled(ctx, realm, ag.ID, false); err == nil {
				res.AgentDisabled = true
			} else {
				keep(err)
			}
			n, err := as.RevokeAgentCredentials(ctx, realm, ag.ID, by, now)
			keep(err)
			res.CredentialsEnd = n
		}
	}
	rc, err := cs.AppendConsentReceipt(ctx, ConsentReceipt{Realm: realm, Time: now, Type: ReceiptKill, ClientID: clientID,
		ClientName: name, Actor: by, Detail: reason})
	keep(err)
	res.ReceiptSeq = rc.Seq
	return res, first
}

// UnkillClient releases the kill switch: it removes the block and re-enables
// the client row. It does NOT restore grants, tokens, or a disabled agent.
func UnkillClient(ctx context.Context, st Store, cs ConsentStore, realm, clientID, by string, now time.Time) error {
	if err := cs.DeleteConsentBlock(ctx, realm, clientID); err != nil {
		return err
	}
	if cl, err := st.GetClientByClientID(ctx, realm, clientID); err == nil && !cl.Enabled {
		cl.Enabled = true
		if err := st.UpdateClient(ctx, cl); err != nil {
			return err
		}
	}
	_, err := cs.AppendConsentReceipt(ctx, ConsentReceipt{Realm: realm, Time: now, Type: ReceiptUnkill, ClientID: clientID, Actor: by})
	return err
}

// RevokeConsent ends one grant completely: the grant itself, the user's
// refresh tokens for that client, and a receipt. actor is the user id (self
// service) or "admin:<subject>". ErrConflict when the grant already ended. The
// caller has checked who may revoke what.
func RevokeConsent(ctx context.Context, cs ConsentStore, g ConsentGrant, actor string, now time.Time) (ConsentGrant, error) {
	rg, err := cs.RevokeConsentGrant(ctx, g.Realm, g.ID, actor, now)
	if err != nil {
		return rg, err
	}
	if _, err := cs.RevokeClientRefreshTokens(ctx, g.Realm, g.ClientID, g.UserID); err != nil {
		return rg, err
	}
	_, err = cs.AppendConsentReceipt(ctx, ConsentReceipt{Realm: g.Realm, Time: now, Type: ReceiptRevoke, UserID: g.UserID,
		ClientID: g.ClientID, ClientName: g.ClientName, Scopes: g.Scopes, Resources: g.Resources, Actor: actor})
	return rg, err
}
