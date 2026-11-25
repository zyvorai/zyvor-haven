// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Authentication context (amr, acr) and step-up (RFC 9470). See
// docs/step-up-acr.md. The amr of a login lists what haven-idp itself observed;
// the acr is derived from the amr with the realm's ACRPolicy and is never
// stored as a fact of its own.

// Authentication method references. pwd, otp, user and mfa are registered in
// RFC 8176; the others are private values (no registered value says the same
// thing without claiming more than was observed).
const (
	AMRPassword  = "pwd"      // the local password was verified
	AMROTP       = "otp"      // a TOTP code (RFC 6238) was verified
	AMRRecovery  = "recovery" // a one-time recovery code was spent
	AMRWebAuthn  = "webauthn" // a passkey assertion was verified (hardware or synced: not known)
	AMRUser      = "user"     // the authenticator reported user presence
	AMRUV        = "uv"       // the authenticator reported user verification (PIN, biometric: not known which)
	AMRFederated = "fed"      // an upstream identity provider authenticated the user; how is not known
	AMRMFA       = "mfa"      // two factors: password plus one of the above, or a passkey with user verification
)

var knownAMR = []string{AMRPassword, AMROTP, AMRRecovery, AMRWebAuthn, AMRUser, AMRUV, AMRFederated, AMRMFA}

// Default acr values, weakest first.
const (
	ACRSingleFactor      = "urn:haven:acr:1fa"
	ACRMultiFactor       = "urn:haven:acr:mfa"
	ACRPhishingResistant = "urn:haven:acr:phr"
)

// ACR ladder limits.
const (
	MaxACRLevels       = 10
	MaxACRAlternatives = 16
	MaxACRValueLen     = 128
	MaxACRMaxAge       = 366 * 24 * time.Hour
)

// ACRLevel is one rung: the acr value and the method combinations that reach
// it. A level is reached when the login's amr contains every value of at least
// one alternative.
type ACRLevel struct {
	Value string     `json:"acr"`
	AnyOf [][]string `json:"anyOf"`
}

// ACRPolicy is the per-realm acr ladder, weakest level first. Reaching a level
// satisfies every level below it.
type ACRPolicy struct {
	Levels []ACRLevel `json:"levels"`
	// EnrollOnStepUp lets a user who has NO second factor at all set up TOTP
	// during a login that needs a higher level. Off by default: whoever knows
	// only the password could otherwise add their own authenticator and obtain
	// a "multi factor" token.
	EnrollOnStepUp bool `json:"enrollOnStepUp"`
	// AdminACR, when set on the Admin API's realm, is the level a USER token
	// must meet on the Admin API (RFC 9470 challenge otherwise). Service
	// account tokens carry no user authentication and are not affected.
	AdminACR string `json:"adminAcr,omitempty"`
	// AdminMaxAge, when above zero, additionally requires the authentication
	// behind a user token on the Admin API to be at most this old.
	AdminMaxAgeSeconds int64 `json:"adminMaxAgeSeconds,omitempty"`
}

// DefaultACRPolicy is the ladder of a realm that never set one.
func DefaultACRPolicy() ACRPolicy {
	return ACRPolicy{Levels: []ACRLevel{
		{Value: ACRSingleFactor, AnyOf: [][]string{{AMRPassword}, {AMRFederated}, {AMRWebAuthn}}},
		{Value: ACRMultiFactor, AnyOf: [][]string{{AMRMFA}}},
		{Value: ACRPhishingResistant, AnyOf: [][]string{{AMRWebAuthn, AMRMFA}}},
	}}
}

// Clone returns a deep copy.
func (p ACRPolicy) Clone() ACRPolicy {
	if p.Levels == nil {
		return p
	}
	ls := make([]ACRLevel, len(p.Levels))
	for i, l := range p.Levels {
		alts := make([][]string, len(l.AnyOf))
		for j, a := range l.AnyOf {
			alts[j] = slices.Clone(a)
		}
		ls[i] = ACRLevel{Value: l.Value, AnyOf: alts}
	}
	p.Levels = ls
	return p
}

// ValidACRValue reports whether v can be used as an acr value. Quotes and
// backslashes are refused because values appear in WWW-Authenticate headers.
func ValidACRValue(v string) bool {
	if v == "" || len(v) > MaxACRValueLen {
		return false
	}
	return !strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r > '~' || r == '"' || r == '\\' })
}

// Validate checks a ladder.
func (p ACRPolicy) Validate() error {
	if len(p.Levels) == 0 || len(p.Levels) > MaxACRLevels {
		return fmt.Errorf("between 1 and %d levels are required", MaxACRLevels)
	}
	seen := map[string]bool{}
	for _, l := range p.Levels {
		if !ValidACRValue(l.Value) {
			return errors.New("an acr value must be 1 to 128 printable ASCII characters without spaces, quotes or backslashes")
		}
		if seen[l.Value] {
			return fmt.Errorf("acr value %q appears twice", l.Value)
		}
		seen[l.Value] = true
		if len(l.AnyOf) == 0 || len(l.AnyOf) > MaxACRAlternatives {
			return fmt.Errorf("level %q needs between 1 and %d alternatives in anyOf", l.Value, MaxACRAlternatives)
		}
		for _, alt := range l.AnyOf {
			// An empty alternative would be reached by a login with no method.
			if len(alt) == 0 || len(alt) > len(knownAMR) {
				return fmt.Errorf("level %q: an alternative must list at least one method", l.Value)
			}
			for _, m := range alt {
				if !slices.Contains(knownAMR, m) {
					return fmt.Errorf("level %q: unknown method %q (known: %s)", l.Value, m, strings.Join(knownAMR, " "))
				}
			}
		}
	}
	if p.AdminACR != "" && !seen[p.AdminACR] {
		return errors.New("adminAcr must be one of the levels")
	}
	if p.AdminMaxAgeSeconds < 0 || p.AdminMaxAgeSeconds > int64(MaxACRMaxAge/time.Second) {
		return errors.New("adminMaxAgeSeconds must be between 0 and one year")
	}
	return nil
}

// Index is the rank of an acr value, -1 when the ladder does not have it.
func (p ACRPolicy) Index(value string) int {
	return slices.IndexFunc(p.Levels, func(l ACRLevel) bool { return l.Value == value })
}

// Rank is the highest level the methods reach, -1 for none.
func (p ACRPolicy) Rank(amr []string) int {
	for i := len(p.Levels) - 1; i >= 0; i-- {
		for _, alt := range p.Levels[i].AnyOf {
			if len(alt) > 0 && !slices.ContainsFunc(alt, func(m string) bool { return !slices.Contains(amr, m) }) {
				return i
			}
		}
	}
	return -1
}

// Meets reports whether the methods reach the level named value (or a higher
// one). An unknown value is never met.
func (p ACRPolicy) Meets(amr []string, value string) bool {
	i := p.Index(value)
	return i >= 0 && p.Rank(amr) >= i
}

// ACRRequirement is what an authorization request demands. Every set must be
// satisfied by one of its values, listed in order of preference; an empty set
// demands some level, whichever.
type ACRRequirement struct {
	Sets [][]string
}

// Empty reports that nothing is demanded.
func (r ACRRequirement) Empty() bool { return len(r.Sets) == 0 }

// Satisfiable reports whether any login at all could meet r under this ladder.
func (p ACRPolicy) Satisfiable(r ACRRequirement) bool {
	for _, set := range r.Sets {
		if len(p.Levels) == 0 || (len(set) > 0 && !slices.ContainsFunc(set, func(v string) bool { return p.Index(v) >= 0 })) {
			return false
		}
	}
	return true
}

// Select decides whether a login with these methods meets r and which acr the
// tokens report: the first met value of the first set that names values, else
// the highest level reached ("" when none is). ok=false: the requirement is
// not met and nothing may be issued.
func (p ACRPolicy) Select(amr []string, r ACRRequirement) (acr string, ok bool) {
	rank := p.Rank(amr)
	for _, set := range r.Sets {
		chosen := ""
		for _, v := range set {
			if i := p.Index(v); i >= 0 && i <= rank {
				chosen = v
				break
			}
		}
		if len(set) == 0 {
			if rank < 0 {
				return "", false
			}
			continue
		}
		if chosen == "" {
			return "", false
		}
		if acr == "" {
			acr = chosen
		}
	}
	if acr == "" && rank >= 0 {
		acr = p.Levels[rank].Value
	}
	return acr, true
}

// SessionAuthn records how the user of an SSO session authenticated. It is
// written once, when the session is created, and never changed.
type SessionAuthn struct {
	Realm     string
	SessionID string
	AMR       []string
}

// AuthnStore is the optional store feature behind amr/acr. A store without it
// leaves the feature off: no amr or acr claims, and any request that demands
// an acr fails.
type AuthnStore interface {
	// GetACRPolicy returns idp.ErrNotFound when the realm never set one (the
	// caller then uses DefaultACRPolicy).
	GetACRPolicy(ctx context.Context, realm string) (ACRPolicy, error)
	// PutACRPolicy replaces the realm's ladder; the realm must exist.
	PutACRPolicy(ctx context.Context, realm string, p ACRPolicy) error
	// DeleteACRPolicy returns the realm to the default (idempotent).
	DeleteACRPolicy(ctx context.Context, realm string) error

	// PutSessionAuthn records a session's methods. idp.ErrNotFound when the
	// session does not exist in the realm, idp.ErrConflict when the session
	// already has a record (it is immutable).
	PutSessionAuthn(ctx context.Context, a SessionAuthn) error
	// GetSessionAuthn returns idp.ErrNotFound when there is no record or the
	// session is gone: records die with their session.
	GetSessionAuthn(ctx context.Context, realm, sessionID string) (SessionAuthn, error)
}
