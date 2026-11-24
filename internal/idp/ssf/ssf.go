// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package ssf is the OpenID Shared Signals Framework 1.0 transmitter: it turns
// things that happen to users (session ended, account disabled, credential
// changed ...) into signed Security Event Tokens (RFC 8417, ES256 with the
// realm keys), queues them in a durable outbox and pushes them to receivers
// (RFC 8935) with the same SSRF policy, retries and backoff as back-channel
// logout.
//
// A SET never contains a secret, a token or a credential: only an event type,
// a subject identifier (opaque id, email or iss+sub, per stream), a timestamp
// and event members documented in CAEP 1.0 / RISC 1.0.
package ssf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
)

// Event type URIs.
const (
	EvSessionRevoked       = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EvCredentialChange     = "https://schemas.openid.net/secevent/caep/event-type/credential-change"   // #nosec G101 -- SSF/CAEP/RISC event-type URIs, not credentials
	EvTokenClaimsChange    = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change" // #nosec G101 -- SSF/CAEP/RISC event-type URIs, not credentials
	EvAccountDisabled      = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EvAccountEnabled       = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	EvCredentialCompromise = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise" // #nosec G101 -- SSF/CAEP/RISC event-type URIs, not credentials
	// EvSessionsRevoked is deprecated in RISC 1.0 final (use CAEP
	// session-revoked) but still offered for receivers that ask for it.
	EvSessionsRevoked = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
	// EvVerification is the SSF verification event; it is always deliverable.
	EvVerification = "https://schemas.openid.net/secevent/ssf/event-type/verification"
)

// Supported lists the event types a stream can ask for (verification is
// implicit and not listed, per SSF 1.0).
var Supported = []string{
	EvSessionRevoked, EvCredentialChange, EvTokenClaimsChange,
	EvAccountDisabled, EvAccountEnabled, EvCredentialCompromise, EvSessionsRevoked,
}

// Delivery method and authorization scheme URNs.
const (
	MethodPush    = "urn:ietf:rfc:8935"
	SchemeRFC6750 = "urn:ietf:rfc:6750"
	// SETType is the JOSE "typ" of a SET (RFC 8417 section 2.3).
	SETType = "secevent+jwt"
)

// Subject identifier formats a stream may use.
const (
	FormatOpaque = "opaque"
	FormatEmail  = "email"
	FormatIssSub = "iss_sub"
)

// Token prefix and sizes.
const tokenPrefix = "hssf_"

// DefaultMinVerificationInterval is the transmitter's min_verification_interval (seconds).
const DefaultMinVerificationInterval = 30

// NewToken returns a fresh receiver token and its storage hash.
func NewToken() (plain, hash string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("ssf: entropy source failed: " + err.Error())
	}
	plain = tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return plain, HashToken(plain)
}

// HashToken is the storage form of a receiver token (sha256 hex; tokens carry
// 256 bits of entropy, so a fast hash is appropriate).
func HashToken(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

// IsSupported reports whether uri is a requestable event type.
func IsSupported(uri string) bool { return slices.Contains(Supported, uri) }

// Allowed returns the event types a receiver may be sent: its own list
// (restricted to supported ones) or all supported ones when empty.
func Allowed(r core.SSFReceiver) []string {
	if len(r.Events) == 0 {
		return slices.Clone(Supported)
	}
	var out []string
	for _, e := range Supported {
		if slices.Contains(r.Events, e) {
			out = append(out, e)
		}
	}
	return out
}

// Delivered computes events_delivered: requested (empty = everything) limited
// to what the receiver may get.
func Delivered(r core.SSFReceiver, requested []string) []string {
	allowed := Allowed(r)
	if len(requested) == 0 {
		// The deprecated RISC sessions-revoked is only sent when asked for.
		return slices.DeleteFunc(allowed, func(e string) bool { return e == EvSessionsRevoked })
	}
	out := []string{}
	for _, e := range allowed {
		if slices.Contains(requested, e) {
			out = append(out, e)
		}
	}
	return out
}

// CleanEvents validates a requested event list: known URIs only, no
// duplicates, bounded length.
func CleanEvents(in []string) ([]string, error) {
	if len(in) > len(Supported)*2 {
		return nil, errors.New("too many events")
	}
	out := make([]string, 0, len(in))
	for _, e := range in {
		if !IsSupported(e) && e != EvVerification {
			return nil, fmt.Errorf("unsupported event type")
		}
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out, nil
}

// ValidateEndpoint checks a push endpoint URL (https only, http for loopback
// in dev; no credentials, fragment or control characters). The IP policy is
// enforced again at dial time.
func ValidateEndpoint(raw string, allowPrivate bool) error {
	_, err := safehttp.ValidateURL(raw, allowPrivate, "endpoint_url", core.SSFMaxEndpointURL)
	return err
}

// ValidAuthHeader accepts a printable single-line header value.
func ValidAuthHeader(v string) bool {
	if len(v) == 0 || len(v) > core.SSFMaxAuthHeader {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return !strings.ContainsAny(v, "\r\n")
}

// ValidFormat reports whether f is a subject format.
func ValidFormat(f string) bool {
	return f == FormatOpaque || f == FormatEmail || f == FormatIssSub
}
