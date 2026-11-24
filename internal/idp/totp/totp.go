// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package totp implements HOTP (RFC 4226) and TOTP (RFC 6238) with the standard
// library only, plus the helpers an authenticator-app enrollment needs: random
// seeds, base32 text, otpauth:// URIs and single-use recovery codes.
//
// The defaults are what every authenticator app supports: HMAC-SHA1, 6 digits,
// 30 second steps. Verify accepts one step of clock skew in either direction
// and never accepts a step that was already used (replay protection is the
// caller's job to persist: Verify takes the last used step and returns the
// matched one).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is the TOTP default (RFC 6238); it is not used as a collision-resistant hash.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the code length used for enrollment and verification.
	Digits = 6
	// Period is the step length in seconds.
	Period = 30
	// SeedSize is the seed length in bytes (160 bits, RFC 4226 section 4).
	SeedSize = 20
	// Skew is how many steps before and after the current one are accepted.
	Skew = 1
)

// Algorithm is the HMAC hash. Authenticator apps only reliably support SHA1,
// which is the only one Verify uses; the others exist for the RFC 6238 vectors.
type Algorithm int

// Supported HMAC hashes.
const (
	SHA1 Algorithm = iota
	SHA256
	SHA512
)

func (a Algorithm) hash() func() hash.Hash {
	switch a {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// HOTP computes the RFC 4226 value for a counter. digits must be 1..9.
func HOTP(alg Algorithm, secret []byte, counter uint64, digits int) string {
	if digits < 1 || digits > 9 {
		panic("totp: digits must be 1..9")
	}
	m := hmac.New(alg.hash(), secret)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], counter)
	m.Write(c[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// StepAt returns the time-step counter of t (seconds since the epoch / 30).
// Times before the epoch are step 0.
func StepAt(t time.Time) int64 {
	s := t.Unix()
	if s < 0 {
		return 0
	}
	return s / Period
}

// Code returns the current 6-digit SHA1 code for the time t.
func Code(secret []byte, t time.Time) string {
	return HOTP(SHA1, secret, uint64(StepAt(t)), Digits)
}

// CodeAt returns the code of an explicit step.
func CodeAt(secret []byte, step int64) string {
	return HOTP(SHA1, secret, uint64(step), Digits)
}

// NormalizeCode strips the spaces and hyphens people type into a code box.
// It returns false unless the result is exactly Digits ASCII digits.
func NormalizeCode(s string) (string, bool) {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ' || r == '-' || r == '\t':
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			return "", false
		}
		if b.Len() > Digits {
			return "", false
		}
	}
	if b.Len() != Digits {
		return "", false
	}
	return b.String(), true
}

// Verify checks code against the steps now-Skew..now+Skew. A step at or below
// lastUsedStep never matches (a code may be used once). On success it returns
// the matched step, which the caller must store atomically as the new
// lastUsedStep before accepting the login. All candidate steps are always
// computed and compared in constant time.
func Verify(secret []byte, code string, now time.Time, lastUsedStep int64) (step int64, ok bool) {
	norm, valid := NormalizeCode(code)
	if !valid {
		return 0, false
	}
	cur := StepAt(now)
	for d := int64(-Skew); d <= Skew; d++ {
		s := cur + d
		if s < 0 {
			continue
		}
		want := CodeAt(secret, s)
		eq := subtle.ConstantTimeCompare([]byte(want), []byte(norm)) == 1
		if eq && s > lastUsedStep && (!ok || s > step) {
			step, ok = s, true
		}
	}
	return step, ok
}

// NewSeed returns SeedSize random bytes.
func NewSeed() []byte {
	b := make([]byte, SeedSize)
	if _, err := rand.Read(b); err != nil {
		panic("totp: entropy source failed: " + err.Error())
	}
	return b
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeSeed is the base32 text (no padding) authenticator apps expect.
func EncodeSeed(seed []byte) string { return b32.EncodeToString(seed) }

// DecodeSeed parses base32 text, ignoring case, spaces and hyphens.
func DecodeSeed(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	return b32.DecodeString(s)
}

// escape percent-encodes s for use as a path segment or query value, with %20
// for spaces (not "+") and ":" escaped so it cannot split the label.
func escape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(s), "+", "%20"), ":", "%3A")
}

// URI builds the otpauth://totp/ provisioning URI (the Key URI Format of
// Google Authenticator). issuer and account are URL-escaped.
func URI(issuer, account string, seed []byte) string {
	label := escape(account)
	q := "secret=" + EncodeSeed(seed) + "&algorithm=SHA1&digits=6&period=30"
	if issuer != "" {
		label = escape(issuer) + ":" + label
		q += "&issuer=" + escape(issuer)
	}
	return "otpauth://totp/" + label + "?" + q
}
