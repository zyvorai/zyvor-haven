// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package totp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// RecoveryCount is how many recovery codes a set holds.
const RecoveryCount = 10

// recoveryAlphabet has 32 symbols: A-Z without I and O, and 2-9. No 0, 1, I, O,
// so a code read from paper cannot be misread. 32 symbols make a byte&31 draw
// exactly uniform.
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

const recoveryLen = 10 // symbols per code (50 bits)

// NewRecoveryCodes returns n fresh codes formatted XXXXX-XXXXX.
func NewRecoveryCodes(n int) []string {
	out := make([]string, n)
	for i := range out {
		raw := make([]byte, recoveryLen)
		if _, err := rand.Read(raw); err != nil {
			panic("totp: entropy source failed: " + err.Error())
		}
		var b strings.Builder
		for j, c := range raw {
			if j == recoveryLen/2 {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryAlphabet[c&31])
		}
		out[i] = b.String()
	}
	return out
}

// NormalizeRecovery canonicalises user input (case, spaces, hyphens) and
// reports whether it has the shape of a recovery code.
func NormalizeRecovery(s string) (string, bool) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(s))
	if len(s) != recoveryLen {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(recoveryAlphabet, s[i]) < 0 {
			return "", false
		}
	}
	return s, true
}

// HashRecovery is the stored form of a recovery code: sha256 hex of the
// normalised code. The codes carry 50 bits of entropy and are rate limited, so
// a fast hash is appropriate (like the stored refresh tokens).
func HashRecovery(code string) (string, bool) {
	n, ok := NormalizeRecovery(code)
	if !ok {
		return "", false
	}
	h := sha256.Sum256([]byte("recovery|" + n))
	return hex.EncodeToString(h[:]), true
}
