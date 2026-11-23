// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package password implements core.PasswordHasher with argon2id and a
// Keycloak-style password policy checker.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// Params are argon2id cost parameters.
type Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	SaltLen int
	KeyLen  uint32
}

// DefaultParams is the production profile: m=65536,t=3,p=2.
var DefaultParams = Params{Memory: 64 * 1024, Time: 3, Threads: 2, SaltLen: 16, KeyLen: 32}

// TestParams is a cheap profile for tests only.
var TestParams = Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

// Hasher implements core.PasswordHasher.
type Hasher struct{ p Params }

// New returns a Hasher; zero fields of p fall back to DefaultParams.
func New(p Params) *Hasher {
	d := DefaultParams
	if p.Memory == 0 {
		p.Memory = d.Memory
	}
	if p.Time == 0 {
		p.Time = d.Time
	}
	if p.Threads == 0 {
		p.Threads = d.Threads
	}
	if p.SaltLen == 0 {
		p.SaltLen = d.SaltLen
	}
	if p.KeyLen == 0 {
		p.KeyLen = d.KeyLen
	}
	return &Hasher{p: p}
}

var enc = base64.RawStdEncoding

// Hash returns a PHC string for pw.
func (h *Hasher) Hash(pw string) (string, error) {
	salt := make([]byte, h.p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, h.p.Time, h.p.Memory, h.p.Threads, h.p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.p.Memory, h.p.Time, h.p.Threads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

const (
	maxMemory  = 1 << 18 // 256 MiB in KiB; refuse hostile hashes
	maxTime    = 64
	maxThreads = 64
)

// Verify checks pw against a PHC string. needsRehash is true when the stored
// parameters differ from the hasher's current ones. Malformed input returns
// (false, false).
func (h *Hasher) Verify(pw, encoded string) (bool, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || !strings.HasPrefix(parts[2], "v=") {
		return false, false
	}
	ver, err := strconv.Atoi(parts[2][2:])
	if err != nil || ver != argon2.Version {
		return false, false
	}
	var m, t uint64
	var p uint64
	kv := strings.Split(parts[3], ",")
	if len(kv) != 3 {
		return false, false
	}
	for i, want := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(kv[i], want) {
			return false, false
		}
		v, err := strconv.ParseUint(kv[i][2:], 10, 32)
		if err != nil {
			return false, false
		}
		switch i {
		case 0:
			m = v
		case 1:
			t = v
		case 2:
			p = v
		}
	}
	if m == 0 || t == 0 || p == 0 || m > maxMemory || t > maxTime || p > maxThreads || m < 8*p {
		return false, false
	}
	salt, err := enc.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false, false
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) < 4 || len(want) > 1024 {
		return false, false
	}
	got := argon2.IDKey([]byte(pw), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false
	}
	rehash := uint32(m) != h.p.Memory || uint32(t) != h.p.Time || uint8(p) != h.p.Threads ||
		len(salt) != h.p.SaltLen || uint32(len(want)) != h.p.KeyLen
	return true, rehash
}

// CheckPolicy validates pw against a realm policy such as
// "length(12) and digits(1) and upperCase(1)". Supported terms: length,
// digits, upperCase, lowerCase, specialChars. Unknown terms are ignored, as
// are malformed ones; an empty policy accepts everything.
func CheckPolicy(policy, pw string) error {
	var digits, upper, lower, special, n int
	for _, r := range pw {
		n++
		switch {
		case unicode.IsDigit(r):
			digits++
		case unicode.IsUpper(r):
			upper++
		case unicode.IsLower(r):
			lower++
		default:
			special++
		}
	}
	for _, part := range strings.Split(policy, " and ") {
		part = strings.TrimSpace(part)
		i := strings.IndexByte(part, '(')
		if i < 0 || !strings.HasSuffix(part, ")") {
			continue
		}
		min, err := strconv.Atoi(strings.TrimSpace(part[i+1 : len(part)-1]))
		if err != nil || min <= 0 {
			continue
		}
		name, have := part[:i], 0
		switch name {
		case "length":
			have = n
		case "digits":
			have = digits
		case "upperCase":
			have = upper
		case "lowerCase":
			have = lower
		case "specialChars":
			have = special
		default:
			continue
		}
		if have < min {
			return fmt.Errorf("password policy: %s(%d) not satisfied", name, min)
		}
	}
	return nil
}
