// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package password implements core.PasswordHasher with argon2id and a
// realm password-policy checker (length(n) and digits(n) style).
package password

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
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

// CheckPolicy validates pw against a realm policy such as
// "length(12) and digits(1) and upperCase(1)". Supported terms: length,
// digits, upperCase, lowerCase, specialChars. Unknown terms are ignored, as
// are malformed ones; an empty policy accepts everything.
//
// It also supports the no-argument terms notCommon(), notBreached() and (via
// CheckPolicyFor) notPersonal(); see docs/password-policy.md. Their names are
// case-insensitive and the parentheses are optional.
func CheckPolicy(policy, pw string) error { return CheckPolicyFor(policy, pw, Personal{}) }

// CheckPolicyFor is CheckPolicy plus the notPersonal() term, which needs to
// know who the password is for. With an empty Personal, notPersonal() accepts.
func CheckPolicyFor(policy, pw string, ctx Personal) error {
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
		switch strings.ToLower(strings.ReplaceAll(part, " ", "")) {
		case "notcommon()", "notcommon":
			if IsCommon(pw) {
				return errors.New("password policy: this password is too common; choose something less guessable")
			}
			continue
		case "notbreached()", "notbreached":
			if IsBreached(pw) {
				return errors.New("password policy: this password appears in a known breach; choose a different one")
			}
			continue
		case "notpersonal()", "notpersonal":
			if containsPersonal(pw, ctx) {
				return errors.New("password policy: password contains your name or email; choose something unrelated")
			}
			continue
		}
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
