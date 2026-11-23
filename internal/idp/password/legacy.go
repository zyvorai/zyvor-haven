// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package password

import (
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // PBKDF2-HMAC-SHA1 is a legacy Keycloak scheme, verify-only
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Resource limits applied to every stored hash (ValidateEncoded and Verify), so
// a hostile hash can never cause a huge allocation or unbounded derivation.
const (
	maxArgonMemory  = 1 << 20 // KiB
	maxArgonTime    = 20
	maxArgonThreads = 16
	minPBKDF2Iter   = 1000
	maxPBKDF2Iter   = 2_000_000
	minSalt         = 8
	maxSalt         = 64
	minHash         = 16
	maxHash         = 128
	maxEncodedLen   = 1024
)

type scheme int

const (
	schemeArgon2id scheme = iota + 1
	schemeArgon2i
	schemePBKDF2SHA1
	schemePBKDF2SHA256
	schemePBKDF2SHA512
)

// parsedHash is a structurally valid, limit-checked stored hash.
type parsedHash struct {
	scheme  scheme
	m, t, p uint32 // argon2
	iter    int    // pbkdf2
	salt    []byte
	want    []byte
}

var strictEnc = enc.Strict()

var errMalformed = errors.New("password: malformed hash")

func parseUint(s string) (uint32, bool) {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 32)
	return uint32(v), err == nil
}

func parseEncoded(encoded string) (parsedHash, error) {
	var ph parsedHash
	if len(encoded) > maxEncodedLen {
		return ph, fmt.Errorf("%w: too long", errMalformed)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) < 2 || parts[0] != "" {
		return ph, fmt.Errorf("%w: not a $-delimited hash", errMalformed)
	}
	var saltS, hashS string
	switch parts[1] {
	case "argon2id", "argon2i":
		if len(parts) != 6 || parts[2] != "v=19" {
			return ph, fmt.Errorf("%w: bad argon2 layout or version", errMalformed)
		}
		ph.scheme = schemeArgon2id
		if parts[1] == "argon2i" {
			ph.scheme = schemeArgon2i
		}
		kv := strings.Split(parts[3], ",")
		if len(kv) != 3 || !strings.HasPrefix(kv[0], "m=") || !strings.HasPrefix(kv[1], "t=") || !strings.HasPrefix(kv[2], "p=") {
			return ph, fmt.Errorf("%w: bad argon2 parameters", errMalformed)
		}
		var ok1, ok2, ok3 bool
		ph.m, ok1 = parseUint(kv[0][2:])
		ph.t, ok2 = parseUint(kv[1][2:])
		ph.p, ok3 = parseUint(kv[2][2:])
		if !ok1 || !ok2 || !ok3 {
			return ph, fmt.Errorf("%w: bad argon2 parameters", errMalformed)
		}
		if ph.m == 0 || ph.t == 0 || ph.p == 0 || ph.m > maxArgonMemory || ph.t > maxArgonTime ||
			ph.p > maxArgonThreads || ph.m < 8*ph.p {
			return ph, errors.New("password: argon2 parameters out of range")
		}
		saltS, hashS = parts[4], parts[5]
	case "pbkdf2-sha1", "pbkdf2-sha256", "pbkdf2-sha512":
		if len(parts) != 5 || !strings.HasPrefix(parts[2], "i=") {
			return ph, fmt.Errorf("%w: bad pbkdf2 layout", errMalformed)
		}
		ph.scheme = map[string]scheme{"pbkdf2-sha1": schemePBKDF2SHA1, "pbkdf2-sha256": schemePBKDF2SHA256,
			"pbkdf2-sha512": schemePBKDF2SHA512}[parts[1]]
		it, ok := parseUint(parts[2][2:])
		if !ok {
			return ph, fmt.Errorf("%w: bad pbkdf2 iterations", errMalformed)
		}
		if it < minPBKDF2Iter || it > maxPBKDF2Iter {
			return ph, errors.New("password: pbkdf2 iterations out of range")
		}
		ph.iter = int(it)
		saltS, hashS = parts[3], parts[4]
	default:
		return ph, errors.New("password: unsupported hash scheme")
	}
	var err error
	if ph.salt, err = strictEnc.DecodeString(saltS); err != nil {
		return ph, fmt.Errorf("%w: salt is not unpadded base64", errMalformed)
	}
	if ph.want, err = strictEnc.DecodeString(hashS); err != nil {
		return ph, fmt.Errorf("%w: hash is not unpadded base64", errMalformed)
	}
	if len(ph.salt) < minSalt || len(ph.salt) > maxSalt {
		return ph, errors.New("password: salt length out of range")
	}
	if len(ph.want) < minHash || len(ph.want) > maxHash {
		return ph, errors.New("password: hash length out of range")
	}
	return ph, nil
}

// ValidateEncoded checks structure and limits WITHOUT any password: known
// scheme, base64 parses, salt 8..64 bytes, hash 16..128 bytes, pbkdf2
// iterations 1000..2_000_000, argon2 m <= 1<<20 KiB, t <= 20, p <= 16.
func ValidateEncoded(encoded string) error {
	_, err := parseEncoded(encoded)
	return err
}

// derive recomputes the key for pw; ok=false only if the KDF itself failed.
func (ph parsedHash) derive(pw string) ([]byte, bool) {
	n := len(ph.want)
	switch ph.scheme {
	case schemeArgon2id:
		return argon2.IDKey([]byte(pw), ph.salt, ph.t, ph.m, uint8(ph.p), uint32(n)), true
	case schemeArgon2i:
		return argon2.Key([]byte(pw), ph.salt, ph.t, ph.m, uint8(ph.p), uint32(n)), true
	}
	var h func() hash.Hash
	switch ph.scheme {
	case schemePBKDF2SHA1:
		h = sha1.New
	case schemePBKDF2SHA256:
		h = sha256.New
	case schemePBKDF2SHA512:
		h = sha512.New
	default:
		return nil, false
	}
	k, err := pbkdf2.Key(h, pw, ph.salt, ph.iter, n)
	return k, err == nil
}

// Verify checks pw against a stored hash of any supported scheme. needsRehash
// is true for every non-argon2id scheme and for argon2id parameters weaker
// than the hasher's current ones. Malformed or out-of-limit input returns
// (false, false). The full derivation runs even for a wrong password.
func (h *Hasher) Verify(pw, encoded string) (bool, bool) {
	ph, err := parseEncoded(encoded)
	if err != nil {
		return false, false
	}
	got, ok := ph.derive(pw)
	if !ok || subtle.ConstantTimeCompare(got, ph.want) != 1 {
		return false, false
	}
	if ph.scheme != schemeArgon2id {
		return true, true
	}
	weaker := ph.m < h.p.Memory || ph.t < h.p.Time || ph.p < uint32(h.p.Threads) ||
		len(ph.salt) < h.p.SaltLen || uint32(len(ph.want)) < h.p.KeyLen
	return true, weaker
}

// KeycloakCredential is the relevant part of a Keycloak password credential.
type KeycloakCredential struct {
	Algorithm  string              // "pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512", "argon2"
	Iterations int                 // hashIterations
	Salt       string              // base64 (std, padded) as in the export
	Value      string              // base64 hash as in the export
	Extra      map[string][]string // additionalParameters (argon2: memory, parallelism, type, version, hashLength)
}

// decodeB64 accepts standard base64 with or without canonical padding.
func decodeB64(s string) ([]byte, error) {
	if strings.Contains(s, "=") {
		return base64.StdEncoding.Strict().DecodeString(s)
	}
	return strictEnc.DecodeString(s)
}

func extra1(c KeycloakCredential, key string) (string, bool) {
	v := c.Extra[key]
	if len(v) != 1 {
		return "", false
	}
	return v[0], true
}

// FromKeycloak converts to the encodings above ("pbkdf2" = HMAC-SHA1). Errors
// never contain the salt or hash value.
func FromKeycloak(c KeycloakCredential) (string, error) {
	salt, err := decodeB64(c.Salt)
	if err != nil {
		return "", errors.New("password: keycloak credential salt: not valid base64")
	}
	val, err := decodeB64(c.Value)
	if err != nil {
		return "", errors.New("password: keycloak credential value: not valid base64")
	}
	if c.Iterations <= 0 {
		return "", errors.New("password: keycloak credential iterations missing or invalid")
	}
	var out string
	switch c.Algorithm {
	case "pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512":
		name := "pbkdf2-sha1"
		if c.Algorithm != "pbkdf2" {
			name = c.Algorithm
		}
		out = fmt.Sprintf("$%s$i=%d$%s$%s", name, c.Iterations, enc.EncodeToString(salt), enc.EncodeToString(val))
	case "argon2":
		mem, ok1 := extra1(c, "memory")
		par, ok2 := extra1(c, "parallelism")
		typ, ok3 := extra1(c, "type")
		ver, ok4 := extra1(c, "version")
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return "", errors.New("password: keycloak argon2 credential needs memory, parallelism, type and version")
		}
		if ver != "19" && ver != "1.3" {
			return "", fmt.Errorf("password: keycloak argon2 version %q unsupported (want 19)", ver)
		}
		if hl, ok := extra1(c, "hashLength"); ok {
			n, err := strconv.Atoi(hl)
			if err != nil || n != len(val) {
				return "", errors.New("password: keycloak argon2 hashLength does not match the value length")
			}
		}
		var name string
		switch typ {
		case "id":
			name = "argon2id"
		case "i":
			name = "argon2i"
		default:
			return "", fmt.Errorf("password: keycloak argon2 type %q unsupported (want i or id)", typ)
		}
		m, okm := parseUint(mem)
		p, okp := parseUint(par)
		if !okm || !okp {
			return "", errors.New("password: keycloak argon2 memory/parallelism invalid")
		}
		out = fmt.Sprintf("$%s$v=19$m=%d,t=%d,p=%d$%s$%s", name, m, c.Iterations, p, enc.EncodeToString(salt), enc.EncodeToString(val))
	default:
		return "", fmt.Errorf("password: keycloak algorithm %q unsupported", c.Algorithm)
	}
	if err := ValidateEncoded(out); err != nil {
		return "", fmt.Errorf("password: keycloak credential rejected: %w", err)
	}
	return out, nil
}
