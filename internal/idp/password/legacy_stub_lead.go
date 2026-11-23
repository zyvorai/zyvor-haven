// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// LEAD-OWNED STUB. The real ValidateEncoded, KeycloakCredential and
// FromKeycloak are implemented by another agent; the lead deletes this file at
// merge. It performs no cryptography: FromKeycloak only re-encodes the export's
// base64 into the self-describing format, ValidateEncoded checks structure.

package password

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// KeycloakCredential is the relevant part of a Keycloak password credential.
type KeycloakCredential struct {
	Algorithm  string              // "pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512", "argon2"
	Iterations int                 // hashIterations
	Salt       string              // base64 (std, padded) as in the export
	Value      string              // base64 hash as in the export
	Extra      map[string][]string // additionalParameters
}

func stubRaw(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", errors.New("invalid base64")
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// FromKeycloak converts to the encodings above ("pbkdf2" = HMAC-SHA1).
func FromKeycloak(c KeycloakCredential) (string, error) {
	salt, err := stubRaw(c.Salt)
	if err != nil {
		return "", errors.New("salt: invalid base64")
	}
	val, err := stubRaw(c.Value)
	if err != nil {
		return "", errors.New("value: invalid base64")
	}
	var out string
	switch c.Algorithm {
	case "pbkdf2":
		out = fmt.Sprintf("$pbkdf2-sha1$i=%d$%s$%s", c.Iterations, salt, val)
	case "pbkdf2-sha256", "pbkdf2-sha512":
		out = fmt.Sprintf("$%s$i=%d$%s$%s", c.Algorithm, c.Iterations, salt, val)
	case "argon2":
		get := func(k, def string) string {
			if v := c.Extra[k]; len(v) > 0 {
				return v[0]
			}
			return def
		}
		typ := get("type", "id")
		if typ != "id" && typ != "i" {
			return "", errors.New("unsupported argon2 variant")
		}
		out = fmt.Sprintf("$argon2%s$v=19$m=%s,t=%d,p=%s$%s$%s", typ, get("memory", "7168"), c.Iterations, get("parallelism", "1"), salt, val)
	default:
		return "", errors.New("unsupported algorithm")
	}
	if err := ValidateEncoded(out); err != nil {
		return "", err
	}
	return out, nil
}

// ValidateEncoded checks structure and limits WITHOUT any password.
func ValidateEncoded(encoded string) error {
	if len(encoded) > 1024 {
		return errors.New("encoded hash too long")
	}
	parts := strings.Split(encoded, "$")
	if len(parts) < 5 || parts[0] != "" {
		return errors.New("malformed hash")
	}
	dec := func(s string, lo, hi int, what string) error {
		b, err := base64.RawStdEncoding.DecodeString(s)
		if err != nil || len(b) < lo || len(b) > hi {
			return fmt.Errorf("invalid %s", what)
		}
		return nil
	}
	switch parts[1] {
	case "pbkdf2-sha1", "pbkdf2-sha256", "pbkdf2-sha512":
		if len(parts) != 5 || !strings.HasPrefix(parts[2], "i=") {
			return errors.New("malformed pbkdf2 hash")
		}
		n, err := strconv.Atoi(parts[2][2:])
		if err != nil || n < 1000 || n > 2_000_000 {
			return errors.New("pbkdf2 iterations out of range")
		}
		if err := dec(parts[3], 8, 64, "salt"); err != nil {
			return err
		}
		return dec(parts[4], 16, 128, "hash")
	case "argon2id", "argon2i":
		if len(parts) != 6 || parts[2] != "v=19" {
			return errors.New("malformed argon2 hash")
		}
		var m, t, p int
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil ||
			m < 1 || m > 1<<20 || t < 1 || t > 20 || p < 1 || p > 16 {
			return errors.New("argon2 parameters out of range")
		}
		if err := dec(parts[4], 8, 64, "salt"); err != nil {
			return err
		}
		return dec(parts[5], 16, 128, "hash")
	}
	return errors.New("unknown hash scheme")
}
