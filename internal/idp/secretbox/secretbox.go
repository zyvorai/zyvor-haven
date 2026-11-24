// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package secretbox encrypts the few secrets haven-idp must be able to read
// back (TOTP seeds, upstream identity-provider client secrets). Passwords,
// tokens and client secrets are never stored this way: they are hashed.
//
// AES-256-GCM with a random 96-bit nonce per message. Every message is bound to
// a context string (additional authenticated data) such as
// "totp|realm|userID", so a ciphertext copied to another row, user or purpose
// fails to open. Rotation: Open accepts several keys (the first that opens
// wins); Seal always uses the first.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const prefix = "v1."

// ErrOpen is returned for every failure to open a message: wrong key, wrong
// context, tampering or malformed input. Callers must not distinguish them.
var ErrOpen = errors.New("secretbox: cannot open")

// Box seals and opens messages.
type Box struct{ aeads []cipher.AEAD }

// New builds a Box from one or more 32-byte keys. The first key seals.
func New(keys ...[]byte) (*Box, error) {
	if len(keys) == 0 {
		return nil, errors.New("secretbox: at least one key is required")
	}
	b := &Box{}
	for i, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("secretbox: key %d is %d bytes, want 32", i, len(k))
		}
		blk, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		b.aeads = append(b.aeads, g)
	}
	return b, nil
}

// ParseKey accepts a 32-byte key as base64 (std or URL, padded or not) or as
// 64 hex characters.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if k, err := hex.DecodeString(s); err == nil {
			return k, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	return nil, errors.New("secretbox: key must be 32 bytes as base64 or 64 hex characters")
}

// ParseKeys parses a comma-separated key list (newest first).
func ParseKeys(s string) ([][]byte, error) {
	var out [][]byte
	for _, part := range strings.Split(s, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		k, err := ParseKey(part)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, errors.New("secretbox: no key given")
	}
	return out, nil
}

// GenerateKey returns a fresh random key in the format ParseKey accepts.
func GenerateKey() string {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("secretbox: entropy source failed: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(k)
}

// Seal encrypts plaintext bound to context. The result is printable text.
func (b *Box) Seal(plaintext []byte, context string) string {
	g := b.aeads[0]
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic("secretbox: entropy source failed: " + err.Error())
	}
	ct := g.Seal(nil, nonce, plaintext, []byte(context))
	return prefix + base64.RawURLEncoding.EncodeToString(append(nonce, ct...))
}

// Open decrypts a message made by Seal with the same context.
func (b *Box) Open(sealed, context string) ([]byte, error) {
	raw, ok := strings.CutPrefix(sealed, prefix)
	if !ok {
		return nil, ErrOpen
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, ErrOpen
	}
	for _, g := range b.aeads {
		if len(data) < g.NonceSize()+g.Overhead() {
			return nil, ErrOpen
		}
		n := g.NonceSize()
		if pt, err := g.Open(nil, data[:n], data[n:], []byte(context)); err == nil {
			return pt, nil
		}
	}
	return nil, ErrOpen
}
