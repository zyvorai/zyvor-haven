// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package webauthn verifies WebAuthn registrations and assertions (passkeys)
// with the Go standard library only. It is pure: no HTTP, no storage.
package webauthn

import (
	"errors"
	"fmt"
	"math"
)

// A deliberately small CBOR (RFC 8949) decoder: exactly what WebAuthn needs.
//
// Supported: unsigned/negative integers (must fit int64), byte strings, text
// strings, arrays, maps (keys: integers or text strings), booleans and null.
// Rejected: indefinite lengths, tags, floats, simple values other than
// false/true/null, duplicate map keys, nesting deeper than maxDepth, more than
// maxItems entries in one container, more than maxTotal values overall, and any
// length that exceeds the bytes that are actually left (so a tiny input can
// never make us allocate a large buffer).
const (
	maxDepth = 8
	maxItems = 64
	maxTotal = 1024
)

// ErrCBOR is wrapped by every decoding error.
var ErrCBOR = errors.New("webauthn: invalid CBOR")

func cborErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCBOR, fmt.Sprintf(format, a...))
}

// Map is a decoded CBOR map. Keys are int64 or string.
type Map map[any]any

// DecodeCBOR decodes exactly one data item and rejects trailing bytes.
func DecodeCBOR(b []byte) (any, error) {
	v, n, err := DecodeCBORPrefix(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, cborErr("%d trailing bytes", len(b)-n)
	}
	return v, nil
}

// DecodeCBORPrefix decodes the first data item of b and reports how many bytes
// it used (authenticator data embeds a COSE key followed by more data).
func DecodeCBORPrefix(b []byte) (any, int, error) {
	d := &decoder{b: b}
	v, err := d.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

type decoder struct {
	b     []byte
	pos   int
	total int
}

func (d *decoder) left() int { return len(d.b) - d.pos }

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || n > d.left() {
		return nil, cborErr("truncated")
	}
	s := d.b[d.pos : d.pos+n]
	d.pos += n
	return s, nil
}

// head reads the initial byte and its argument.
func (d *decoder) head() (major byte, arg uint64, err error) {
	hb, err := d.take(1)
	if err != nil {
		return 0, 0, err
	}
	major, ai := hb[0]>>5, hb[0]&0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai >= 28: // 28-30 reserved, 31 indefinite length
		return 0, 0, cborErr("indefinite or reserved length")
	}
	n := 1 << (ai - 24) // 1, 2, 4, 8
	raw, err := d.take(n)
	if err != nil {
		return 0, 0, err
	}
	for _, c := range raw {
		arg = arg<<8 | uint64(c)
	}
	return major, arg, nil
}

func (d *decoder) item(depth int) (any, error) {
	if depth > maxDepth {
		return nil, cborErr("nesting too deep")
	}
	if d.total++; d.total > maxTotal {
		return nil, cborErr("too many values")
	}
	if d.left() < 1 {
		return nil, cborErr("truncated")
	}
	first := d.b[d.pos]
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, cborErr("integer out of range")
		}
		return int64(arg), nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, cborErr("integer out of range")
		}
		return -1 - int64(arg), nil
	case 2, 3:
		if arg > uint64(d.left()) { // never allocate more than the input holds
			return nil, cborErr("string longer than input")
		}
		s, _ := d.take(int(arg))
		if major == 2 {
			return append([]byte(nil), s...), nil
		}
		return string(s), nil
	case 4:
		if arg > maxItems || arg > uint64(d.left()) {
			return nil, cborErr("array too large")
		}
		out := make([]any, 0, int(arg))
		for i := uint64(0); i < arg; i++ {
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if arg > maxItems || arg*2 > uint64(d.left()) {
			return nil, cborErr("map too large")
		}
		out := make(Map, int(arg))
		for i := uint64(0); i < arg; i++ {
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, cborErr("unsupported map key type")
			}
			if _, dup := out[k]; dup {
				return nil, cborErr("duplicate map key")
			}
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 6:
		return nil, cborErr("tags are not supported")
	default: // 7
		switch first {
		case 0xf4:
			return false, nil
		case 0xf5:
			return true, nil
		case 0xf6:
			return nil, nil
		}
		return nil, cborErr("unsupported simple value or float")
	}
}
