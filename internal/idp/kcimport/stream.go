// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kcimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// errTooLarge is returned when the export exceeds MaxExportBytes.
var errTooLarge = fmt.Errorf("export exceeds the %d MiB limit", MaxExportBytes>>20)

// capReader fails (instead of silently truncating) once more than the limit
// has been read.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return n, errTooLarge
	}
	return n, err
}

// syntaxErr turns a decoder error into one that never echoes content.
func syntaxErr(err error) error {
	switch {
	case errors.Is(err, errTooLarge):
		return errTooLarge
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("invalid Keycloak export: the file is truncated")
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("invalid Keycloak export: not valid JSON (at byte %d)", se.Offset)
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Errorf("invalid Keycloak export: field %q has the wrong type (%s expected)", te.Field, te.Type)
	}
	return errors.New("invalid Keycloak export: cannot read JSON")
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return syntaxErr(err)
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("invalid Keycloak export: expected %q", string(want))
	}
	return nil
}

// skipValue consumes one JSON value without retaining it.
func skipValue(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return syntaxErr(err)
	}
	d, ok := t.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil
	}
	for depth := 1; depth > 0; {
		t, err := dec.Token()
		if err != nil {
			return syntaxErr(err)
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			default:
				depth--
			}
		}
	}
	return nil
}

// forEach decodes each element of a JSON array into a fresh T and calls fn.
// A JSON null in place of the array is accepted as empty.
func forEach[T any](dec *json.Decoder, fn func(*T) error) error {
	t, err := dec.Token()
	if err != nil {
		return syntaxErr(err)
	}
	if t == nil {
		return nil
	}
	if d, ok := t.(json.Delim); !ok || d != '[' {
		return errors.New("invalid Keycloak export: expected a JSON array")
	}
	for dec.More() {
		var v T
		if err := dec.Decode(&v); err != nil {
			return syntaxErr(err)
		}
		if err := fn(&v); err != nil {
			return err
		}
	}
	return expectDelim(dec, ']')
}

func decodeValue[T any](dec *json.Decoder) (T, error) {
	var v T
	if err := dec.Decode(&v); err != nil {
		return v, syntaxErr(err)
	}
	return v, nil
}
