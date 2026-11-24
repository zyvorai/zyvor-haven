// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
)

// RAR: rich authorization requests (RFC 9396). Only the "type" of each entry is
// interpreted: it must be one of the types registered for the client. The rest
// of an entry is carried unchanged to the tokens for the resource server to
// judge; haven-idp does not know what "payment_initiation" means.

const (
	rarMaxBytes   = 8 << 10
	rarMaxEntries = 10
	rarMaxDepth   = 8
)

var (
	errRAR       = errors.New("invalid authorization_details")
	rarTypeRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}$`)
)

// ValidAuthzDetailType reports whether s may be registered as a detail type.
func ValidAuthzDetailType(s string) bool { return rarTypeRegex.MatchString(s) }

// validateAuthzDetails checks raw (a JSON array) against the allowed types and
// returns its canonical re-encoding. An empty allowed list means the client may
// not send any.
func validateAuthzDetails(raw string, allowed []string) (string, error) {
	if len(raw) == 0 || len(raw) > rarMaxBytes || len(allowed) == 0 {
		return "", errRAR
	}
	if hasDupKeys([]byte(raw)) {
		return "", errRAR // two "type" members would be read differently by different parsers
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.UseNumber()
	var arr []map[string]any
	if err := dec.Decode(&arr); err != nil || len(arr) == 0 || len(arr) > rarMaxEntries {
		return "", errRAR
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) { // nothing after the array
		return "", errRAR
	}
	for _, e := range arr {
		t, ok := e["type"].(string)
		if !ok || !rarTypeRegex.MatchString(t) || !slices.Contains(allowed, t) {
			return "", errRAR
		}
		if jsonDepth(e) > rarMaxDepth {
			return "", errRAR
		}
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return "", errRAR
	}
	return string(out), nil
}

func jsonDepth(v any) int {
	d := 0
	switch t := v.(type) {
	case map[string]any:
		for _, x := range t {
			d = max(d, jsonDepth(x))
		}
		return d + 1
	case []any:
		for _, x := range t {
			d = max(d, jsonDepth(x))
		}
		return d + 1
	}
	return 0
}

// hasDupKeys reports whether any JSON object in raw repeats a member name (or
// the document is not well-formed JSON).
func hasDupKeys(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var walk func() bool
	walk = func() bool {
		tok, err := dec.Token()
		if err != nil {
			return true
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return false
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return true
				}
				k, _ := kt.(string)
				if seen[k] {
					return true
				}
				seen[k] = true
				if walk() {
					return true
				}
			}
		case '[':
			for dec.More() {
				if walk() {
					return true
				}
			}
		}
		_, err = dec.Token() // closing delimiter
		return err != nil
	}
	return walk()
}
