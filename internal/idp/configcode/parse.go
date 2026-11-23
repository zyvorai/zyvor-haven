// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"sigs.k8s.io/yaml"
)

// MaxSpecBytes is the largest accepted realm file.
const MaxSpecBytes = 1 << 20

// Parse reads one strict YAML realm document (unknown fields are errors,
// exactly one document, at most 1 MiB) and validates it.
func Parse(r io.Reader) (*Spec, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSpecBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	if len(data) > MaxSpecBytes {
		return nil, errors.New("spec exceeds the 1 MiB limit")
	}
	if err := singleDocument(data); err != nil {
		return nil, err
	}
	var s Spec
	if err := yaml.UnmarshalStrict(data, &s); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// singleDocument rejects multi-document streams and empty input. A document
// marker can only start at column 0, so a line scan is exact.
func singleDocument(data []byte) error {
	content := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		isMarker := line == "---" || line == "..." || strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "---\t")
		if isMarker {
			if content {
				return errors.New("spec must contain exactly one YAML document")
			}
			continue
		}
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") {
			content = true
		}
	}
	if !content {
		return errors.New("spec is empty")
	}
	return nil
}

// Marshal renders s as canonical YAML: lists sorted, keys in stable
// (alphabetical) order. Defaults are not injected.
func Marshal(s *Spec) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil spec")
	}
	out, err := yaml.Marshal(canonical(s))
	if err != nil {
		return nil, err
	}
	return bytes.TrimLeft(out, "\n"), nil
}
