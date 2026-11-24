// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package realmdiff compares two Keycloak realm export documents and reports
// the configuration paths that were added, removed or changed. It is built for
// GitOps review: server-generated identifiers are ignored and any value under
// a credential-bearing key is redacted, so a diff is safe to paste in a PR.
package realmdiff

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	MaxDocBytes  = 32 << 20
	MaxDepth     = 24
	MaxNodes     = 500000
	MaxValueLen  = 120
	Redacted     = "<redacted>"
	maxArrayIdxs = 100000
)

var (
	secretKey = regexp.MustCompile(`(?i)(secret|credential|password|passwd|private[_-]?key|api[_-]?key|token$|^value$|certificate|keystore|salt|hash)`)
	// Server-generated or volatile keys that differ between otherwise identical exports.
	volatileKey = map[string]bool{
		"id": true, "internalId": true, "containerId": true, "createdTimestamp": true,
		"notBefore": true, "federationLink": true,
	}
	// Keys that identify an element inside an array, in priority order.
	identityKeys = []string{"clientId", "alias", "username", "realm", "name", "path", "providerId", "id"}
)

type Change struct {
	Path   string `json:"path"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type Result struct {
	Added   []Change `json:"added"`
	Removed []Change `json:"removed"`
	Changed []Change `json:"changed"`
}

// Filter drops changes whose path matches any glob; * matches any run of
// characters, including dots and brackets. Patterns match the whole path, or
// a parent of it (the path continues with "." or "[" after the pattern).
func (r Result) Filter(globs []string) Result {
	if len(globs) == 0 {
		return r
	}
	keep := func(in []Change) []Change {
		out := []Change{}
		for _, c := range in {
			if !ignored(c.Path, globs) {
				out = append(out, c)
			}
		}
		return out
	}
	return Result{Added: keep(r.Added), Removed: keep(r.Removed), Changed: keep(r.Changed)}
}

func ignored(path string, globs []string) bool {
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if globMatch(g, path) || globMatch(g+".*", path) || globMatch(g+"[*", path) {
			return true
		}
	}
	return false
}

// globMatch reports whether s matches pattern, where * matches any run of
// characters. It runs in linear time per star and cannot backtrack badly.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return strings.HasSuffix(s, last) && len(s) >= len(last)
}

// Markdown renders the result as a fenced diff block for a pull-request
// comment. Values are already redacted and truncated by Compare.
func (r Result) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "### Haven realm diff: %d added, %d removed, %d changed\n", len(r.Added), len(r.Removed), len(r.Changed))
	if r.Empty() {
		b.WriteString("\nNo differences.\n")
		return b.String()
	}
	b.WriteString("\n~~~diff\n")
	line := func(s string) string { return strings.NewReplacer("\n", " ", "\r", " ").Replace(s) }
	for _, c := range r.Added {
		fmt.Fprintf(&b, "+ %s = %s\n", line(c.Path), line(c.After))
	}
	for _, c := range r.Removed {
		fmt.Fprintf(&b, "- %s = %s\n", line(c.Path), line(c.Before))
	}
	for _, c := range r.Changed {
		fmt.Fprintf(&b, "- %s = %s\n+ %s = %s\n", line(c.Path), line(c.Before), line(c.Path), line(c.After))
	}
	b.WriteString("~~~\n")
	return b.String()
}

func (r Result) Empty() bool { return len(r.Added)+len(r.Removed)+len(r.Changed) == 0 }

// Compare diffs two decoded realm documents.
func Compare(before, after any) (Result, error) {
	a, err := flatten(before)
	if err != nil {
		return Result{}, fmt.Errorf("before: %w", err)
	}
	b, err := flatten(after)
	if err != nil {
		return Result{}, fmt.Errorf("after: %w", err)
	}
	res := Result{Added: []Change{}, Removed: []Change{}, Changed: []Change{}}
	for p, av := range a {
		bv, ok := b[p]
		switch {
		case !ok:
			res.Removed = append(res.Removed, Change{Path: p, Before: av})
		case av != bv:
			res.Changed = append(res.Changed, Change{Path: p, Before: av, After: bv})
		}
	}
	for p, bv := range b {
		if _, ok := a[p]; !ok {
			res.Added = append(res.Added, Change{Path: p, After: bv})
		}
	}
	for _, s := range [][]Change{res.Added, res.Removed, res.Changed} {
		sort.Slice(s, func(i, j int) bool { return s[i].Path < s[j].Path })
	}
	return res, nil
}

// CompareJSON decodes and diffs two raw JSON documents.
func CompareJSON(before, after []byte) (Result, error) {
	var a, b any
	for _, in := range []struct {
		name string
		raw  []byte
		dst  *any
	}{{"before", before, &a}, {"after", after, &b}} {
		if len(in.raw) > MaxDocBytes {
			return Result{}, fmt.Errorf("%s document exceeds %d bytes", in.name, MaxDocBytes)
		}
		if err := json.Unmarshal(in.raw, in.dst); err != nil {
			return Result{}, fmt.Errorf("decode %s: %w", in.name, err)
		}
	}
	return Compare(a, b)
}

func flatten(doc any) (map[string]string, error) {
	out := map[string]string{}
	nodes := 0
	var walk func(path string, v any, depth int, secret bool) error
	walk = func(path string, v any, depth int, secret bool) error {
		nodes++
		if nodes > MaxNodes {
			return errors.New("document has too many nodes")
		}
		if depth > MaxDepth {
			return fmt.Errorf("document nesting exceeds %d levels", MaxDepth)
		}
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				out[path] = "{}"
			}
			for k, c := range x {
				if volatileKey[k] {
					continue
				}
				sub := k
				if path != "" {
					sub = path + "." + k
				}
				if err := walk(sub, c, depth+1, secret || secretKey.MatchString(k)); err != nil {
					return err
				}
			}
		case []any:
			if len(x) > maxArrayIdxs {
				return errors.New("array too large")
			}
			if len(x) == 0 {
				out[path] = "[]"
			}
			keys := arrayKeys(x)
			for i, c := range x {
				if err := walk(fmt.Sprintf("%s[%s]", path, keys[i]), c, depth+1, secret); err != nil {
					return err
				}
			}
		default:
			out[path] = render(x, secret)
		}
		return nil
	}
	if err := walk("", doc, 0, false); err != nil {
		return nil, err
	}
	return out, nil
}

// arrayKeys picks a stable label per element: a natural identity when every
// element is an object with a unique one, otherwise the sorted-scalar value or
// the position.
func arrayKeys(arr []any) []string {
	keys := make([]string, len(arr))
	for _, k := range identityKeys {
		seen := map[string]bool{}
		ok := true
		for i, el := range arr {
			m, isMap := el.(map[string]any)
			s, isStr := "", false
			if isMap {
				s, isStr = m[k].(string)
			}
			if !isMap || !isStr || s == "" || seen[s] {
				ok = false
				break
			}
			seen[s] = true
			keys[i] = s
		}
		if ok {
			return keys
		}
	}
	allScalar := true
	for _, el := range arr {
		switch el.(type) {
		case string, float64, bool:
		default:
			allScalar = false
		}
	}
	for i, el := range arr {
		if allScalar {
			keys[i] = render(el, false)
		} else {
			keys[i] = fmt.Sprint(i)
		}
	}
	return keys
}

func render(v any, secret bool) string {
	if secret {
		return Redacted
	}
	var s string
	switch x := v.(type) {
	case nil:
		s = "null"
	case string:
		s = fmt.Sprintf("%q", x)
	default:
		s = fmt.Sprint(x)
	}
	if len(s) > MaxValueLen {
		s = s[:MaxValueLen] + "..."
	}
	return s
}
