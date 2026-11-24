// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package policy evaluates organisation-defined, declarative rules against
// realm exports (the standard realm-export JSON format). It is deterministic,
// has no side effects and never reads, prints or stores secret material: paths
// that name credentials are rejected when a policy is loaded.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/zyvorai/haven/internal/posture"
)

// Hard limits keep hostile policy or realm documents from consuming memory or CPU.
const (
	MaxPolicyBytes   = 256 << 10
	MaxRules         = 200
	MaxPathSegments  = 8
	MaxPathLen       = 200
	MaxValueItems    = 200
	MaxPatternLen    = 256
	MaxTextLen       = 300
	MaxEvidenceLen   = 120
	MaxFindingsRule  = 50
	MaxArrayElements = 10000
)

var (
	idPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$`)
	segPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}(\[\])?$`)
	// Segments that can carry credential material. "passwordPolicy" and
	// similar configuration names are fine; a bare password, secrets,
	// credentials, keys and tokens are not.
	secretPattern = regexp.MustCompile(`(?i)(secret|credential|private[_-]?key|api[_-]?key|^passwords?(\[\])?$|^passwd$|^value$|^(access|refresh|id)?_?token$)`)
)

type Policy struct {
	Version int    `json:"version"`
	Name    string `json:"name,omitempty"`
	Rules   []Rule `json:"rules"`
}

// Rule asserts that Path satisfies Op for every selected realm or client. A
// violation yields one finding. Paths use dot notation; a trailing [] on a
// segment selects every element of an array.
type Rule struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Remediation string `json:"remediation,omitempty"`
	Scope       string `json:"scope"` // realm (default) or client
	Path        string `json:"path"`
	Op          string `json:"op"`
	Value       any    `json:"value,omitempty"`
	// Optional makes a missing path pass instead of count as a violation.
	Optional bool `json:"optional,omitempty"`
	// IncludeBuiltin evaluates the built-in clients too (client scope).
	IncludeBuiltin bool `json:"includeBuiltin,omitempty"`

	segments []string
	re       *regexp.Regexp
	num      float64
	list     []any
}

var ops = map[string]bool{
	"eq": true, "ne": true, "lt": true, "lte": true, "gt": true, "gte": true,
	"in": true, "notIn": true, "contains": true, "notContains": true,
	"matches": true, "present": true, "absent": true, "nonEmpty": true,
}

// Parse decodes and validates a policy document.
func Parse(data []byte) (*Policy, error) {
	if len(data) > MaxPolicyBytes {
		return nil, fmt.Errorf("policy exceeds %d bytes", MaxPolicyBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if dec.More() {
		return nil, errors.New("decode policy: trailing data")
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d (want 1)", p.Version)
	}
	if len(p.Rules) == 0 {
		return nil, errors.New("policy has no rules")
	}
	if len(p.Rules) > MaxRules {
		return nil, fmt.Errorf("policy has %d rules, maximum is %d", len(p.Rules), MaxRules)
	}
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if err := r.prepare(); err != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i+1, r.ID, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
	}
	return &p, nil
}

func (r *Rule) prepare() error {
	if !idPattern.MatchString(r.ID) {
		return errors.New("id must match [A-Za-z0-9][A-Za-z0-9_-]{0,39}")
	}
	switch strings.ToLower(r.Severity) {
	case "critical", "high", "medium", "low", "info":
		r.Severity = strings.ToLower(r.Severity)
	default:
		return fmt.Errorf("unsupported severity %q", r.Severity)
	}
	if strings.TrimSpace(r.Title) == "" || len(r.Title) > MaxTextLen || len(r.Remediation) > MaxTextLen {
		return fmt.Errorf("title is required and title/remediation are limited to %d bytes", MaxTextLen)
	}
	switch r.Scope {
	case "":
		r.Scope = "realm"
	case "realm", "client":
	default:
		return fmt.Errorf("unsupported scope %q", r.Scope)
	}
	if !ops[r.Op] {
		return fmt.Errorf("unsupported op %q", r.Op)
	}
	if r.Path == "" || len(r.Path) > MaxPathLen {
		return errors.New("path is required and limited to 200 bytes")
	}
	r.segments = strings.Split(r.Path, ".")
	if len(r.segments) > MaxPathSegments {
		return fmt.Errorf("path has more than %d segments", MaxPathSegments)
	}
	for _, s := range r.segments {
		if !segPattern.MatchString(s) {
			return fmt.Errorf("invalid path segment %q", s)
		}
		if secretPattern.MatchString(s) {
			return errors.New("policies may not inspect credential-bearing paths")
		}
	}
	return r.prepareValue()
}

func (r *Rule) prepareValue() error {
	switch r.Op {
	case "present", "absent", "nonEmpty":
		if r.Value != nil {
			return fmt.Errorf("op %s takes no value", r.Op)
		}
	case "lt", "lte", "gt", "gte":
		f, ok := r.Value.(float64)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("op %s needs a numeric value", r.Op)
		}
		r.num = f
	case "in", "notIn":
		l, ok := r.Value.([]any)
		if !ok || len(l) == 0 || len(l) > MaxValueItems {
			return fmt.Errorf("op %s needs a list of 1-%d scalars", r.Op, MaxValueItems)
		}
		for _, v := range l {
			if !scalar(v) {
				return errors.New("list values must be scalars")
			}
		}
		r.list = l
	case "matches":
		s, ok := r.Value.(string)
		if !ok || s == "" || len(s) > MaxPatternLen {
			return fmt.Errorf("matches needs a pattern of 1-%d bytes", MaxPatternLen)
		}
		re, err := regexp.Compile(s) // RE2: linear time, no catastrophic backtracking
		if err != nil {
			return fmt.Errorf("invalid pattern: %w", err)
		}
		r.re = re
	default: // eq, ne, contains, notContains
		if !scalar(r.Value) {
			return fmt.Errorf("op %s needs a scalar value", r.Op)
		}
	}
	return nil
}

func scalar(v any) bool {
	switch x := v.(type) {
	case string:
		return len(x) <= MaxTextLen
	case float64, bool:
		return true
	}
	return false
}

// Evaluate runs the policy against one realm export document (the decoded
// JSON object). Findings are sorted for deterministic output.
func (p *Policy) Evaluate(realm string, doc map[string]any) []posture.Finding {
	var out []posture.Finding
	for i := range p.Rules {
		r := &p.Rules[i]
		var n int
		add := func(clientID, evidence string) {
			if n >= MaxFindingsRule {
				return
			}
			n++
			out = append(out, posture.Finding{
				RuleID: "POLICY-" + r.ID, Severity: posture.Severity(r.Severity), Realm: realm,
				ClientID: clientID, Title: r.Title, Evidence: evidence, Remediation: r.Remediation,
			})
		}
		if r.Scope == "client" {
			clients, _ := doc["clients"].([]any)
			for ci, c := range clients {
				if ci >= MaxArrayElements {
					break
				}
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				id, _ := cm["clientId"].(string)
				if !r.IncludeBuiltin && posture.IsBuiltInClient(id) {
					continue
				}
				r.check(cm, func(e string) { add(id, e) })
			}
			continue
		}
		r.check(doc, func(e string) { add("", e) })
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Realm != out[j].Realm {
			return out[i].Realm < out[j].Realm
		}
		if out[i].ClientID != out[j].ClientID {
			return out[i].ClientID < out[j].ClientID
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func (r *Rule) check(root map[string]any, violate func(evidence string)) {
	vals, found := resolve(root, r.segments)
	switch r.Op {
	case "present":
		if !found || len(vals) == 0 {
			violate("missing " + r.Path)
		}
		return
	case "absent":
		if found {
			violate("present " + r.Path)
		}
		return
	}
	if !found {
		if !r.Optional {
			violate("missing " + r.Path)
		}
		return
	}
	for _, v := range vals {
		if !r.holds(v) {
			violate(fmt.Sprintf("%s=%s", r.Path, render(v)))
		}
	}
}

// resolve walks the path and returns every selected value.
func resolve(cur any, segs []string) ([]any, bool) {
	if len(segs) == 0 {
		return []any{cur}, true
	}
	seg := segs[0]
	each := strings.HasSuffix(seg, "[]")
	seg = strings.TrimSuffix(seg, "[]")
	m, ok := cur.(map[string]any)
	if !ok {
		return nil, false
	}
	next, ok := m[seg]
	if !ok {
		return nil, false
	}
	if !each {
		return resolve(next, segs[1:])
	}
	arr, ok := next.([]any)
	if !ok {
		return nil, false
	}
	var out []any
	for i, el := range arr {
		if i >= MaxArrayElements {
			break
		}
		if vs, ok := resolve(el, segs[1:]); ok {
			out = append(out, vs...)
		}
	}
	return out, true
}

func (r *Rule) holds(v any) bool {
	switch r.Op {
	case "eq":
		return equal(v, r.Value)
	case "ne":
		return !equal(v, r.Value)
	case "lt", "lte", "gt", "gte":
		f, ok := v.(float64)
		if !ok {
			return false
		}
		switch r.Op {
		case "lt":
			return f < r.num
		case "lte":
			return f <= r.num
		case "gt":
			return f > r.num
		}
		return f >= r.num
	case "in":
		return anyEqual(v, r.list)
	case "notIn":
		return !anyEqual(v, r.list)
	case "contains", "notContains":
		has := false
		switch x := v.(type) {
		case string:
			s, _ := r.Value.(string)
			has = s != "" && strings.Contains(x, s)
		case []any:
			has = anyEqual(r.Value, x)
		}
		return has == (r.Op == "contains")
	case "matches":
		s, ok := v.(string)
		return ok && r.re.MatchString(s)
	case "nonEmpty":
		switch x := v.(type) {
		case string:
			return strings.TrimSpace(x) != ""
		case []any:
			return len(x) > 0
		case map[string]any:
			return len(x) > 0
		}
		return false
	}
	return false
}

func equal(a, b any) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	}
	return false
}

func anyEqual(v any, list []any) bool {
	for _, e := range list {
		if equal(v, e) {
			return true
		}
	}
	return false
}

func render(v any) string {
	var s string
	switch x := v.(type) {
	case string:
		s = fmt.Sprintf("%q", x)
	case nil:
		s = "null"
	case float64, bool:
		s = fmt.Sprint(x)
	case []any:
		s = fmt.Sprintf("[%d items]", len(x))
	case map[string]any:
		s = "{object}"
	default:
		s = "?"
	}
	if len(s) > MaxEvidenceLen {
		s = s[:MaxEvidenceLen] + "..."
	}
	return s
}
