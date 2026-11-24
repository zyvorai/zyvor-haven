// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SCIM filter (RFC 7644 section 3.4.2.2), a bounded subset: the comparison
// operators eq ne co sw ew and the presence test pr, combined with and / or
// and parentheses. Not supported (rejected as invalidFilter): not(), gt ge lt
// le, value paths such as emails[type eq "work"], and filter on schema URNs.
// The limits keep a hostile filter from costing more than a bounded parse and
// one bounded pass over the users.
const (
	scimMaxFilterLen   = 1024
	scimMaxFilterTerms = 16
	scimMaxFilterDepth = 4
)

type scimFilterErr string

func (e scimFilterErr) Error() string { return string(e) }

type fnode struct {
	op   string // and | or | eq | ne | co | sw | ew | pr
	l, r *fnode
	attr string // lower case
	val  any    // string | bool | nil (JSON null)
}

type ftok struct {
	s   string
	str bool // quoted string literal
}

func scimTokenize(in string) ([]ftok, error) {
	var out []ftok
	for i := 0; i < len(in); {
		c := in[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			out = append(out, ftok{s: string(c)})
			i++
		case c == '"':
			j := i + 1
			for ; j < len(in); j++ {
				if in[j] == '\\' {
					j++
					continue
				}
				if in[j] == '"' {
					break
				}
			}
			if j >= len(in) {
				return nil, scimFilterErr("unterminated string in filter")
			}
			var s string
			if err := json.Unmarshal([]byte(in[i:j+1]), &s); err != nil {
				return nil, scimFilterErr("invalid string in filter")
			}
			out = append(out, ftok{s: s, str: true})
			i = j + 1
		default:
			j := i
			for j < len(in) && in[j] != ' ' && in[j] != '\t' && in[j] != '(' && in[j] != ')' && in[j] != '"' {
				j++
			}
			out = append(out, ftok{s: in[i:j]})
			i = j
		}
		if len(out) > 4*scimMaxFilterTerms+8 {
			return nil, scimFilterErr("filter too complex")
		}
	}
	return out, nil
}

type fparser struct {
	t     []ftok
	p     int
	terms int
}

func (p *fparser) peekWord(w string) bool {
	return p.p < len(p.t) && !p.t[p.p].str && strings.EqualFold(p.t[p.p].s, w)
}

// parseSCIMFilter parses a filter. allowed lists the attribute paths (lower
// case) the resource supports; any other attribute is an error.
func parseSCIMFilter(in string, allowed map[string]bool) (*fnode, error) {
	if len(in) > scimMaxFilterLen {
		return nil, scimFilterErr("filter too long")
	}
	toks, err := scimTokenize(in)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, scimFilterErr("empty filter")
	}
	p := &fparser{t: toks}
	n, err := p.or(0, allowed)
	if err != nil {
		return nil, err
	}
	if p.p != len(p.t) {
		return nil, scimFilterErr("unexpected token in filter")
	}
	return n, nil
}

func (p *fparser) or(depth int, allowed map[string]bool) (*fnode, error) {
	l, err := p.and(depth, allowed)
	if err != nil {
		return nil, err
	}
	for p.peekWord("or") {
		p.p++
		r, err := p.and(depth, allowed)
		if err != nil {
			return nil, err
		}
		l = &fnode{op: "or", l: l, r: r}
	}
	return l, nil
}

func (p *fparser) and(depth int, allowed map[string]bool) (*fnode, error) {
	l, err := p.term(depth, allowed)
	if err != nil {
		return nil, err
	}
	for p.peekWord("and") {
		p.p++
		r, err := p.term(depth, allowed)
		if err != nil {
			return nil, err
		}
		l = &fnode{op: "and", l: l, r: r}
	}
	return l, nil
}

func (p *fparser) term(depth int, allowed map[string]bool) (*fnode, error) {
	if p.p >= len(p.t) {
		return nil, scimFilterErr("unexpected end of filter")
	}
	tk := p.t[p.p]
	if !tk.str && tk.s == "(" {
		if depth+1 > scimMaxFilterDepth {
			return nil, scimFilterErr("filter nested too deeply")
		}
		p.p++
		n, err := p.or(depth+1, allowed)
		if err != nil {
			return nil, err
		}
		if p.p >= len(p.t) || p.t[p.p].str || p.t[p.p].s != ")" {
			return nil, scimFilterErr("missing closing parenthesis in filter")
		}
		p.p++
		return n, nil
	}
	if tk.str || tk.s == ")" {
		return nil, scimFilterErr("expected an attribute in filter")
	}
	if strings.EqualFold(tk.s, "not") {
		return nil, scimFilterErr("not() is not supported")
	}
	attr := strings.ToLower(tk.s)
	if !allowed[attr] {
		return nil, scimFilterErr(fmt.Sprintf("filter attribute %q is not supported", trunc(tk.s, 64)))
	}
	p.terms++
	if p.terms > scimMaxFilterTerms {
		return nil, scimFilterErr("filter has too many terms")
	}
	p.p++
	if p.p >= len(p.t) || p.t[p.p].str {
		return nil, scimFilterErr("expected a filter operator")
	}
	op := strings.ToLower(p.t[p.p].s)
	p.p++
	switch op {
	case "pr":
		return &fnode{op: "pr", attr: attr}, nil
	case "eq", "ne", "co", "sw", "ew":
	default:
		return nil, scimFilterErr(fmt.Sprintf("filter operator %q is not supported", trunc(op, 16)))
	}
	if p.p >= len(p.t) {
		return nil, scimFilterErr("expected a filter value")
	}
	v := p.t[p.p]
	p.p++
	n := &fnode{op: op, attr: attr}
	switch {
	case v.str:
		n.val = v.s
	case v.s == "true":
		n.val = true
	case v.s == "false":
		n.val = false
	case v.s == "null":
		n.val = nil
	default:
		return nil, scimFilterErr("filter values must be quoted strings, true, false or null")
	}
	if _, isStr := n.val.(string); !isStr && op != "eq" && op != "ne" {
		return nil, scimFilterErr("co, sw and ew need a string value")
	}
	return n, nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// eqAttr returns the single attribute and value when n is exactly
// `attr eq "string"`, so callers can use an index instead of a scan.
func (n *fnode) eqAttr() (attr, val string, ok bool) {
	if n == nil || n.op != "eq" {
		return "", "", false
	}
	s, isStr := n.val.(string)
	return n.attr, s, isStr
}

// scimGet returns the values of an attribute (nil when absent).
type scimGet func(attr string) []any

// eval reports whether the resource matches. Strings compare case-insensitively
// except attributes listed in exact (ids).
func (n *fnode) eval(get scimGet, exact map[string]bool) bool {
	switch n.op {
	case "and":
		return n.l.eval(get, exact) && n.r.eval(get, exact)
	case "or":
		return n.l.eval(get, exact) || n.r.eval(get, exact)
	}
	vals := get(n.attr)
	if n.op == "pr" {
		for _, v := range vals {
			if s, isStr := v.(string); !isStr || s != "" {
				return true
			}
		}
		return false
	}
	hit := false
	for _, v := range vals {
		if fmatch(n.op, v, n.val, exact[n.attr]) {
			hit = true
			break
		}
	}
	if n.op == "ne" {
		return !anyEq(vals, n.val, exact[n.attr])
	}
	return hit
}

func anyEq(vals []any, want any, exact bool) bool {
	for _, v := range vals {
		if fmatch("eq", v, want, exact) {
			return true
		}
	}
	return false
}

func fmatch(op string, have, want any, exact bool) bool {
	switch w := want.(type) {
	case nil:
		return have == nil || have == ""
	case bool:
		b, ok := have.(bool)
		return ok && b == w
	case string:
		h, ok := have.(string)
		if !ok {
			return false
		}
		if !exact {
			h, w = strings.ToLower(h), strings.ToLower(w)
		}
		switch op {
		case "eq", "ne":
			return h == w
		case "co":
			return strings.Contains(h, w)
		case "sw":
			return strings.HasPrefix(h, w)
		case "ew":
			return strings.HasSuffix(h, w)
		}
	}
	return false
}
