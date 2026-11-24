// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"strings"
	"testing"
)

func TestSCIMFilterParseAndEval(t *testing.T) {
	get := func(a string) []any {
		switch a {
		case "username":
			return []any{"Alice.Smith"}
		case "active":
			return []any{true}
		case "emails.value":
			return []any{"alice@example.com"}
		case "id":
			return []any{"AbC"}
		}
		return nil
	}
	cases := []struct {
		f    string
		want bool
	}{
		{`userName eq "alice.smith"`, true}, // case-insensitive
		{`USERNAME EQ "alice.smith"`, true}, // attribute and operator names are case-insensitive
		{`userName ne "alice.smith"`, false},
		{`userName co "ce.sm"`, true},
		{`userName sw "alice"`, true},
		{`userName ew "SMITH"`, true},
		{`userName sw "smith"`, false},
		{`active eq true`, true},
		{`active eq false`, false},
		{`name.givenName pr`, false},
		{`emails.value pr`, true},
		{`id eq "abc"`, false}, // ids are case-exact
		{`id eq "AbC"`, true},
		{`userName eq "x" or active eq true`, true},
		{`userName eq "x" and active eq true`, false},
		{`userName eq "x" or userName eq "alice.smith" and active eq true`, true}, // and binds tighter
		{`(userName eq "x" or active eq true) and emails.value ew "example.com"`, true},
		{`userName eq "a\"b"`, false},
		{`name.givenName ne "bob"`, true}, // absent attribute is not equal
	}
	for _, c := range cases {
		n, err := parseSCIMFilter(c.f, scimUserAttrs)
		if err != nil {
			t.Errorf("%s: %v", c.f, err)
			continue
		}
		if got := n.eval(get, scimExactAttrs); got != c.want {
			t.Errorf("%s: got %v want %v", c.f, got, c.want)
		}
	}
}

func TestSCIMFilterRejects(t *testing.T) {
	long := `userName eq "` + strings.Repeat("a", scimMaxFilterLen) + `"`
	terms := strings.TrimSuffix(strings.Repeat(`active eq true or `, scimMaxFilterTerms+1), " or ")
	deep := strings.Repeat("(", scimMaxFilterDepth+1) + `active eq true` + strings.Repeat(")", scimMaxFilterDepth+1)
	bad := map[string]string{
		"empty":            ``,
		"too long":         long,
		"too many terms":   terms,
		"too deep":         deep,
		"unknown attr":     `password eq "x"`,
		"roles":            `roles eq "admin"`,
		"gt":               `active gt true`,
		"not":              `not (active eq true)`,
		"value path":       `emails[type eq "work"].value eq "x"`,
		"unquoted":         `userName eq alice`,
		"missing value":    `userName eq`,
		"missing paren":    `(userName eq "a"`,
		"extra paren":      `userName eq "a")`,
		"unterminated":     `userName eq "a`,
		"trailing garbage": `userName eq "a" "b"`,
		"co on bool":       `active co true`,
		"dangling and":     `userName eq "a" and`,
	}
	for name, f := range bad {
		if _, err := parseSCIMFilter(f, scimUserAttrs); err == nil {
			t.Errorf("%s: filter %.40q was accepted", name, f)
		}
	}
	// A filter at exactly the limits is fine.
	ok := strings.TrimSuffix(strings.Repeat(`active eq true or `, scimMaxFilterTerms), " or ")
	if _, err := parseSCIMFilter(ok, scimUserAttrs); err != nil {
		t.Errorf("filter at the term limit rejected: %v", err)
	}
}
