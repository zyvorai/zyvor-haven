// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"strings"
	"testing"
)

func TestDefaultACRLadder(t *testing.T) {
	p := DefaultACRPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	const one, two, phr = ACRSingleFactor, ACRMultiFactor, ACRPhishingResistant
	for _, c := range []struct {
		amr  string
		want string // highest level reached, "" none
	}{
		{"", ""},
		{"otp", ""}, // a second factor alone is not a login
		{"user uv", ""},
		{"pwd", one},
		{"fed", one}, // whatever the upstream did is not known
		{"webauthn user", one},
		{"pwd otp mfa", two},
		{"pwd recovery mfa", two},
		{"pwd webauthn user mfa", phr},
		{"webauthn user uv mfa", phr},
	} {
		amr := strings.Fields(c.amr)
		got, ok := p.Select(amr, ACRRequirement{})
		if !ok || got != c.want {
			t.Errorf("%q: acr %q ok %v, want %q", c.amr, got, ok, c.want)
		}
		for i, l := range p.Levels {
			want := c.want != "" && i <= p.Index(c.want)
			if p.Meets(amr, l.Value) != want {
				t.Errorf("%q meets %s = %v", c.amr, l.Value, !want)
			}
		}
		if p.Meets(amr, "unknown") {
			t.Errorf("%q meets an unknown level", c.amr)
		}
	}
}

func TestACRSelect(t *testing.T) {
	p := DefaultACRPolicy()
	const one, two, phr = ACRSingleFactor, ACRMultiFactor, ACRPhishingResistant
	mfa := []string{"pwd", "otp", "mfa"}
	pk := []string{"webauthn", "user", "uv", "mfa"}
	req := func(sets ...[]string) ACRRequirement { return ACRRequirement{Sets: sets} }
	s := func(v ...string) []string { return v }
	for _, c := range []struct {
		name string
		amr  []string
		req  ACRRequirement
		acr  string
		ok   bool
	}{
		{"weaker than asked", []string{"pwd"}, req(s(two)), "", false},
		{"nothing observed", nil, req(s(one)), "", false},
		{"nothing observed, any level", nil, req(s()), "", false},
		{"any level", []string{"pwd"}, req(s()), one, true},
		{"exact", mfa, req(s(two)), two, true},
		{"stronger login reports the requested level", pk, req(s(two)), two, true},
		{"first met preference wins", pk, req(s(phr, two)), phr, true},
		{"unmet preference is skipped", mfa, req(s(phr, two)), two, true},
		{"unknown preference is skipped", mfa, req(s("x", two)), two, true},
		{"only unknown", pk, req(s("x")), "", false},
		{"every set must be met", mfa, req(s(one), s(phr)), "", false},
		{"the first set names the claim", pk, req(s(two), s(phr)), two, true},
		{"an empty set then values", pk, req(s(), s(two)), two, true},
	} {
		acr, ok := p.Select(c.amr, c.req)
		if acr != c.acr || ok != c.ok {
			t.Errorf("%s: %q %v, want %q %v", c.name, acr, ok, c.acr, c.ok)
		}
	}
	if !p.Satisfiable(req(s("x", two), s())) || p.Satisfiable(req(s(two), s("x"))) {
		t.Error("satisfiability")
	}
	if (ACRPolicy{}).Satisfiable(req(s())) {
		t.Error("an empty ladder satisfies nothing")
	}
}

func TestACRPolicyValidate(t *testing.T) {
	lvl := func(v string, alts ...[]string) ACRLevel { return ACRLevel{Value: v, AnyOf: alts} }
	pw := []string{AMRPassword}
	good := ACRPolicy{Levels: []ACRLevel{lvl("a", pw)}, AdminACR: "a", AdminMaxAgeSeconds: 60}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	many := ACRPolicy{}
	for i := range MaxACRLevels + 1 {
		many.Levels = append(many.Levels, lvl(strings.Repeat("a", i+1), pw))
	}
	for name, p := range map[string]ACRPolicy{
		"no levels":            {},
		"too many levels":      many,
		"empty value":          {Levels: []ACRLevel{lvl("", pw)}},
		"space":                {Levels: []ACRLevel{lvl("a b", pw)}},
		"quote":                {Levels: []ACRLevel{lvl(`a"`, pw)}},
		"backslash":            {Levels: []ACRLevel{lvl(`a\`, pw)}},
		"newline":              {Levels: []ACRLevel{lvl("a\nb", pw)}},
		"non ascii":            {Levels: []ACRLevel{lvl("é", pw)}},
		"long":                 {Levels: []ACRLevel{lvl(strings.Repeat("a", 129), pw)}},
		"duplicate":            {Levels: []ACRLevel{lvl("a", pw), lvl("a", pw)}},
		"no alternative":       {Levels: []ACRLevel{lvl("a")}},
		"empty alternative":    {Levels: []ACRLevel{lvl("a", []string{})}},
		"unknown method":       {Levels: []ACRLevel{lvl("a", []string{"sms"})}},
		"admin acr unknown":    {Levels: []ACRLevel{lvl("a", pw)}, AdminACR: "b"},
		"negative max age":     {Levels: []ACRLevel{lvl("a", pw)}, AdminMaxAgeSeconds: -1},
		"huge max age":         {Levels: []ACRLevel{lvl("a", pw)}, AdminMaxAgeSeconds: 1 << 40},
		"too many alternative": {Levels: []ACRLevel{lvl("a", make([][]string, MaxACRAlternatives+1)...)}},
	} {
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An empty alternative never matches, even if one got into a store.
	if (ACRPolicy{Levels: []ACRLevel{lvl("a", []string{})}}).Rank(nil) != -1 {
		t.Error("an empty alternative must not be reached")
	}
}
