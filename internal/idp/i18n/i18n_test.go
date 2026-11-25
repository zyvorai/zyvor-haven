// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package i18n

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	long := strings.Repeat("xx,", 400) + "de"
	for _, c := range []struct {
		ui, accept, def, want string
	}{
		{"", "", "", "en"},
		{"", "", "hi", "hi"},
		{"", "", "fr", "en"},          // unsupported default
		{"de", "hi", "en", "de"},      // ui_locales beats Accept-Language
		{"fr de-CH hi", "", "", "de"}, // first supported entry wins
		{"fr", "hi-IN", "de", "hi"},   // unsupported ui_locales falls through
		{"", "de-AT,de;q=0.9,en;q=0.8", "", "de"},
		{"", "en;q=0.2,hi;q=0.9,de;q=0.9", "", "hi"}, // quality, then order
		{"", "de;q=0,hi;q=0.1", "", "hi"},            // q=0 is "not acceptable"
		{"", "de;q=0", "hi", "hi"},
		{"", "*", "de", "de"},
		{"", "fr,es", "de", "de"},
		{"", "de;q=2,hi;q=abc,en;q=NaN", "hi", "hi"}, // nonsense quality ignored
		{"", "en", "de", "en"},                       // the browser's English beats the realm default
		{"DE", "", "", "de"},
		{"", long, "hi", "hi"}, // over-long headers are ignored, not truncated into a match
		{`"><script>`, `de"><script>`, "../../x", "en"},
	} {
		if got := Match(c.ui, c.accept, c.def); got != c.want {
			t.Errorf("Match(%q, %.40q, %q) = %q, want %q", c.ui, c.accept, c.def, got, c.want)
		}
	}
}

func TestMatchReturnsOnlyOwnStrings(t *testing.T) {
	for _, in := range []string{"de-<b>", "hi_\"x", "EN-us"} {
		if got := Match(in, "", ""); !slices.Contains(Supported(), got) {
			t.Errorf("Match(%q) = %q, not a supported language", in, got)
		}
	}
}

func TestT(t *testing.T) {
	if got := T("de", "Sign in"); got != "Anmelden" {
		t.Errorf("de: %q", got)
	}
	if got := T("en", "Sign in to %s", "Acme"); got != "Sign in to Acme" {
		t.Errorf("en: %q", got)
	}
	if got := T("xx", "Sign in"); got != "Sign in" {
		t.Errorf("unknown language: %q", got)
	}
	if got := T("de", "a string nobody translated"); got != "a string nobody translated" {
		t.Errorf("missing key: %q", got)
	}
	// Without args the text is not a format string.
	if got := T("de", "100% sure %s"); got != "100% sure %s" {
		t.Errorf("verbatim: %q", got)
	}
	if got := T("de", "%s wants to sign in to %s as %s.", "App", "Realm", "bob"); got != "App möchte sich bei Realm als bob anmelden." {
		t.Errorf("reordered args: %q", got)
	}
}

func TestContext(t *testing.T) {
	ctx := context.Background()
	if LangFrom(ctx) != "" || LangFrom(WithLang(ctx, "fr")) != "" || LangFrom(WithLang(ctx, "")) != "" {
		t.Error("unsupported language recorded")
	}
	if LangFrom(WithLang(ctx, "hi")) != "hi" {
		t.Error("language lost")
	}
}

var verbRE = regexp.MustCompile(`%(\[([0-9]+)\])?([sdqv%])`)

// args returns the verb of every argument position of a format string.
func args(t *testing.T, s string) map[int]string {
	out := map[int]string{}
	next := 1
	for _, m := range verbRE.FindAllStringSubmatch(s, -1) {
		if m[3] == "%" {
			continue
		}
		i := next
		if m[2] != "" {
			i, _ = strconv.Atoi(m[2])
		}
		out[i] = m[3]
		next = i + 1
	}
	if rest := verbRE.ReplaceAllString(s, ""); strings.Contains(rest, "%") {
		t.Errorf("unsupported %% sequence in %q", s)
	}
	return out
}

// Every catalogue translates the same sentences, with the same arguments, as
// plain text.
func TestCatalogues(t *testing.T) {
	ref := Keys("de")
	if len(ref) < 200 {
		t.Fatalf("German catalogue has only %d entries", len(ref))
	}
	for _, lang := range Supported() {
		if lang == Default {
			continue
		}
		keys := Keys(lang)
		for _, k := range ref {
			if !slices.Contains(keys, k) {
				t.Errorf("%s: missing translation of %q", lang, k)
			}
		}
		for _, k := range keys {
			if !slices.Contains(ref, k) {
				t.Errorf("de: missing translation of %q", k)
			}
			v, _ := Lookup(lang, k)
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: empty translation of %q", lang, k)
			}
			if strings.ContainsAny(v, "<>") || strings.Contains(v, "://") {
				t.Errorf("%s: translation of %q carries markup or an address", lang, k)
			}
			want, got := args(t, k), args(t, v)
			if len(want) != len(got) {
				t.Errorf("%s: %q takes %v, translation takes %v", lang, k, want, got)
				continue
			}
			for i, verb := range want {
				if got[i] != verb {
					t.Errorf("%s: %q argument %d is %%%s, translation uses %%%s", lang, k, i, verb, got[i])
				}
			}
		}
	}
}
