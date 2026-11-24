// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package realmdiff

import (
	"strings"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"a", "a", true}, {"a", "ab", false}, {"*", "anything", true},
		{"a*c", "abc", true}, {"a*c", "ac", true}, {"a*c", "abd", false},
		{"*.attributes.*", "clients[x].attributes.k", true},
		{"a*b*c", "aXbYc", true}, {"a*b*c", "acb", false},
		{"ab*ab", "ab", false}, {"ab*ab", "abab", true},
	}
	for _, c := range cases {
		if got := globMatch(c.p, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.p, c.s, got, c.want)
		}
	}
}

func TestFilterIgnoresPathsAndChildren(t *testing.T) {
	before := `{"realm":"r","displayName":"A","attributes":{"x":"1","y":"1"},"clients":[{"clientId":"c","description":"d1","enabled":true}]}`
	after := `{"realm":"r","displayName":"B","attributes":{"x":"2","y":"2"},"clients":[{"clientId":"c","description":"d2","enabled":false}]}`
	res, err := CompareJSON([]byte(before), []byte(after))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changed) != 5 {
		t.Fatalf("setup: %+v", res.Changed)
	}
	got := res.Filter([]string{"attributes", "*.description", "  "})
	if len(got.Changed) != 2 {
		t.Fatalf("filtered: %+v", got.Changed)
	}
	for _, c := range got.Changed {
		if strings.Contains(c.Path, "attributes") || strings.HasSuffix(c.Path, "description") {
			t.Errorf("not filtered: %s", c.Path)
		}
	}
	if all := res.Filter([]string{"*"}); !all.Empty() {
		t.Errorf("* should drop everything: %+v", all)
	}
	if same := res.Filter(nil); len(same.Changed) != 5 {
		t.Error("nil globs must keep everything")
	}
	// A prefix that is not a path boundary must not match.
	if got := res.Filter([]string{"display"}); len(got.Changed) != 5 {
		t.Errorf("partial segment matched: %+v", got.Changed)
	}
}

func TestMarkdownRendersDiffBlock(t *testing.T) {
	res := Result{Added: []Change{{Path: "a", After: "1"}}, Removed: []Change{{Path: "b", Before: "2"}},
		Changed: []Change{{Path: "c", Before: "x\ny", After: "z"}}}
	md := res.Markdown()
	for _, want := range []string{"1 added, 1 removed, 1 changed", "~~~diff", "+ a = 1", "- b = 2", "- c = x y", "+ c = z"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in\n%s", want, md)
		}
	}
	if !strings.Contains((Result{}).Markdown(), "No differences.") {
		t.Error("empty result text")
	}
}
