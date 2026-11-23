// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package realmdiff

import (
	"fmt"
	"strings"
	"testing"
)

func TestCompareJSON(t *testing.T) {
	const base = `{"realm":"a","id":"1","accessTokenLifespan":300,"smtpServer":{"host":"h","password":"hunter2"},
	 "clients":[{"id":"u1","clientId":"web","secret":"s3cret","redirectUris":["https://a/cb"]},{"id":"u2","clientId":"api"}]}`
	cases := []struct {
		name                    string
		after                   string
		added, removed, changed int
		mustContain             []string
		mustNotContain          []string
	}{
		{"identical", base, 0, 0, 0, nil, nil},
		{"ids and ordering ignored", `{"realm":"a","id":"ZZZ","accessTokenLifespan":300,"smtpServer":{"host":"h","password":"hunter2"},
		 "clients":[{"id":"x2","clientId":"api"},{"id":"x1","clientId":"web","secret":"s3cret","redirectUris":["https://a/cb"]}]}`, 0, 0, 0, nil, nil},
		{"scalar change", strings.Replace(base, `300`, `3600`, 1), 0, 0, 1, []string{"accessTokenLifespan"}, nil},
		{"secret change is redacted and invisible", strings.Replace(strings.Replace(base, "hunter2", "other-pass", 1), "s3cret", "n3w", 1), 0, 0, 0, nil, []string{"hunter2", "other-pass", "s3cret", "n3w"}},
		{"client added", strings.Replace(base, `{"id":"u2","clientId":"api"}`, `{"id":"u2","clientId":"api"},{"clientId":"new","redirectUris":["*"]}`, 1), 2, 0, 0, []string{"clients[new].clientId", `clients[new].redirectUris["*"]`}, nil},
		{"redirect removed", strings.Replace(base, `"redirectUris":["https://a/cb"]`, `"redirectUris":[]`, 1), 1, 1, 0, []string{`redirectUris["https://a/cb"]`}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CompareJSON([]byte(base), []byte(tc.after))
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Added) != tc.added || len(res.Removed) != tc.removed || len(res.Changed) != tc.changed {
				t.Fatalf("added=%d removed=%d changed=%d: %+v", len(res.Added), len(res.Removed), len(res.Changed), res)
			}
			dump := fmt.Sprintf("%+v", res)
			for _, s := range tc.mustContain {
				if !strings.Contains(dump, s) {
					t.Errorf("expected %q in %s", s, dump)
				}
			}
			for _, s := range tc.mustNotContain {
				if strings.Contains(dump, s) {
					t.Errorf("leaked %q in %s", s, dump)
				}
			}
		})
	}
}

func TestCompareJSONHostile(t *testing.T) {
	deep := strings.Repeat(`{"a":`, MaxDepth+5) + "1" + strings.Repeat("}", MaxDepth+5)
	cases := map[string]struct{ before, after string }{
		"invalid before": {`{`, `{}`},
		"invalid after":  {`{}`, `nope`},
		"too deep":       {deep, `{}`},
		"oversize":       {strings.Repeat(" ", MaxDocBytes+1), `{}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := CompareJSON([]byte(c.before), []byte(c.after)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLongValuesTruncatedAndDuplicateKeysFallBack(t *testing.T) {
	long := strings.Repeat("x", 500)
	res, err := CompareJSON([]byte(`{"n":"`+long+`","l":[{"name":"a"},{"name":"a"}]}`), []byte(`{"n":"y","l":[{"name":"a"},{"name":"b"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Changed {
		if len(c.Before) > MaxValueLen+3 {
			t.Fatalf("not truncated: %d", len(c.Before))
		}
	}
	if res.Empty() {
		t.Fatal("expected differences")
	}
}

func TestScalarArraysCompareAsSets(t *testing.T) {
	res, err := CompareJSON([]byte(`{"u":["b","a"]}`), []byte(`{"u":["a","b"]}`))
	if err != nil || !res.Empty() {
		t.Fatalf("reordered scalar arrays should be equal: %v %+v", err, res)
	}
}
