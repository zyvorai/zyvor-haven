// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustPolicy(t *testing.T, rule string) *Policy {
	t.Helper()
	p, err := Parse([]byte(`{"version":1,"rules":[` + rule + `]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func doc(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseRejectsHostilePolicies(t *testing.T) {
	long := strings.Repeat("a", 301)
	cases := map[string]string{
		"bad version":      `{"version":2,"rules":[]}`,
		"no rules":         `{"version":1,"rules":[]}`,
		"unknown field":    `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"x","op":"present","extra":1}]}`,
		"trailing data":    `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"x","op":"present"}]} {}`,
		"bad id":           `{"version":1,"rules":[{"id":"a b","severity":"high","title":"t","path":"x","op":"present"}]}`,
		"bad severity":     `{"version":1,"rules":[{"id":"A","severity":"urgent","title":"t","path":"x","op":"present"}]}`,
		"no title":         `{"version":1,"rules":[{"id":"A","severity":"high","title":" ","path":"x","op":"present"}]}`,
		"long title":       `{"version":1,"rules":[{"id":"A","severity":"high","title":"` + long + `","path":"x","op":"present"}]}`,
		"bad op":           `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"x","op":"exec"}]}`,
		"bad scope":        `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","scope":"user","path":"x","op":"present"}]}`,
		"secret path":      `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"clients[].secret","op":"present"}]}`,
		"token path":       `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"attributes.access_token","op":"present"}]}`,
		"password path":    `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"smtpServer.password","op":"present"}]}`,
		"deep path":        `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a.b.c.d.e.f.g.h.i","op":"present"}]}`,
		"empty segment":    `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a..b","op":"present"}]}`,
		"weird segment":    `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a/b","op":"present"}]}`,
		"value on present": `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a","op":"present","value":1}]}`,
		"lt string":        `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a","op":"lt","value":"5"}]}`,
		"in not list":      `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a","op":"in","value":"x"}]}`,
		"in nested":        `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a","op":"in","value":[[1]]}]}`,
		"bad regex":        `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a","op":"matches","value":"("}]}`,
		"long regex":       `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a","op":"matches","value":"` + strings.Repeat("a", 257) + `"}]}`,
		"object value":     `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a","op":"eq","value":{"x":1}}]}`,
		"duplicate id":     `{"version":1,"rules":[{"id":"A","severity":"high","title":"t","path":"a","op":"present"},{"id":"A","severity":"low","title":"t","path":"b","op":"present"}]}`,
		"not json":         `rules: []`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestParseSizeCaps(t *testing.T) {
	if _, err := Parse(make([]byte, MaxPolicyBytes+1)); err == nil {
		t.Fatal("oversize policy accepted")
	}
	var b strings.Builder
	b.WriteString(`{"version":1,"rules":[`)
	for i := 0; i <= MaxRules; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"id":"R` + strings.Repeat("1", 1) + string(rune('a'+i%26)) + strings.Repeat("x", i/26) + `","severity":"low","title":"t","path":"a","op":"present"}`)
	}
	b.WriteString(`]}`)
	if _, err := Parse([]byte(b.String())); err == nil {
		t.Fatal("too many rules accepted")
	}
}

func TestEvaluate(t *testing.T) {
	realm := doc(t, `{"realm":"acme","accessTokenLifespan":900,"sslRequired":"external","displayName":"",
	 "smtpServer":{"host":"smtp.example"},
	 "clients":[
	  {"clientId":"account","redirectUris":["*"]},
	  {"clientId":"web","redirectUris":["https://a.example/cb","http://b.example/cb"],"attributes":{"pkce.code.challenge.method":"S256"}},
	  {"clientId":"api","redirectUris":[]}
	 ]}`)
	cases := []struct {
		name string
		rule string
		want []string // "client|evidence-substring"; empty = no finding
	}{
		{"lte pass", `{"id":"T1","severity":"high","title":"t","path":"accessTokenLifespan","op":"lte","value":900}`, nil},
		{"lte fail", `{"id":"T1","severity":"high","title":"t","path":"accessTokenLifespan","op":"lte","value":300}`, []string{"|accessTokenLifespan=900"}},
		{"eq string", `{"id":"T1","severity":"low","title":"t","path":"sslRequired","op":"eq","value":"all"}`, []string{`|sslRequired="external"`}},
		{"in pass", `{"id":"T1","severity":"low","title":"t","path":"sslRequired","op":"in","value":["external","all"]}`, nil},
		{"notIn fail", `{"id":"T1","severity":"low","title":"t","path":"sslRequired","op":"notIn","value":["external"]}`, []string{"|sslRequired"}},
		{"missing path violates", `{"id":"T1","severity":"low","title":"t","path":"passwordPolicy","op":"nonEmpty"}`, []string{"|missing passwordPolicy"}},
		{"optional missing passes", `{"id":"T1","severity":"low","title":"t","path":"passwordPolicy","op":"nonEmpty","optional":true}`, nil},
		{"nonEmpty empty string", `{"id":"T1","severity":"low","title":"t","path":"displayName","op":"nonEmpty"}`, []string{"|displayName"}},
		{"present", `{"id":"T1","severity":"low","title":"t","path":"smtpServer.host","op":"present"}`, nil},
		{"absent fail", `{"id":"T1","severity":"low","title":"t","path":"smtpServer","op":"absent"}`, []string{"|present smtpServer"}},
		{"type mismatch fails closed", `{"id":"T1","severity":"low","title":"t","path":"sslRequired","op":"lt","value":5}`, []string{"|sslRequired"}},
		{"client scope skips builtin", `{"id":"T1","severity":"high","title":"t","scope":"client","path":"redirectUris[]","op":"matches","value":"^https://"}`, []string{"web|http://b.example/cb"}},
		{"client scope builtin opt-in", `{"id":"T1","severity":"high","title":"t","scope":"client","includeBuiltin":true,"path":"redirectUris[]","op":"matches","value":"^https://"}`, []string{"account|", "web|http://b.example/cb"}},
		{"client nested attr", `{"id":"T1","severity":"high","title":"t","scope":"client","path":"attributes.pkce.code.challenge.method","op":"eq","value":"S256","optional":true}`, nil},
		{"empty array missing", `{"id":"T1","severity":"high","title":"t","scope":"client","path":"redirectUris[]","op":"present"}`, []string{"api|missing"}},
		{"contains on array", `{"id":"T1","severity":"low","title":"t","scope":"client","path":"redirectUris","op":"contains","value":"https://a.example/cb"}`, []string{"api|", "web|"}[0:0]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustPolicy(t, tc.rule).Evaluate("acme", realm)
			if tc.name == "contains on array" {
				if len(got) != 1 || got[0].ClientID != "api" {
					t.Fatalf("got %+v", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings %+v, want %d", len(got), got, len(tc.want))
			}
			for i, w := range tc.want {
				parts := strings.SplitN(w, "|", 2)
				if got[i].ClientID != parts[0] || !strings.Contains(got[i].Evidence, parts[1]) {
					t.Errorf("finding %d = %+v, want client %q evidence ~%q", i, got[i], parts[0], parts[1])
				}
				if !strings.HasPrefix(got[i].RuleID, "POLICY-") {
					t.Errorf("rule id %q", got[i].RuleID)
				}
			}
		})
	}
}

func TestEvaluateCapsAndTruncates(t *testing.T) {
	clients := make([]any, 0, 200)
	for i := 0; i < 200; i++ {
		clients = append(clients, map[string]any{"clientId": "c" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26)), "name": strings.Repeat("v", 500)})
	}
	p := mustPolicy(t, `{"id":"CAP","severity":"low","title":"t","scope":"client","path":"name","op":"eq","value":"ok"}`)
	got := p.Evaluate("r", map[string]any{"clients": clients})
	if len(got) != MaxFindingsRule {
		t.Fatalf("expected cap %d, got %d", MaxFindingsRule, len(got))
	}
	for _, f := range got {
		if len(f.Evidence) > MaxEvidenceLen+len("name=")+10 {
			t.Fatalf("evidence not truncated: %d", len(f.Evidence))
		}
	}
}

func TestEvaluateIsDeterministicAndHandlesNonObjects(t *testing.T) {
	p := mustPolicy(t, `{"id":"D","severity":"low","title":"t","scope":"client","path":"x","op":"present"}`)
	d := map[string]any{"clients": []any{"str", 5, nil, map[string]any{"clientId": "b"}, map[string]any{"clientId": "a"}}}
	a, b := p.Evaluate("r", d), p.Evaluate("r", d)
	if len(a) != 2 || a[0].ClientID != "a" || a[1].ClientID != "b" {
		t.Fatalf("unexpected order %+v", a)
	}
	if a[0] != b[0] || a[1] != b[1] {
		t.Fatal("non deterministic")
	}
	if got := p.Evaluate("r", map[string]any{"clients": "nope"}); len(got) != 0 {
		t.Fatal("non-array clients should produce nothing")
	}
}
