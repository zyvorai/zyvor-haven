// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package posture

import (
	"encoding/json"
	"encoding/xml"
	"github.com/zyvorai/haven/internal/idp"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRound3RealmRules(t *testing.T) {
	cases := []struct {
		name   string
		h      *idp.RealmHardening
		want   []string
		absent []string
	}{
		{"events kept forever", &idp.RealmHardening{EventsExpiration: ip(0)}, []string{"HAVEN024"}, nil},
		{"events with retention", &idp.RealmHardening{EventsExpiration: ip(7776000)}, nil, []string{"HAVEN024"}},
		{"events off, no retention needed", &idp.RealmHardening{EventsEnabled: bp(false), EventsExpiration: ip(0)}, []string{"HAVEN019"}, []string{"HAVEN024"}},
		{"unreported retention", &idp.RealmHardening{}, nil, []string{"HAVEN024"}},
		{"reuse with rotation", &idp.RealmHardening{RevokeRefreshToken: bp(true), RefreshTokenMaxReuse: ip(2)}, []string{"HAVEN025"}, nil},
		{"no reuse", &idp.RealmHardening{RevokeRefreshToken: bp(true), RefreshTokenMaxReuse: ip(0)}, nil, []string{"HAVEN025"}},
		{"reuse without rotation is moot", &idp.RealmHardening{RevokeRefreshToken: bp(false), RefreshTokenMaxReuse: ip(2)}, nil, []string{"HAVEN025"}},
		{"loose lockout", &idp.RealmHardening{FailureFactor: ip(30)}, []string{"HAVEN026"}, nil},
		{"boundary lockout", &idp.RealmHardening{FailureFactor: ip(10)}, nil, []string{"HAVEN026"}},
		{"offline unlimited", &idp.RealmHardening{OfflineSessionMaxLifespanEnabled: bp(false)}, []string{"HAVEN027"}, nil},
		{"offline limited", &idp.RealmHardening{OfflineSessionMaxLifespanEnabled: bp(true)}, nil, []string{"HAVEN027"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			realm := idp.Realm{Realm: "r", Enabled: true, VerifyEmail: true, BruteForceProtected: true, RealmHardening: tc.h}
			got := ruleIDs(evalKC([]idp.Realm{realm}, nil, Options{}))
			for _, id := range tc.want {
				if !got[id] {
					t.Errorf("missing %s", id)
				}
			}
			for _, id := range tc.absent {
				if got[id] {
					t.Errorf("unexpected %s", id)
				}
			}
		})
	}
	// Lockout threshold is moot when brute-force detection is off (HAVEN012 covers that).
	off := idp.Realm{Realm: "r", Enabled: true, RealmHardening: &idp.RealmHardening{FailureFactor: ip(30)}}
	if ruleIDs(evalKC([]idp.Realm{off}, nil, Options{}))["HAVEN026"] {
		t.Error("HAVEN026 reported with brute-force detection off")
	}
}

func TestRound3ClientRules(t *testing.T) {
	yes, no := true, false
	base := idp.Client{ClientID: "app", Enabled: true, StandardFlowEnabled: true, RedirectURIs: []string{"https://a.example/cb"}}
	mk := func(f func(c *idp.Client)) idp.Client { c := base; f(&c); return c }
	cases := []struct {
		name   string
		c      idp.Client
		want   string
		absent string
	}{
		{"full scope", mk(func(c *idp.Client) { c.FullScopeAllowed = &yes }), "HAVEN028", ""},
		{"scoped", mk(func(c *idp.Client) { c.FullScopeAllowed = &no }), "", "HAVEN028"},
		{"unreported scope", base, "", "HAVEN028"},
		{"bearer-only full scope ignored", mk(func(c *idp.Client) { c.BearerOnly = true; c.FullScopeAllowed = &yes }), "", "HAVEN028"},
		{"offline default", mk(func(c *idp.Client) { c.DefaultClientScopes = []string{"profile", "offline_access"} }), "HAVEN029", ""},
		{"no offline default", mk(func(c *idp.Client) { c.DefaultClientScopes = []string{"profile"} }), "", "HAVEN029"},
		{"long client token", mk(func(c *idp.Client) { c.Attributes = map[string]string{"access.token.lifespan": "86400"} }), "HAVEN030", ""},
		{"short client token", mk(func(c *idp.Client) { c.Attributes = map[string]string{"access.token.lifespan": "300"} }), "", "HAVEN030"},
		{"garbage client token", mk(func(c *idp.Client) { c.Attributes = map[string]string{"access.token.lifespan": "x"} }), "", "HAVEN030"},
		{"saml skipped", mk(func(c *idp.Client) { c.Protocol = "saml"; c.FullScopeAllowed = &yes }), "", "HAVEN028"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			realm := idp.Realm{Realm: "r", Enabled: true, VerifyEmail: true, BruteForceProtected: true}
			got := ruleIDs(evalKC([]idp.Realm{realm}, map[string][]idp.Client{"r": {tc.c}}, Options{}))
			if tc.want != "" && !got[tc.want] {
				t.Errorf("missing %s", tc.want)
			}
			if tc.absent != "" && got[tc.absent] {
				t.Errorf("unexpected %s", tc.absent)
			}
		})
	}
}

func TestRound3FieldsDecodeFromRealmExport(t *testing.T) {
	var c idp.Client
	if err := json.Unmarshal([]byte(`{"clientId":"x","fullScopeAllowed":true,"defaultClientScopes":["offline_access"]}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.FullScopeAllowed == nil || !*c.FullScopeAllowed || len(c.DefaultClientScopes) != 1 {
		t.Fatalf("client fields not decoded: %+v", c)
	}
	var r idp.Realm
	if err := json.Unmarshal([]byte(`{"realm":"r","eventsExpiration":0,"failureFactor":30,"refreshTokenMaxReuse":1,"offlineSessionMaxLifespanEnabled":false}`), &r); err != nil {
		t.Fatal(err)
	}
	h := r.RealmHardening
	if h == nil || h.EventsExpiration == nil || h.FailureFactor == nil || *h.FailureFactor != 30 || h.OfflineSessionMaxLifespanEnabled == nil {
		t.Fatalf("realm fields not decoded: %+v", h)
	}
}

func TestRuleCatalogAndDocsAgree(t *testing.T) {
	all := Rules()
	if len(all) < 30 {
		t.Fatalf("catalog has %d rules", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].ID >= all[i].ID {
			t.Fatalf("catalog not sorted: %s, %s", all[i-1].ID, all[i].ID)
		}
	}
	doc, err := os.ReadFile("../../docs/security-posture.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\| (HAVEN\d+) \| (\w+) \|`).FindAllStringSubmatch(string(doc), -1) {
		documented[m[1]] = m[2]
	}
	for _, r := range all {
		sev, ok := documented[r.ID]
		if !ok {
			t.Errorf("%s missing from docs/security-posture.md rule table", r.ID)
		} else if sev != string(r.Severity) {
			t.Errorf("%s severity %s in docs, %s in code", r.ID, sev, r.Severity)
		}
	}
	if r, ok := RuleByID(" haven029 "); !ok || r.ID != "HAVEN029" {
		t.Errorf("RuleByID is not case/space tolerant: %+v %v", r, ok)
	}
	if _, ok := RuleByID("HAVEN999"); ok {
		t.Error("unknown rule found")
	}
}

func sampleReport(t *testing.T) Report {
	t.Helper()
	realm := idp.Realm{Realm: "prod", Enabled: true, VerifyEmail: true, BruteForceProtected: true}
	clients := map[string][]idp.Client{"prod": {{ClientID: "a|b <img>", Enabled: true, PublicClient: true, ImplicitFlowEnabled: true}}}
	return evalKC([]idp.Realm{realm}, clients, Options{})
}

func TestMarkdownEscapesEvidenceAndListsFindings(t *testing.T) {
	r := sampleReport(t)
	r.Findings[0].Evidence = "line1\nline2 | <script>alert(1)</script> `x`"
	r.Realms[0].Findings[0].Evidence = r.Findings[0].Evidence
	md := ToMarkdown(r)
	if !strings.Contains(md, "## Haven Guard: score") || !strings.Contains(md, "| HAVEN006 | high |") {
		t.Fatalf("unexpected markdown:\n%s", md)
	}
	if strings.Contains(md, "<script>") || strings.Contains(md, "`x`") {
		t.Errorf("evidence not neutralised:\n%s", md)
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "| HAVEN") && strings.Count(strings.ReplaceAll(line, `\|`, ""), "|") != 6 {
			t.Errorf("row broken by evidence: %q", line)
		}
	}
	clean := ToMarkdown(Report{Grade: "A", Score: 100})
	if !strings.Contains(clean, "No findings.") {
		t.Errorf("clean report: %s", clean)
	}
}

func TestMarkdownReportsKnownWaiversAndDrift(t *testing.T) {
	r := sampleReport(t)
	r.Baseline, r.Drifted = "sha256:x", true
	ws, err := ParseWaivers([]byte(strings.ReplaceAll(`{"version":1,"waivers":[{"ruleId":"HAVEN006","realm":"prod","clientId":"a|b <img>","reason":"legacy","approver":"sec","expires":"SOON"},{"ruleId":"HAVEN001","realm":"prod","reason":"r","approver":"a","expires":"SOON"}]}`, "SOON", soon())), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.ApplyWaivers(ws, time.Now())
	r.MarkNew(map[string]bool{})
	md := ToMarkdown(r)
	for _, want := range []string{"drift", "covered by active waivers", "matches no finding", "new finding(s)"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestJUnitFailuresAndWaivedSkips(t *testing.T) {
	r := sampleReport(t)
	ws, err := ParseWaivers([]byte(strings.ReplaceAll(`{"version":1,"waivers":[{"ruleId":"HAVEN006","realm":"prod","clientId":"a|b <img>","reason":"legacy & accepted","approver":"sec","expires":"SOON"}]}`, "SOON", soon())), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	failing := len(r.Findings) - 1
	r.ApplyWaivers(ws, time.Now())
	b, err := ToJUnit(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc junitSuites
	if err := xml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("not well-formed XML: %v\n%s", err, b)
	}
	if len(doc.Suites) != 1 || doc.Suites[0].Name != "prod" {
		t.Fatalf("suites: %+v", doc.Suites)
	}
	s := doc.Suites[0]
	if s.Failures != failing || s.Skipped != 1 || s.Tests != failing+1 {
		t.Errorf("counts failures=%d skipped=%d tests=%d want failing=%d", s.Failures, s.Skipped, s.Tests, failing)
	}
	skipped := 0
	for _, c := range s.Cases {
		if c.Skipped != nil {
			skipped++
			if c.Skipped.Message != "legacy & accepted" || !strings.Contains(c.Name, "[high][HAVEN006]") {
				t.Errorf("skipped case: %+v", c)
			}
		}
	}
	if skipped != 1 {
		t.Errorf("skipped cases = %d", skipped)
	}
	empty, err := ToJUnit(Report{})
	if err != nil || !strings.Contains(string(empty), "<testsuites>") && !strings.Contains(string(empty), "<testsuites") {
		t.Errorf("empty report: %s %v", empty, err)
	}
}

// soon is a waiver expiry inside the one-year limit ParseWaivers enforces.
func soon() string { return time.Now().AddDate(0, 6, 0).Format("2006-01-02") }
