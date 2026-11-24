// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package posture

import (
	"github.com/zyvorai/haven/internal/idp"
	"strings"
	"testing"
	"time"
)

var waiverNow = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func waiverReport() Report {
	realm := idp.Realm{Realm: "r", Enabled: true, VerifyEmail: true, BruteForceProtected: true,
		RealmHardening: &idp.RealmHardening{SSLRequired: sp("none"), EventsEnabled: bp(false)}}
	clients := []idp.Client{{ClientID: "app", Enabled: true, StandardFlowEnabled: true, RedirectURIs: []string{"*"}}}
	return evalWire([]idp.Realm{realm}, map[string][]idp.Client{"r": clients}, Options{})
}

func TestNewHardeningRules022And023(t *testing.T) {
	h := &idp.RealmHardening{SSOSessionMaxLifespan: ip(31 * 86400), OfflineSessionIdleTimeout: ip(91 * 86400)}
	realm := idp.Realm{Realm: "r", Enabled: true, VerifyEmail: true, BruteForceProtected: true, RealmHardening: h}
	ids := ruleIDs(evalWire([]idp.Realm{realm}, nil, Options{}))
	if !ids["HAVEN022"] || !ids["HAVEN023"] {
		t.Fatalf("want 022 and 023, got %v", ids)
	}
	h.SSOSessionMaxLifespan, h.OfflineSessionIdleTimeout = ip(30*86400), ip(90*86400)
	ids = ruleIDs(evalWire([]idp.Realm{realm}, nil, Options{}))
	if ids["HAVEN022"] || ids["HAVEN023"] {
		t.Fatalf("boundary values must pass, got %v", ids)
	}
}

func TestParseWaiversValidation(t *testing.T) {
	ok := `{"version":1,"waivers":[{"ruleId":"HAVEN014","realm":"r","reason":"lab","approver":"a@x","expires":"2027-01-01"}]}`
	if ws, err := ParseWaivers([]byte(ok), waiverNow); err != nil || len(ws) != 1 {
		t.Fatalf("valid file rejected: %v", err)
	}
	cases := map[string]string{
		"version":     `{"version":2,"waivers":[]}`,
		"unknown":     `{"version":1,"waivers":[],"x":1}`,
		"bad rule":    `{"version":1,"waivers":[{"ruleId":"a b","realm":"r","reason":"x","approver":"y","expires":"2027-01-01"}]}`,
		"wild realm":  `{"version":1,"waivers":[{"ruleId":"HAVEN014","realm":"*","reason":"x","approver":"y","expires":"2027-01-01"}]}`,
		"no reason":   `{"version":1,"waivers":[{"ruleId":"HAVEN014","realm":"r","reason":" ","approver":"y","expires":"2027-01-01"}]}`,
		"no approver": `{"version":1,"waivers":[{"ruleId":"HAVEN014","realm":"r","reason":"x","approver":"","expires":"2027-01-01"}]}`,
		"bad date":    `{"version":1,"waivers":[{"ruleId":"HAVEN014","realm":"r","reason":"x","approver":"y","expires":"soon"}]}`,
		"too far":     `{"version":1,"waivers":[{"ruleId":"HAVEN014","realm":"r","reason":"x","approver":"y","expires":"2030-01-01"}]}`,
		"long":        `{"version":1,"waivers":[{"ruleId":"HAVEN014","realm":"r","reason":"` + strings.Repeat("x", 501) + `","approver":"y","expires":"2027-01-01"}]}`,
		"garbage":     `nope`,
	}
	for name, raw := range cases {
		if _, err := ParseWaivers([]byte(raw), waiverNow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Already expired is accepted so it can be reported as reopened.
	old := `{"version":1,"waivers":[{"ruleId":"HAVEN014","realm":"r","reason":"x","approver":"y","expires":"2020-01-01"}]}`
	if _, err := ParseWaivers([]byte(old), waiverNow); err != nil {
		t.Errorf("expired waiver rejected: %v", err)
	}
}

func TestApplyWaivers(t *testing.T) {
	base := waiverReport()
	fp := base.Fingerprint
	ws := []Waiver{
		{RuleID: "HAVEN014", Realm: "r", Reason: "lab", Approver: "a", Expires: "2026-11-24"}, // valid through today
		{RuleID: "HAVEN001", Realm: "r", ClientID: "app", Reason: "legacy", Approver: "a", Expires: "2020-01-01"},
		{RuleID: "HAVEN019", Realm: "other", Reason: "x", Approver: "a", Expires: "2027-01-01"},
		{RuleID: "HAVEN019", Realm: "r", ClientID: "app", Reason: "wrong scope", Approver: "a", Expires: "2027-01-01"},
	}
	r := base
	r.ApplyWaivers(ws, waiverNow)
	ids := ruleIDs(r)
	if ids["HAVEN014"] {
		t.Error("active waiver did not suppress HAVEN014")
	}
	if !ids["HAVEN001"] {
		t.Error("expired waiver must reopen HAVEN001")
	}
	if !ids["HAVEN019"] {
		t.Error("realm-level finding must not be waived by a client-scoped waiver")
	}
	if len(r.Waived) != 1 || r.Waived[0].RuleID != "HAVEN014" || r.Waived[0].Approver != "a" {
		t.Errorf("waived = %+v", r.Waived)
	}
	if len(r.ExpiredWaivers) != 1 || r.ExpiredWaivers[0].RuleID != "HAVEN001" {
		t.Errorf("expired = %+v", r.ExpiredWaivers)
	}
	if len(r.UnusedWaivers) != 2 {
		t.Errorf("unused = %+v", r.UnusedWaivers)
	}
	if r.Counts.High >= base.Counts.High || r.Score <= base.Score {
		t.Errorf("counts/score not recomputed: %+v score %d vs %d", r.Counts, r.Score, base.Score)
	}
	if r.Fingerprint != fp {
		t.Error("waivers must not change the fingerprint")
	}
	// The base report must be untouched (no aliasing of the findings slice).
	if !ruleIDs(base)["HAVEN014"] || len(base.Realms[0].Findings) != len(base.Findings) {
		t.Error("ApplyWaivers mutated the original report")
	}
	// Day after expiry the waiver lapses.
	r2 := base
	r2.ApplyWaivers(ws[:1], waiverNow.Add(24*time.Hour))
	if !ruleIDs(r2)["HAVEN014"] || len(r2.ExpiredWaivers) != 1 {
		t.Error("waiver still active after its expiry day")
	}
}

func TestApplyWaiversWildcardClient(t *testing.T) {
	r := waiverReport()
	r.ApplyWaivers([]Waiver{{RuleID: "HAVEN001", Realm: "r", ClientID: "*", Reason: "x", Approver: "a", Expires: "2027-01-01"}}, waiverNow)
	if ruleIDs(r)["HAVEN001"] {
		t.Error("wildcard client waiver did not match")
	}
}

func TestKnownFindingsRoundTripAndNew(t *testing.T) {
	r := waiverReport()
	raw, err := KnownFindings(r)
	if err != nil {
		t.Fatal(err)
	}
	known, err := ParseKnownFindings(raw)
	if err != nil {
		t.Fatal(err)
	}
	same := waiverReport()
	if c := same.MarkNew(known); c != (Counts{}) || len(same.NewFindings) != 0 || !same.KnownApplied {
		t.Errorf("identical report has new findings: %+v", same.NewFindings)
	}
	// A new offending value on an already-flagged client is new.
	worse := waiverReport()
	worse.Findings = append(worse.Findings, Finding{RuleID: "HAVEN001", Severity: SeverityCritical, Realm: "r", ClientID: "app", Evidence: "https://*.example/cb"})
	c := worse.MarkNew(known)
	if len(worse.NewFindings) != 1 || c.Critical != 1 {
		t.Errorf("new=%+v counts=%+v", worse.NewFindings, c)
	}
	if _, err := ParseKnownFindings([]byte(`{"version":9,"findings":[]}`)); err == nil {
		t.Error("bad version accepted")
	}
	if _, err := ParseKnownFindings([]byte(`{"version":1,"findings":[],"x":1}`)); err == nil {
		t.Error("unknown field accepted")
	}
}
