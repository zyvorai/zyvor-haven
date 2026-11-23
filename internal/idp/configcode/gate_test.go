// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/posture"
)

func rules(fs []posture.Finding) string {
	var ids []string
	for _, f := range fs {
		id := f.RuleID
		if f.ClientID != "" {
			id += ":" + f.ClientID
		}
		ids = append(ids, id)
	}
	return strings.Join(ids, ",")
}

func secureSpec() *Spec {
	return &Spec{Realm: "r", Clients: []Client{{
		ClientID: "web", Public: true, RedirectURIs: []string{"https://app.example.com/cb"},
	}}}
}

func TestGateSecureConfigIsClean(t *testing.T) {
	g := Gate(secureSpec(), nil, posture.SeverityHigh)
	if len(g.New) != 0 || len(g.Blocked) != 0 {
		t.Fatalf("secure config produced findings: %s", rules(g.New))
	}
}

func TestGateInsecureClientBlocked(t *testing.T) {
	d := secureSpec()
	d.Clients[0].RequirePKCE = ptr(false)
	g := Gate(d, nil, posture.SeverityHigh)
	if !strings.Contains(rules(g.Blocked), "HAVEN005:web") {
		t.Fatalf("blocked = %s", rules(g.Blocked))
	}
}

func TestGateThreshold(t *testing.T) {
	d := secureSpec()
	d.Clients[0].RequirePKCE = ptr(false)
	d.Settings.PasswordPolicy = ptr("")
	if g := Gate(d, nil, posture.SeverityCritical); len(g.Blocked) != 0 {
		t.Fatalf("critical threshold blocked %s", rules(g.Blocked))
	}
	if g := Gate(d, nil, ""); len(g.Blocked) != 0 || len(g.New) == 0 {
		t.Fatalf("empty threshold must disable blocking but keep New")
	}
	g := Gate(d, nil, posture.SeverityMedium)
	if !strings.Contains(rules(g.Blocked), "HAVEN015") || !strings.Contains(rules(g.Blocked), "HAVEN005") {
		t.Fatalf("medium blocked = %s", rules(g.Blocked))
	}
}

func TestGateHardeningRules(t *testing.T) {
	d := secureSpec()
	d.Settings = Settings{
		TransportSecurity:    ptr("none"),
		PasswordPolicy:       ptr("length(8)"),
		AccessTokenSeconds:   ptr(7200),
		SessionIdleSeconds:   ptr(200000),
		AuthEvents:           ptr(false),
		AdminEvents:          ptr(false),
		RefreshTokenRotation: ptr(false),
	}
	g := Gate(d, nil, posture.SeverityHigh)
	got := rules(g.New)
	for _, id := range []string{"HAVEN014", "HAVEN016", "HAVEN017", "HAVEN018", "HAVEN019", "HAVEN020", "HAVEN021"} {
		if !strings.Contains(got, id) {
			t.Errorf("missing %s in %s", id, got)
		}
	}
	if !strings.Contains(rules(g.Blocked), "HAVEN014") {
		t.Errorf("HAVEN014 (high) must block: %s", rules(g.Blocked))
	}
}

func TestGateFixedAndUnmanagedKeepsLive(t *testing.T) {
	live := &Spec{Realm: "r", Settings: Settings{TransportSecurity: ptr("none"), PasswordPolicy: ptr("length(12)")}}
	fix := &Spec{Realm: "r", Settings: Settings{TransportSecurity: ptr("external")}}
	g := Gate(fix, live, posture.SeverityHigh)
	if !strings.Contains(rules(g.Fixed), "HAVEN014") || len(g.New) != 0 {
		t.Fatalf("fixed=%s new=%s", rules(g.Fixed), rules(g.New))
	}
	// An unmanaged transportSecurity keeps the live insecure value: nothing fixed or new.
	g = Gate(&Spec{Realm: "r"}, live, posture.SeverityHigh)
	if len(g.Fixed) != 0 || len(g.New) != 0 {
		t.Fatalf("unmanaged must not change findings: %s / %s", rules(g.Fixed), rules(g.New))
	}
}

func TestGateClientReplaceAndAdd(t *testing.T) {
	live := &Spec{Realm: "r", Clients: []Client{{ClientID: "web", Public: true, RequirePKCE: ptr(false), RedirectURIs: []string{"https://a.example.com/cb"}}}}
	d := &Spec{Realm: "r", Clients: []Client{
		{ClientID: "web", Public: true, RedirectURIs: []string{"https://a.example.com/cb"}},
		{ClientID: "api", ServiceAccount: true},
	}}
	g := Gate(d, live, posture.SeverityHigh)
	if !strings.Contains(rules(g.Fixed), "HAVEN005:web") {
		t.Fatalf("fixed = %s", rules(g.Fixed))
	}
	if len(g.Blocked) != 0 {
		t.Fatalf("blocked = %s", rules(g.Blocked))
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityAtLeast(posture.SeverityCritical, posture.SeverityHigh) || SeverityAtLeast(posture.SeverityLow, posture.SeverityHigh) || SeverityAtLeast(posture.SeverityCritical, "") {
		t.Fatal("SeverityAtLeast wrong")
	}
}

func TestRenderPlanGolden(t *testing.T) {
	p := &Plan{Realm: "r", Changes: []Change{
		{Action: ActionCreate, Kind: KindOfClient, Name: "web", Fields: []FieldChange{{Field: "public", New: "true"}}},
		{Action: ActionUpdate, Kind: KindOfClient, Name: "app", Fields: []FieldChange{{Field: "redirectUris", Old: "[a]", New: "[b]"}}},
		{Action: ActionDelete, Kind: KindOfClient, Name: "old"},
	}}
	var b bytes.Buffer
	p.Render(&b, false)
	want := `Plan for realm "r":

  + client web
      public: true
  ~ client app
      redirectUris: [a] -> [b]
  - client old

Plan: 1 to create, 1 to update, 1 to delete
`
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
	b.Reset()
	(&Plan{Realm: "r"}).Render(&b, true)
	if b.String() != "No changes. Live state matches the file.\n" {
		t.Fatalf("empty: %q", b.String())
	}
	b.Reset()
	p.Render(&b, true)
	if !strings.Contains(b.String(), "\x1b[") {
		t.Fatal("color=true must emit ANSI")
	}
}

func TestRenderGateGolden(t *testing.T) {
	d := &Spec{Realm: "r", Settings: Settings{TransportSecurity: ptr("none")}}
	g := Gate(d, nil, posture.SeverityHigh)
	var b bytes.Buffer
	g.Render(&b, false)
	out := b.String()
	for _, want := range []string{"Haven Guard", "New findings (1):", "[HIGH] HAVEN014 Realm does not require TLS (r)", "evidence: sslRequired=none", "BLOCKED:"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("ANSI in color=false output")
	}
	b.Reset()
	Gate(secureSpec(), nil, posture.SeverityHigh).Render(&b, false)
	if strings.Contains(b.String(), "BLOCKED") || !strings.Contains(b.String(), "no change in findings") {
		t.Errorf("clean gate output wrong:\n%s", b.String())
	}
}
