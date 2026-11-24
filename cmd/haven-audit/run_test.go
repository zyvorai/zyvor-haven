// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
)

const insecureExport = `{"realm":"prod","enabled":true,"verifyEmail":true,"bruteForceProtected":true,
 "sslRequired":"none","eventsExpiration":0,"failureFactor":30,
 "clients":[{"clientId":"web","enabled":true,"publicClient":true,"implicitFlowEnabled":true,"fullScopeAllowed":true,
   "defaultClientScopes":["offline_access"],"attributes":{"access.token.lifespan":"7200"}}]}`

const cleanExport = `{"realm":"ok","enabled":true,"verifyEmail":true,"bruteForceProtected":true,"clients":[]}`

func runCLI(t *testing.T, stdin string, args ...string) (int, string, error) {
	t.Helper()
	var out bytes.Buffer
	code, err := run(args, strings.NewReader(stdin), &out)
	return code, out.String(), err
}

func TestAuditRunFormatsAndExitCodes(t *testing.T) {
	exp := write(t, "realm.json", insecureExport)
	code, out, err := runCLI(t, "", "--input", exp)
	if err != nil || code != 2 {
		t.Fatalf("text: code=%d err=%v", code, err)
	}
	for _, id := range []string{"HAVEN006", "HAVEN014", "HAVEN024", "HAVEN026", "HAVEN028", "HAVEN029", "HAVEN030"} {
		if !strings.Contains(out, id) {
			t.Errorf("text output missing %s", id)
		}
	}

	code, out, err = runCLI(t, insecureExport, "--format", "markdown", "--fail-on", "none")
	if err != nil || code != 0 || !strings.Contains(out, "| HAVEN006 | high |") {
		t.Fatalf("markdown via stdin: code=%d err=%v\n%s", code, err, out)
	}

	code, out, err = runCLI(t, insecureExport, "--format", "junit", "--fail-on", "none")
	if err != nil || code != 0 {
		t.Fatalf("junit: %d %v", code, err)
	}
	var doc struct {
		Suites []struct {
			Failures int `xml:"failures,attr"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal([]byte(out), &doc); err != nil || len(doc.Suites) != 1 || doc.Suites[0].Failures < 7 {
		t.Fatalf("junit content: %v %+v\n%s", err, doc, out)
	}

	code, out, err = runCLI(t, cleanExport, "--format", "json")
	if err != nil || code != 0 {
		t.Fatalf("clean json: %d %v", code, err)
	}
	var rep map[string]any
	if json.Unmarshal([]byte(out), &rep) != nil {
		t.Fatalf("json output invalid: %s", out)
	}
}

func TestAuditRunRejectsBadFlagsBeforeReading(t *testing.T) {
	for _, args := range [][]string{
		{"--format", "yaml"}, {"--fail-on", "sometimes"}, {"--bogus"}, {"--input", "/nonexistent/realm.json"},
	} {
		code, _, err := runCLI(t, cleanExport, args...)
		if err == nil || code != 1 {
			t.Errorf("%v: code=%d err=%v", args, code, err)
		}
	}
	if code, _, err := runCLI(t, "not json"); err == nil || code != 1 {
		t.Errorf("garbage input: code=%d err=%v", code, err)
	}
}

func TestAuditRunWritesKnownBaselineAndGatesOnNew(t *testing.T) {
	exp := write(t, "realm.json", insecureExport)
	known := t.TempDir() + "/known.json"
	if code, _, err := runCLI(t, "", "--input", exp, "--write-known", known, "--fail-on", "none"); err != nil || code != 0 {
		t.Fatalf("write-known: %d %v", code, err)
	}
	if code, _, err := runCLI(t, "", "--input", exp, "--known", known); err != nil || code != 0 {
		t.Fatalf("known findings must not trip the gate: %d %v", code, err)
	}
}

func TestRulesAndExplainSubcommands(t *testing.T) {
	code, out, err := runCLI(t, "", "rules")
	if err != nil || code != 0 || !strings.Contains(out, "HAVEN001") || !strings.Contains(out, "HAVEN030") {
		t.Fatalf("rules text: %d %v\n%s", code, err, out)
	}
	_, out, err = runCLI(t, "", "rules", "--format", "json")
	var list []map[string]any
	if err != nil || json.Unmarshal([]byte(out), &list) != nil || len(list) < 30 {
		t.Fatalf("rules json: %v %d", err, len(list))
	}
	_, out, err = runCLI(t, "", "rules", "--format", "markdown")
	if err != nil || !strings.HasPrefix(out, "| ID | Severity |") {
		t.Fatalf("rules md: %v\n%s", err, out)
	}
	code, out, err = runCLI(t, "", "explain", "haven029")
	if err != nil || code != 0 || !strings.Contains(out, "offline_access") || !strings.Contains(out, "Fix:") {
		t.Fatalf("explain: %d %v\n%s", code, err, out)
	}
	if _, out, err = runCLI(t, "", "explain", "--format", "json", "HAVEN001"); err != nil || !strings.Contains(out, `"severity": "critical"`) {
		t.Fatalf("explain json: %v\n%s", err, out)
	}
	for _, args := range [][]string{{"explain"}, {"explain", "HAVEN999"}, {"explain", "A", "B"}, {"rules", "--format", "xml"}} {
		if code, _, err := runCLI(t, "", args...); err == nil || code != 1 {
			t.Errorf("%v: code=%d err=%v", args, code, err)
		}
	}
}

func TestDiffSubcommandIgnoreAndMarkdown(t *testing.T) {
	a := write(t, "a.json", `{"realm":"r","displayName":"A","attributes":{"k":"1"},"clientSecret":"s1"}`)
	b := write(t, "b.json", `{"realm":"r","displayName":"B","attributes":{"k":"2"},"clientSecret":"s2"}`)
	code, out, err := runCLI(t, "", "diff", a, b)
	if err != nil || code != 2 || !strings.Contains(out, "displayName") {
		t.Fatalf("diff: %d %v\n%s", code, err, out)
	}
	if strings.Contains(out, "s1") || strings.Contains(out, "s2") {
		t.Errorf("secret leaked:\n%s", out)
	}
	code, out, err = runCLI(t, "", "diff", "--ignore", "displayName", "--ignore", "attributes", "--ignore", "clientSecret", a, b)
	if err != nil || code != 0 || !strings.Contains(out, "added=0 removed=0 changed=0") {
		t.Fatalf("ignored diff: %d %v\n%s", code, err, out)
	}
	code, out, err = runCLI(t, "", "diff", "--format", "markdown", "--ignore", "attributes", a, b)
	if err != nil || code != 2 || !strings.Contains(out, "~~~diff") || strings.Contains(out, "attributes") {
		t.Fatalf("markdown diff: %d %v\n%s", code, err, out)
	}
	for _, args := range [][]string{{"diff", a}, {"diff", "--format", "xml", a, b}, {"diff", a, "/nonexistent"}} {
		if code, _, err := runCLI(t, "", args...); err == nil || code != 1 {
			t.Errorf("%v: code=%d err=%v", args, code, err)
		}
	}
}

func TestAccessReviewSubcommandUsage(t *testing.T) {
	for _, args := range [][]string{{"access-review", "--fail-on", "x"}, {"access-review", "--format", "xml"}} {
		if code, _, err := runCLI(t, "{}", args...); err == nil || code != 1 {
			t.Errorf("%v: code=%d err=%v", args, code, err)
		}
	}
	if code, _, err := runCLI(t, `{"realm":""}`, "access-review"); err == nil || code != 1 {
		t.Errorf("nameless snapshot accepted: %d %v", code, err)
	}
	code, out, err := runCLI(t, `{"realm":"r"}`, "access-review", "--format", "json")
	if err != nil || code != 0 || !strings.Contains(out, `"realm": "r"`) {
		t.Errorf("empty snapshot: %d %v\n%s", code, err, out)
	}
}
