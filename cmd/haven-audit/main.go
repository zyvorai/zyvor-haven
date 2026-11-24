// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/keycloak"
	"github.com/zyvorai/haven/internal/policy"
	"github.com/zyvorai/haven/internal/posture"
)

// maxInputBytes bounds every file or stdin read.
const maxInputBytes = 64 << 20

type realmExport struct {
	keycloak.Realm
	Clients []keycloak.Client `json:"clients"`
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "diff":
			runDiff(os.Args[2:])
			return
		case "access-review":
			runAccessReview(os.Args[2:])
			return
		}
	}
	var input, format, baseline, failOn, policyPath, waiversPath, knownPath, writeKnownPath string
	flag.StringVar(&input, "input", "-", "Keycloak realm export JSON file, or - for stdin")
	flag.StringVar(&format, "format", "text", "text, json, or sarif")
	flag.StringVar(&baseline, "baseline", "", "expected Haven Guard sha256 fingerprint")
	flag.StringVar(&policyPath, "policy", "", "policy-as-code JSON file evaluated in addition to the built-in rules")
	flag.StringVar(&waiversPath, "waivers", "", "accepted-risk waivers JSON (reason, approver, expiry per waiver); expired waivers reopen their findings")
	flag.StringVar(&knownPath, "known", "", "known-findings baseline JSON; --fail-on then gates on findings not in it")
	flag.StringVar(&writeKnownPath, "write-known", "", "write the current findings to this file as a known-findings baseline")
	flag.StringVar(&failOn, "fail-on", "high", "critical, high, medium, low, or none")
	flag.Parse()

	data, err := readInput(input)
	if err != nil {
		fatal(err)
	}
	exports, err := decodeExports(data)
	if err != nil {
		fatal(err)
	}
	realms := make([]keycloak.Realm, 0, len(exports))
	clients := make(map[string][]keycloak.Client, len(exports))
	for _, item := range exports {
		realms = append(realms, item.Realm)
		clients[item.Realm.Realm] = item.Clients
	}
	report := posture.Evaluate(realms, clients, posture.Options{Baseline: baseline})
	if policyPath != "" {
		extra, err := evaluatePolicy(policyPath, data)
		if err != nil {
			fatal(err)
		}
		report.AddFindings(extra)
	}

	if waiversPath != "" {
		raw, err := readCapped(waiversPath)
		if err != nil {
			fatal(err)
		}
		ws, err := posture.ParseWaivers(raw, time.Now())
		if err != nil {
			fatal(err)
		}
		report.ApplyWaivers(ws, time.Now())
	}
	gate := report.Counts
	if knownPath != "" {
		raw, err := readCapped(knownPath)
		if err != nil {
			fatal(err)
		}
		known, err := posture.ParseKnownFindings(raw)
		if err != nil {
			fatal(err)
		}
		gate = report.MarkNew(known)
	}
	if writeKnownPath != "" {
		out, err := posture.KnownFindings(report)
		if err != nil {
			fatal(err)
		}
		// #nosec G306 -- baseline holds rule ids and realm/client names, no secrets
		if err := os.WriteFile(writeKnownPath, append(out, 10), 0o644); err != nil {
			fatal(err)
		}
	}

	switch strings.ToLower(format) {
	case "text":
		printText(report)
	case "json":
		writeJSON(report)
	case "sarif":
		writeJSON(posture.ToSARIF(report, input))
	default:
		fatal(fmt.Errorf("unsupported --format %q", format))
	}

	if shouldFail(gate, failOn) {
		os.Exit(2)
	}
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return limited(os.Stdin)
	}
	return readCapped(path)
}

// readCapped reads a file the operator names on the command line, refusing
// anything larger than maxInputBytes.
func readCapped(path string) ([]byte, error) {
	// #nosec G304 -- CLI reads the file the operator names on the command line
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return limited(f)
}

func limited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}
	return data, nil
}

func evaluatePolicy(path string, export []byte) ([]posture.Finding, error) {
	raw, err := readCapped(path)
	if err != nil {
		return nil, err
	}
	pol, err := policy.Parse(raw)
	if err != nil {
		return nil, err
	}
	var docs []map[string]any
	if err := json.Unmarshal(export, &docs); err != nil {
		var one map[string]any
		if err := json.Unmarshal(export, &one); err != nil {
			return nil, fmt.Errorf("decode realm export for policy: %w", err)
		}
		docs = []map[string]any{one}
	}
	var out []posture.Finding
	for _, d := range docs {
		name, _ := d["realm"].(string)
		out = append(out, pol.Evaluate(name, d)...)
	}
	return out, nil
}

func decodeExports(data []byte) ([]realmExport, error) {
	var many []realmExport
	if err := json.Unmarshal(data, &many); err == nil && len(many) > 0 {
		return many, nil
	}
	var one realmExport
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, fmt.Errorf("decode Keycloak realm export: %w", err)
	}
	if one.Realm.Realm == "" {
		return nil, fmt.Errorf("realm export does not contain a realm name")
	}
	return []realmExport{one}, nil
}

func printText(r posture.Report) {
	fmt.Printf("Haven Guard  score=%d grade=%s realms=%d clients=%d\n", r.Score, r.Grade, r.RealmCount, r.ClientCount)
	fmt.Printf("fingerprint %s\n", r.Fingerprint)
	if r.Baseline != "" {
		fmt.Printf("drift       %t\n", r.Drifted)
	}
	fmt.Printf("findings    critical=%d high=%d medium=%d low=%d\n", r.Counts.Critical, r.Counts.High, r.Counts.Medium, r.Counts.Low)
	if r.KnownApplied {
		fmt.Printf("new         %d finding(s) not in the known-findings baseline\n", len(r.NewFindings))
	}
	if n := len(r.Waived); n > 0 {
		fmt.Printf("waived      %d finding(s) under active waivers\n", n)
	}
	for _, w := range r.ExpiredWaivers {
		fmt.Printf("expired     waiver %s %s %s (expired %s, approver %s): finding reopened\n", w.RuleID, w.Realm, w.ClientID, w.Expires, w.Approver)
	}
	for _, w := range r.UnusedWaivers {
		fmt.Printf("unused      waiver %s %s %s matches no finding: remove it\n", w.RuleID, w.Realm, w.ClientID)
	}
	fmt.Println()
	for _, f := range r.Findings {
		scope := f.Realm
		if f.ClientID != "" {
			scope += "/" + f.ClientID
		}
		fmt.Printf("%-8s %-8s %-24s %s\n", f.RuleID, strings.ToUpper(string(f.Severity)), scope, f.Title)
		if f.Evidence != "" {
			fmt.Printf("  evidence: %s\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Printf("  fix:      %s\n", f.Remediation)
		}
	}
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err)
	}
}

func shouldFail(r posture.Counts, threshold string) bool {
	switch strings.ToLower(threshold) {
	case "none", "off":
		return false
	case "critical":
		return r.Critical > 0
	case "high":
		return r.Critical+r.High > 0
	case "medium":
		return r.Critical+r.High+r.Medium > 0
	case "low":
		return r.Critical+r.High+r.Medium+r.Low > 0
	default:
		fatal(fmt.Errorf("unsupported --fail-on %q", threshold))
		return true
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "haven-audit:", err)
	os.Exit(1)
}
