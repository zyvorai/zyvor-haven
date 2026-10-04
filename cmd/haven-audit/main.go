// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zyvorai/haven/internal/keycloak"
	"github.com/zyvorai/haven/internal/posture"
)

type realmExport struct {
	keycloak.Realm
	Clients []keycloak.Client `json:"clients"`
}

func main() {
	var input, format, baseline, failOn string
	flag.StringVar(&input, "input", "-", "Keycloak realm export JSON file, or - for stdin")
	flag.StringVar(&format, "format", "text", "text, json, or sarif")
	flag.StringVar(&baseline, "baseline", "", "expected Haven Guard sha256 fingerprint")
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

	if shouldFail(report, failOn) {
		os.Exit(2)
	}
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	// #nosec G304 -- CLI reads the export file the operator names on the command line
	return os.ReadFile(path)
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
	fmt.Printf("findings    critical=%d high=%d medium=%d low=%d\n\n", r.Counts.Critical, r.Counts.High, r.Counts.Medium, r.Counts.Low)
	for _, f := range r.Findings {
		scope := f.Realm
		if f.ClientID != "" {
			scope += "/" + f.ClientID
		}
		fmt.Printf("%-8s %-8s %-24s %s\n", f.RuleID, strings.ToUpper(string(f.Severity)), scope, f.Title)
		if f.Evidence != "" {
			fmt.Printf("  evidence: %s\n", f.Evidence)
		}
		fmt.Printf("  fix:      %s\n", f.Remediation)
	}
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err)
	}
}

func shouldFail(r posture.Report, threshold string) bool {
	switch strings.ToLower(threshold) {
	case "none", "off":
		return false
	case "critical":
		return r.Counts.Critical > 0
	case "high":
		return r.Counts.Critical+r.Counts.High > 0
	case "medium":
		return r.Counts.Critical+r.Counts.High+r.Counts.Medium > 0
	case "low":
		return r.Counts.Critical+r.Counts.High+r.Counts.Medium+r.Counts.Low > 0
	default:
		fatal(fmt.Errorf("unsupported --fail-on %q", threshold))
		return true
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "haven-audit:", err)
	os.Exit(1)
}
