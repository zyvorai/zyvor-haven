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

	"github.com/zyvorai/haven/internal/idmodel"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/policy"
	"github.com/zyvorai/haven/internal/posture"
)

// maxInputBytes bounds every file or stdin read.
const maxInputBytes = 64 << 20

// realmExport is one realm in the standard realm-export JSON format (the
// shape Haven Guard reads offline; the JSON field names mirror that format).
type realmExport struct {
	idp.Realm
	Clients []idp.Client `json:"clients"`
}

func main() {
	code, err := run(os.Args[1:], os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "haven-audit:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// run executes one haven-audit invocation. It returns the process exit code
// (0 clean, 2 gate tripped) and an error for usage or input problems (exit 1).
func run(args []string, stdin io.Reader, stdout io.Writer) (int, error) {
	if len(args) > 0 {
		switch args[0] {
		case "diff":
			return runDiff(args[1:], stdout)
		case "access-review":
			return runAccessReview(args[1:], stdin, stdout)
		case "rules":
			return runRules(args[1:], stdout)
		case "explain":
			return runExplain(args[1:], stdout)
		}
	}
	var input, format, baseline, failOn, policyPath, waiversPath, knownPath, writeKnownPath string
	fs := flag.NewFlagSet("haven-audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&input, "input", "-", "realm export JSON file (standard realm-export format), or - for stdin")
	fs.StringVar(&format, "format", "text", "text, json, sarif, markdown, or junit")
	fs.StringVar(&baseline, "baseline", "", "expected Haven Guard sha256 fingerprint")
	fs.StringVar(&policyPath, "policy", "", "policy-as-code JSON file evaluated in addition to the built-in rules")
	fs.StringVar(&waiversPath, "waivers", "", "accepted-risk waivers JSON (reason, approver, expiry per waiver); expired waivers reopen their findings")
	fs.StringVar(&knownPath, "known", "", "known-findings baseline JSON; --fail-on then gates on findings not in it")
	fs.StringVar(&writeKnownPath, "write-known", "", "write the current findings to this file as a known-findings baseline")
	fs.StringVar(&failOn, "fail-on", "high", "critical, high, medium, low, or none")
	if err := fs.Parse(args); err != nil {
		return 1, err
	}
	if !validFailOn(failOn) {
		return 1, fmt.Errorf("unsupported --fail-on %q", failOn)
	}
	if !validFormat(format) {
		return 1, fmt.Errorf("unsupported --format %q", format)
	}

	var data []byte
	var err error
	if input == "-" {
		data, err = limited(stdin)
	} else {
		data, err = readCapped(input)
	}
	if err != nil {
		return 1, err
	}
	exports, err := decodeExports(data)
	if err != nil {
		return 1, err
	}
	realms := make([]idp.Realm, 0, len(exports))
	clients := make(map[string][]idmodel.Client, len(exports))
	for _, item := range exports {
		realms = append(realms, item.Realm)
		clients[item.Realm.Realm] = idmodel.FromClients(item.Clients)
	}
	report := posture.Evaluate(idmodel.FromRealms(realms), clients, posture.Options{Baseline: baseline})
	if policyPath != "" {
		extra, err := evaluatePolicy(policyPath, data)
		if err != nil {
			return 1, err
		}
		report.AddFindings(extra)
	}

	if waiversPath != "" {
		raw, err := readCapped(waiversPath)
		if err != nil {
			return 1, err
		}
		ws, err := posture.ParseWaivers(raw, time.Now())
		if err != nil {
			return 1, err
		}
		report.ApplyWaivers(ws, time.Now())
	}
	gate := report.Counts
	if knownPath != "" {
		raw, err := readCapped(knownPath)
		if err != nil {
			return 1, err
		}
		known, err := posture.ParseKnownFindings(raw)
		if err != nil {
			return 1, err
		}
		gate = report.MarkNew(known)
	}
	if writeKnownPath != "" {
		out, err := posture.KnownFindings(report)
		if err != nil {
			return 1, err
		}
		// #nosec G306 -- baseline holds rule ids and realm/client names, no secrets
		if err := os.WriteFile(writeKnownPath, append(out, 10), 0o644); err != nil {
			return 1, err
		}
	}

	if err := renderReport(stdout, format, report, input); err != nil {
		return 1, err
	}
	if shouldFail(gate, failOn) {
		return 2, nil
	}
	return 0, nil
}

func validFormat(f string) bool {
	switch strings.ToLower(f) {
	case "text", "json", "sarif", "markdown", "md", "junit":
		return true
	}
	return false
}

func validFailOn(t string) bool {
	switch strings.ToLower(t) {
	case "none", "off", "critical", "high", "medium", "low":
		return true
	}
	return false
}

func renderReport(w io.Writer, format string, report posture.Report, input string) error {
	switch strings.ToLower(format) {
	case "text":
		printText(w, report)
	case "json":
		return writeJSON(w, report)
	case "sarif":
		return writeJSON(w, posture.ToSARIF(report, input))
	case "markdown", "md":
		_, err := io.WriteString(w, posture.ToMarkdown(report))
		return err
	case "junit":
		b, err := posture.ToJUnit(report)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	default:
		return fmt.Errorf("unsupported --format %q", format)
	}
	return nil
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
		return nil, fmt.Errorf("decode realm export (standard realm-export JSON format): %w", err)
	}
	if one.Realm.Realm == "" {
		return nil, fmt.Errorf("realm export does not contain a realm name")
	}
	return []realmExport{one}, nil
}

func printText(out io.Writer, r posture.Report) {
	_, _ = fmt.Fprintf(out, "Haven Guard  score=%d grade=%s realms=%d clients=%d\n", r.Score, r.Grade, r.RealmCount, r.ClientCount)
	_, _ = fmt.Fprintf(out, "fingerprint %s\n", r.Fingerprint)
	if r.Baseline != "" {
		_, _ = fmt.Fprintf(out, "drift       %t\n", r.Drifted)
	}
	_, _ = fmt.Fprintf(out, "findings    critical=%d high=%d medium=%d low=%d\n", r.Counts.Critical, r.Counts.High, r.Counts.Medium, r.Counts.Low)
	if r.KnownApplied {
		_, _ = fmt.Fprintf(out, "new         %d finding(s) not in the known-findings baseline\n", len(r.NewFindings))
	}
	if n := len(r.Waived); n > 0 {
		_, _ = fmt.Fprintf(out, "waived      %d finding(s) under active waivers\n", n)
	}
	for _, w := range r.ExpiredWaivers {
		_, _ = fmt.Fprintf(out, "expired     waiver %s %s %s (expired %s, approver %s): finding reopened\n", w.RuleID, w.Realm, w.ClientID, w.Expires, w.Approver)
	}
	for _, w := range r.UnusedWaivers {
		_, _ = fmt.Fprintf(out, "unused      waiver %s %s %s matches no finding: remove it\n", w.RuleID, w.Realm, w.ClientID)
	}
	_, _ = fmt.Fprintln(out)
	for _, f := range r.Findings {
		scope := f.Realm
		if f.ClientID != "" {
			scope += "/" + f.ClientID
		}
		_, _ = fmt.Fprintf(out, "%-8s %-8s %-24s %s\n", f.RuleID, strings.ToUpper(string(f.Severity)), scope, f.Title)
		if f.Evidence != "" {
			_, _ = fmt.Fprintf(out, "  evidence: %s\n", f.Evidence)
		}
		if f.Remediation != "" {
			_, _ = fmt.Fprintf(out, "  fix:      %s\n", f.Remediation)
		}
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
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
