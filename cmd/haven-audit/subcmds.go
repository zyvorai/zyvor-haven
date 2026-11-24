// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/zyvorai/haven/internal/accessreview"
	"github.com/zyvorai/haven/internal/identityops"
	"github.com/zyvorai/haven/internal/posture"
	"github.com/zyvorai/haven/internal/realmdiff"
)

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// listFlag collects a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// runDiff implements `haven-audit diff [--ignore GLOB]... BEFORE.json AFTER.json`.
// Exit codes: 0 identical, 1 error, 2 differences found.
func runDiff(args []string, stdout io.Writer) (int, error) {
	fs := newFlagSet("diff")
	format := fs.String("format", "text", "text, json or markdown")
	var ignore listFlag
	fs.Var(&ignore, "ignore", "glob of paths to leave out of the diff (repeatable); * matches any run of characters")
	if err := fs.Parse(args); err != nil {
		return 1, err
	}
	if fs.NArg() != 2 {
		return 1, fmt.Errorf("usage: haven-audit diff [--format text|json|markdown] [--ignore GLOB]... BEFORE.json AFTER.json")
	}
	switch strings.ToLower(*format) {
	case "text", "json", "markdown", "md":
	default:
		return 1, fmt.Errorf("unsupported --format %q", *format)
	}
	before, err := readCapped(fs.Arg(0))
	if err != nil {
		return 1, err
	}
	after, err := readCapped(fs.Arg(1))
	if err != nil {
		return 1, err
	}
	res, err := realmdiff.CompareJSON(before, after)
	if err != nil {
		return 1, err
	}
	res = res.Filter(ignore)
	switch strings.ToLower(*format) {
	case "json":
		if err := writeJSON(stdout, res); err != nil {
			return 1, err
		}
	case "text":
		printDiff(stdout, res)
	default:
		_, _ = io.WriteString(stdout, res.Markdown())
	}
	if !res.Empty() {
		return 2, nil
	}
	return 0, nil
}

func printDiff(w io.Writer, r realmdiff.Result) {
	_, _ = fmt.Fprintf(w, "Haven realm diff  added=%d removed=%d changed=%d\n", len(r.Added), len(r.Removed), len(r.Changed))
	for _, c := range r.Added {
		_, _ = fmt.Fprintf(w, "+ %s = %s\n", c.Path, c.After)
	}
	for _, c := range r.Removed {
		_, _ = fmt.Fprintf(w, "- %s = %s\n", c.Path, c.Before)
	}
	for _, c := range r.Changed {
		_, _ = fmt.Fprintf(w, "~ %s: %s -> %s\n", c.Path, c.Before, c.After)
	}
}

// runRules implements `haven-audit rules [--format text|json|markdown]`.
func runRules(args []string, stdout io.Writer) (int, error) {
	fs := newFlagSet("rules")
	format := fs.String("format", "text", "text, json or markdown")
	if err := fs.Parse(args); err != nil {
		return 1, err
	}
	rules := posture.Rules()
	switch strings.ToLower(*format) {
	case "json":
		return 0, writeJSON(stdout, rules)
	case "text":
		for _, r := range rules {
			_, _ = fmt.Fprintf(stdout, "%-8s %-8s %s\n", r.ID, strings.ToUpper(string(r.Severity)), r.Title)
		}
	case "markdown", "md":
		_, _ = fmt.Fprint(stdout, "| ID | Severity | Check | Fix |\n|---|---|---|---|\n")
		for _, r := range rules {
			_, _ = fmt.Fprintf(stdout, "| %s | %s | %s | %s |\n", r.ID, r.Severity, r.Title, r.Remediation)
		}
	default:
		return 1, fmt.Errorf("unsupported --format %q", *format)
	}
	return 0, nil
}

// runExplain implements `haven-audit explain RULE_ID`.
func runExplain(args []string, stdout io.Writer) (int, error) {
	fs := newFlagSet("explain")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return 1, err
	}
	if fs.NArg() != 1 {
		return 1, fmt.Errorf("usage: haven-audit explain [--format text|json] RULE_ID (see `haven-audit rules`)")
	}
	r, ok := posture.RuleByID(fs.Arg(0))
	if !ok {
		return 1, fmt.Errorf("unknown rule %q (see `haven-audit rules`)", fs.Arg(0))
	}
	switch strings.ToLower(*format) {
	case "json":
		return 0, writeJSON(stdout, r)
	case "text":
		_, _ = fmt.Fprintf(stdout, "%s  %s\n%s\nFix: %s\n", r.ID, strings.ToUpper(string(r.Severity)), r.Title, r.Remediation)
	default:
		return 1, fmt.Errorf("unsupported --format %q", *format)
	}
	return 0, nil
}

// runAccessReview implements `haven-audit access-review --input SNAPSHOT.json`.
// The input is a Time Machine snapshot. Exit codes: 0 no high-risk account
// and break-glass coverage ok, 1 error, 2 high-risk accounts found.
func runAccessReview(args []string, stdin io.Reader, stdout io.Writer) (int, error) {
	fs := newFlagSet("access-review")
	input := fs.String("input", "-", "Time Machine snapshot JSON file, or - for stdin")
	format := fs.String("format", "text", "text or json")
	bg := fs.String("break-glass", "", "RE2 pattern for break-glass usernames (default matches break-glass*, emergency*, bg*)")
	failOn := fs.String("fail-on", "high", "high or none")
	if err := fs.Parse(args); err != nil {
		return 1, err
	}
	switch strings.ToLower(*failOn) {
	case "none", "high":
	default:
		return 1, fmt.Errorf("unsupported --fail-on %q", *failOn)
	}
	switch strings.ToLower(*format) {
	case "json", "text":
	default:
		return 1, fmt.Errorf("unsupported --format %q", *format)
	}

	var data []byte
	var err error
	if *input == "-" {
		data, err = limited(stdin)
	} else {
		data, err = readCapped(*input)
	}
	if err != nil {
		return 1, err
	}
	var snap identityops.RealmSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return 1, fmt.Errorf("decode snapshot: %w", err)
	}
	if snap.Realm == "" {
		return 1, fmt.Errorf("snapshot does not contain a realm name")
	}
	rep, err := accessreview.Analyze(snap, accessreview.Options{BreakGlassPattern: *bg})
	if err != nil {
		return 1, err
	}
	if strings.ToLower(*format) == "json" {
		if err := writeJSON(stdout, rep); err != nil {
			return 1, err
		}
	} else {
		_, _ = fmt.Fprintf(stdout, "Haven Access Review  realm=%s users=%d withAccess=%d privileged=%d stale=%d high=%d\n",
			rep.Realm, rep.Summary.Users, rep.Summary.WithAccess, rep.Summary.Privileged, rep.Summary.StaleAccess, rep.Summary.HighRisk)
		for _, w := range rep.BreakGlass.Warnings {
			_, _ = fmt.Fprintf(stdout, "break-glass: %s\n", w)
		}
		for _, it := range rep.Items {
			_, _ = fmt.Fprintf(stdout, "%-7s %-24s %s\n", strings.ToUpper(it.Risk), it.Username, strings.Join(it.Flags, ","))
		}
	}
	if strings.ToLower(*failOn) == "high" && rep.Summary.HighRisk > 0 {
		return 2, nil
	}
	return 0, nil
}
