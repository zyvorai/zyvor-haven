// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/zyvorai/haven/internal/accessreview"
	"github.com/zyvorai/haven/internal/identityops"
	"github.com/zyvorai/haven/internal/realmdiff"
)

// runDiff implements `haven-audit diff BEFORE.json AFTER.json`.
// Exit codes: 0 identical, 1 error, 2 differences found.
func runDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	format := fs.String("format", "text", "text or json")
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		fatal(fmt.Errorf("usage: haven-audit diff [--format text|json] BEFORE.json AFTER.json"))
	}
	before, err := readCapped(fs.Arg(0))
	if err != nil {
		fatal(err)
	}
	after, err := readCapped(fs.Arg(1))
	if err != nil {
		fatal(err)
	}
	res, err := realmdiff.CompareJSON(before, after)
	if err != nil {
		fatal(err)
	}
	switch strings.ToLower(*format) {
	case "json":
		writeJSON(res)
	case "text":
		printDiff(res)
	default:
		fatal(fmt.Errorf("unsupported --format %q", *format))
	}
	if !res.Empty() {
		os.Exit(2)
	}
}

func printDiff(r realmdiff.Result) {
	fmt.Printf("Haven realm diff  added=%d removed=%d changed=%d\n", len(r.Added), len(r.Removed), len(r.Changed))
	for _, c := range r.Added {
		fmt.Printf("+ %s = %s\n", c.Path, c.After)
	}
	for _, c := range r.Removed {
		fmt.Printf("- %s = %s\n", c.Path, c.Before)
	}
	for _, c := range r.Changed {
		fmt.Printf("~ %s: %s -> %s\n", c.Path, c.Before, c.After)
	}
}

// runAccessReview implements `haven-audit access-review --input SNAPSHOT.json`.
// The input is a Time Machine snapshot. Exit codes: 0 no high-risk account
// and break-glass coverage ok, 1 error, 2 high-risk accounts found.
func runAccessReview(args []string) {
	fs := flag.NewFlagSet("access-review", flag.ExitOnError)
	input := fs.String("input", "-", "Time Machine snapshot JSON file, or - for stdin")
	format := fs.String("format", "text", "text or json")
	bg := fs.String("break-glass", "", "RE2 pattern for break-glass usernames (default matches break-glass*, emergency*, bg*)")
	failOn := fs.String("fail-on", "high", "high or none")
	_ = fs.Parse(args)

	data, err := readInput(*input)
	if err != nil {
		fatal(err)
	}
	var snap identityops.RealmSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		fatal(fmt.Errorf("decode snapshot: %w", err))
	}
	if snap.Realm == "" {
		fatal(fmt.Errorf("snapshot does not contain a realm name"))
	}
	rep, err := accessreview.Analyze(snap, accessreview.Options{BreakGlassPattern: *bg})
	if err != nil {
		fatal(err)
	}
	switch strings.ToLower(*format) {
	case "json":
		writeJSON(rep)
	case "text":
		fmt.Printf("Haven Access Review  realm=%s users=%d withAccess=%d privileged=%d stale=%d high=%d\n",
			rep.Realm, rep.Summary.Users, rep.Summary.WithAccess, rep.Summary.Privileged, rep.Summary.StaleAccess, rep.Summary.HighRisk)
		for _, w := range rep.BreakGlass.Warnings {
			fmt.Printf("break-glass: %s\n", w)
		}
		for _, it := range rep.Items {
			fmt.Printf("%-7s %-24s %s\n", strings.ToUpper(it.Risk), it.Username, strings.Join(it.Flags, ","))
		}
	default:
		fatal(fmt.Errorf("unsupported --format %q", *format))
	}
	switch strings.ToLower(*failOn) {
	case "none":
	case "high":
		if rep.Summary.HighRisk > 0 {
			os.Exit(2)
		}
	default:
		fatal(fmt.Errorf("unsupported --fail-on %q", *failOn))
	}
}
