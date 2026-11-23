// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"fmt"
	"io"
	"strings"

	"github.com/zyvorai/haven/internal/posture"
)

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBold   = "\x1b[1m"
)

func paint(color bool, code, s string) string {
	if !color {
		return s
	}
	return code + s + ansiReset
}

// Summary returns the counts of creates, updates and deletes.
func (p *Plan) Summary() (create, update, del int) {
	for _, c := range p.Changes {
		switch c.Action {
		case ActionCreate:
			create++
		case ActionUpdate:
			update++
		case ActionDelete:
			del++
		}
	}
	return
}

// Empty reports whether the plan has no changes.
func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

// Render writes a terraform-style plan. Output is deterministic and contains
// ANSI escapes only when color is true.
func (p *Plan) Render(w io.Writer, color bool) {
	if p.Empty() && !p.RealmMissing {
		fmt.Fprintln(w, "No changes. Live state matches the file.")
		return
	}
	if p.RealmMissing {
		fmt.Fprintf(w, "Realm %q does not exist and will be created.\n\n", p.Realm)
	} else {
		fmt.Fprintf(w, "Plan for realm %q:\n\n", p.Realm)
	}
	for _, c := range p.Changes {
		var sym, code string
		switch c.Action {
		case ActionCreate:
			sym, code = "+", ansiGreen
		case ActionUpdate:
			sym, code = "~", ansiYellow
		default:
			sym, code = "-", ansiRed
		}
		fmt.Fprintf(w, "  %s\n", paint(color, code, fmt.Sprintf("%s %s %s", sym, c.Kind, c.Name)))
		for _, f := range c.Fields {
			switch c.Action {
			case ActionCreate:
				fmt.Fprintf(w, "      %s: %s\n", f.Field, show(f.New))
			case ActionDelete:
				fmt.Fprintf(w, "      %s: %s\n", f.Field, show(f.Old))
			default:
				fmt.Fprintf(w, "      %s: %s -> %s\n", f.Field, show(f.Old), show(f.New))
			}
		}
	}
	cr, up, de := p.Summary()
	fmt.Fprintf(w, "\nPlan: %d to create, %d to update, %d to delete\n", cr, up, de)
}

func show(s string) string {
	if s == "" {
		return `""`
	}
	return s
}

func sevLabel(s posture.Severity) string { return strings.ToUpper(string(s)) }

func sevColor(s posture.Severity) string {
	switch s {
	case posture.SeverityCritical, posture.SeverityHigh:
		return ansiRed
	case posture.SeverityMedium:
		return ansiYellow
	}
	return ""
}

func renderFindings(w io.Writer, color bool, fs []posture.Finding) {
	for _, f := range fs {
		where := f.Realm
		if f.ClientID != "" {
			where += "/" + f.ClientID
		}
		label := fmt.Sprintf("[%s]", sevLabel(f.Severity))
		if c := sevColor(f.Severity); c != "" {
			label = paint(color, c, label)
		}
		fmt.Fprintf(w, "  %s %s %s (%s)\n", label, f.RuleID, f.Title, where)
		if f.Evidence != "" {
			fmt.Fprintf(w, "      evidence: %s\n", f.Evidence)
		}
	}
}

// Render writes Guard's verdict on the planned change.
func (g GateResult) Render(w io.Writer, color bool) {
	fmt.Fprintf(w, "%s\n", paint(color, ansiBold, "Haven Guard"))
	fmt.Fprintf(w, "  score: %d (%s) -> %d (%s)\n", g.Before.Score, g.Before.Grade, g.After.Score, g.After.Grade)
	if len(g.New) > 0 {
		fmt.Fprintf(w, "\nNew findings (%d):\n", len(g.New))
		renderFindings(w, color, g.New)
	}
	if len(g.Fixed) > 0 {
		fmt.Fprintf(w, "\nFixed findings (%d):\n", len(g.Fixed))
		renderFindings(w, color, g.Fixed)
	}
	if len(g.New) == 0 && len(g.Fixed) == 0 {
		fmt.Fprintln(w, "  no change in findings")
	}
	if len(g.Blocked) > 0 {
		msg := fmt.Sprintf("BLOCKED: apply would introduce %d finding(s) at or above the --fail-on threshold. Fix the file, or override with --allow-findings.", len(g.Blocked))
		fmt.Fprintf(w, "\n%s\n", paint(color, ansiRed, msg))
	}
}
