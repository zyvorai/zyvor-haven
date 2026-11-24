// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package posture

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// RuleInfo describes one built-in rule.
type RuleInfo struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Remediation string   `json:"remediation"`
}

// Rules returns the built-in rule catalog sorted by ID.
func Rules() []RuleInfo {
	out := make([]RuleInfo, 0, len(rules))
	for _, r := range rules {
		out = append(out, RuleInfo{ID: r.id, Severity: r.severity, Title: r.title, Remediation: r.remediation})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RuleByID looks up a built-in rule; the ID match is case-insensitive.
func RuleByID(id string) (RuleInfo, bool) {
	r, ok := rules[strings.ToUpper(strings.TrimSpace(id))]
	if !ok {
		return RuleInfo{}, false
	}
	return RuleInfo{ID: r.id, Severity: r.severity, Title: r.title, Remediation: r.remediation}, true
}

// mdCell makes a value safe inside a Markdown table cell or inline text, so
// evidence taken from a realm export cannot break out of the table or inject
// HTML into a pull-request comment.
func mdCell(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ", "|", "\\|", "<", "&lt;", ">", "&gt;", "`", "'").Replace(s)
	return strings.TrimSpace(s)
}

// ToMarkdown renders the report for a pull-request comment or a GitHub job
// summary. The gate counts decide the headline when a known-findings baseline
// is in use.
func ToMarkdown(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Haven Guard: score %d (%s)\n\n", r.Score, mdCell(r.Grade))
	fmt.Fprintf(&b, "%d realm(s), %d client(s). Critical %d, high %d, medium %d, low %d.\n\n",
		r.RealmCount, r.ClientCount, r.Counts.Critical, r.Counts.High, r.Counts.Medium, r.Counts.Low)
	if r.Baseline != "" {
		fmt.Fprintf(&b, "Configuration drift from the baseline fingerprint: **%t**.\n\n", r.Drifted)
	}
	if r.KnownApplied {
		fmt.Fprintf(&b, "**%d new finding(s)** since the known-findings baseline.\n\n", len(r.NewFindings))
	}
	if n := len(r.Waived); n > 0 {
		fmt.Fprintf(&b, "%d finding(s) are covered by active waivers.\n\n", n)
	}
	for _, w := range r.ExpiredWaivers {
		fmt.Fprintf(&b, "- Waiver for %s %s %s expired %s (approver %s): finding reopened.\n",
			mdCell(w.RuleID), mdCell(w.Realm), mdCell(w.ClientID), mdCell(w.Expires), mdCell(w.Approver))
	}
	for _, w := range r.UnusedWaivers {
		fmt.Fprintf(&b, "- Waiver for %s %s %s matches no finding: remove it.\n", mdCell(w.RuleID), mdCell(w.Realm), mdCell(w.ClientID))
	}
	if len(r.ExpiredWaivers)+len(r.UnusedWaivers) > 0 {
		b.WriteString("\n")
	}
	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	b.WriteString("| Rule | Severity | Scope | Finding | Evidence |\n|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		scope := f.Realm
		if f.ClientID != "" {
			scope += "/" + f.ClientID
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", mdCell(f.RuleID), mdCell(string(f.Severity)),
			mdCell(scope), mdCell(f.Title), mdCell(f.Evidence))
	}
	return b.String()
}

type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

// ToJUnit renders the report as JUnit XML for CI systems that show test
// results (GitLab, Jenkins, Azure DevOps). One suite per realm; each finding
// is a failed test case named like Checkov's "[severity][rule] title", and
// waived findings are skipped cases that carry the waiver reason.
func ToJUnit(r Report) ([]byte, error) {
	out := junitSuites{Suites: []junitSuite{}}
	idx := map[string]int{}
	suite := func(realm string) *junitSuite {
		i, ok := idx[realm]
		if !ok {
			out.Suites = append(out.Suites, junitSuite{Name: realm})
			i = len(out.Suites) - 1
			idx[realm] = i
		}
		return &out.Suites[i]
	}
	name := func(f Finding) (string, string) {
		class := f.Realm
		if f.ClientID != "" {
			class += "." + f.ClientID
		}
		return fmt.Sprintf("[%s][%s] %s", f.Severity, f.RuleID, f.Title), class
	}
	for _, rr := range r.Realms {
		s := suite(rr.Realm)
		for _, f := range rr.Findings {
			n, class := name(f)
			s.Cases = append(s.Cases, junitCase{Name: n, ClassName: class, Failure: &junitFailure{
				Message: f.Title, Type: string(f.Severity), Body: strings.TrimSpace(f.Evidence + "\nFix: " + f.Remediation)}})
			s.Failures++
		}
	}
	for _, w := range r.Waived {
		s := suite(w.Realm)
		n, class := name(w.Finding)
		s.Cases = append(s.Cases, junitCase{Name: n, ClassName: class, Skipped: &junitSkipped{Message: w.Reason}})
		s.Skipped++
	}
	for i := range out.Suites {
		out.Suites[i].Tests = len(out.Suites[i].Cases)
	}
	b, err := xml.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(b, '\n')...), nil
}
