// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"testing"

	"github.com/zyvorai/haven/internal/posture"
)

func TestDiffFindings(t *testing.T) {
	f := func(rule string, sev posture.Severity, client, evidence string) posture.Finding {
		return posture.Finding{RuleID: rule, Severity: sev, Realm: "r", ClientID: client, Evidence: evidence}
	}
	before := []posture.Finding{f("A", posture.SeverityHigh, "c", "old"), f("B", posture.SeverityLow, "", "")}
	after := []posture.Finding{f("A", posture.SeverityHigh, "c", "new evidence"), f("C", posture.SeverityHigh, "", ""), f("D", posture.SeverityLow, "", "")}
	d := DiffFindings(before, after, posture.SeverityHigh)
	if rules(d.New) != "C,D" || rules(d.Blocked) != "C" || rules(d.Fixed) != "B" {
		t.Errorf("new=%s blocked=%s fixed=%s", rules(d.New), rules(d.Blocked), rules(d.Fixed))
	}
	if d := DiffFindings(before, after, ""); len(d.Blocked) != 0 {
		t.Error("an empty threshold must block nothing")
	}
}
