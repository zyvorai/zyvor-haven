// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package posture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Limits that keep a waiver file reviewable and bounded.
const (
	maxWaivers       = 1000
	maxWaiverField   = 500
	maxWaiverHorizon = 366 * 24 * time.Hour
	waiverDateLayout = "2006-01-02"
)

var waiverRuleID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Waiver is an accepted risk. It must name who accepted it, why, and when the
// acceptance lapses, so exceptions cannot silently become permanent.
type Waiver struct {
	RuleID   string `json:"ruleId"`
	Realm    string `json:"realm"`
	ClientID string `json:"clientId,omitempty"` // empty: realm-level findings only; "*": any client
	Reason   string `json:"reason"`
	Approver string `json:"approver"`
	Expires  string `json:"expires"` // YYYY-MM-DD, valid through the end of that UTC day
}

// WaivedFinding is a finding suppressed by an active waiver.
type WaivedFinding struct {
	Finding
	Reason   string `json:"reason"`
	Approver string `json:"approver"`
	Expires  string `json:"expires"`
}

type waiverFile struct {
	Version int      `json:"version"`
	Waivers []Waiver `json:"waivers"`
}

func (w Waiver) expiry() (time.Time, error) {
	d, err := time.Parse(waiverDateLayout, w.Expires)
	if err != nil {
		return time.Time{}, fmt.Errorf("expires %q is not YYYY-MM-DD", w.Expires)
	}
	return d.Add(24 * time.Hour), nil // first instant the waiver no longer applies
}

func (w Waiver) matches(f Finding) bool {
	if w.RuleID != f.RuleID || w.Realm != f.Realm {
		return false
	}
	return w.ClientID == "*" || w.ClientID == f.ClientID
}

// ParseWaivers decodes and validates a waiver file. Every waiver needs a rule,
// realm, reason, approver and an expiry no more than a year after now.
// Already-expired waivers are accepted so they can be reported as reopened.
func ParseWaivers(raw []byte, now time.Time) ([]Waiver, error) {
	var f waiverFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode waivers: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported waiver file version %d (want 1)", f.Version)
	}
	if len(f.Waivers) > maxWaivers {
		return nil, fmt.Errorf("too many waivers (%d, max %d)", len(f.Waivers), maxWaivers)
	}
	for i, w := range f.Waivers {
		at := fmt.Sprintf("waivers[%d]", i)
		if !waiverRuleID.MatchString(w.RuleID) {
			return nil, fmt.Errorf("%s: invalid ruleId %q", at, w.RuleID)
		}
		if strings.TrimSpace(w.Realm) == "" || w.Realm == "*" {
			return nil, fmt.Errorf("%s: realm must name a single realm", at)
		}
		for name, v := range map[string]string{"reason": w.Reason, "approver": w.Approver} {
			if strings.TrimSpace(v) == "" {
				return nil, fmt.Errorf("%s: %s is required", at, name)
			}
			if len(v) > maxWaiverField {
				return nil, fmt.Errorf("%s: %s exceeds %d bytes", at, name, maxWaiverField)
			}
		}
		exp, err := w.expiry()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", at, err)
		}
		if exp.After(now.Add(maxWaiverHorizon)) {
			return nil, fmt.Errorf("%s: expires %s is more than a year away", at, w.Expires)
		}
	}
	return f.Waivers, nil
}

// ApplyWaivers removes findings covered by an active waiver, recomputing counts,
// score and grade. Findings whose waiver has expired stay in the report and
// the waiver is listed in ExpiredWaivers; active waivers that match nothing
// are listed in UnusedWaivers so stale exceptions get cleaned up. The
// fingerprint is unchanged.
func (r *Report) ApplyWaivers(ws []Waiver, now time.Time) {
	r.Waived, r.ExpiredWaivers, r.UnusedWaivers = nil, nil, nil
	if len(ws) == 0 {
		return
	}
	r.Realms = append([]RealmReport(nil), r.Realms...) // do not mutate a copied report
	used := make([]bool, len(ws))
	expiredHit := make([]bool, len(ws))
	for i := range r.Realms {
		rr := &r.Realms[i]
		kept := rr.Findings[:0:0]
		for _, f := range rr.Findings {
			waived := false
			for j, w := range ws {
				if !w.matches(f) {
					continue
				}
				exp, err := w.expiry()
				if err != nil {
					continue
				}
				if !now.Before(exp) {
					expiredHit[j] = true
					continue
				}
				used[j] = true
				r.Waived = append(r.Waived, WaivedFinding{Finding: f, Reason: w.Reason, Approver: w.Approver, Expires: w.Expires})
				waived = true
				break
			}
			if !waived {
				kept = append(kept, f)
			}
		}
		rr.Findings = kept
	}
	for j, w := range ws {
		exp, err := w.expiry()
		switch {
		case expiredHit[j]:
			r.ExpiredWaivers = append(r.ExpiredWaivers, w)
		case err == nil && !used[j] && now.Before(exp):
			r.UnusedWaivers = append(r.UnusedWaivers, w)
		}
	}
	r.recompute()
}

// FindingKey identifies a finding across runs. Evidence is part of the key so
// a new offending value on an already-flagged client still counts as new.
func FindingKey(f Finding) string {
	return strings.Join([]string{f.RuleID, f.Realm, f.ClientID, f.Evidence}, "|")
}

type knownFile struct {
	Version  int      `json:"version"`
	Findings []string `json:"findings"`
}

// KnownFindings serialises the report findings as a sorted, deduplicated
// known-findings baseline for later runs.
func KnownFindings(r Report) ([]byte, error) {
	seen := map[string]bool{}
	keys := []string{}
	for _, f := range r.Findings {
		k := FindingKey(f)
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return json.MarshalIndent(knownFile{Version: 1, Findings: keys}, "", "  ")
}

// ParseKnownFindings decodes a file written by KnownFindings.
func ParseKnownFindings(raw []byte) (map[string]bool, error) {
	var f knownFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode known findings: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported known-findings version %d (want 1)", f.Version)
	}
	out := make(map[string]bool, len(f.Findings))
	for _, k := range f.Findings {
		out[k] = true
	}
	return out, nil
}

// MarkNew records which findings are absent from the known set and returns
// their severity counts. Use these counts to gate CI on regressions only.
func (r *Report) MarkNew(known map[string]bool) Counts {
	r.NewFindings = []Finding{}
	var c Counts
	for _, f := range r.Findings {
		if !known[FindingKey(f)] {
			r.NewFindings = append(r.NewFindings, f)
			increment(&c, f.Severity)
		}
	}
	r.KnownApplied = true
	return c
}
