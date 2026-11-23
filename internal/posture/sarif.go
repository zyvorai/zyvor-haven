// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package posture

import (
	"path/filepath"
	"strings"
)

type SARIF struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription SARIFMessage      `json:"shortDescription"`
	Help             SARIFMessage      `json:"help"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type SARIFResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    SARIFMessage      `json:"message"`
	Locations  []SARIFLocation   `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

func ToSARIF(report Report, artifactURI ...string) SARIF {
	seen := map[string]bool{}
	var sarifRules []SARIFRule
	for _, f := range report.Findings {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		r, known := rules[f.RuleID]
		if !known {
			// Findings from user policy files carry their own metadata.
			r = rule{id: f.RuleID, severity: f.Severity, title: f.Title, remediation: f.Remediation}
		}
		sarifRules = append(sarifRules, SARIFRule{
			ID:               r.id,
			Name:             r.title,
			ShortDescription: SARIFMessage{Text: r.title},
			Help:             SARIFMessage{Text: r.remediation},
			Properties:       map[string]string{"severity": string(r.severity)},
		})
	}

	locationURI := ""
	if len(artifactURI) > 0 {
		locationURI = strings.TrimSpace(artifactURI[0])
	}

	results := make([]SARIFResult, 0, len(report.Findings))
	for _, f := range report.Findings {
		msg := f.Title
		if f.Evidence != "" {
			msg += ": " + f.Evidence
		}
		props := map[string]string{"realm": f.Realm, "severity": string(f.Severity)}
		if f.ClientID != "" {
			props["clientId"] = f.ClientID
		}
		result := SARIFResult{
			RuleID:     f.RuleID,
			Level:      sarifLevel(f.Severity),
			Message:    SARIFMessage{Text: msg},
			Properties: props,
		}
		if locationURI != "" && locationURI != "-" {
			result.Locations = []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: filepath.ToSlash(locationURI)},
					Region:           SARIFRegion{StartLine: 1},
				},
			}}
		}
		results = append(results, result)
	}
	return SARIF{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           "Haven Guard",
				InformationURI: "https://github.com/zyvorai/haven",
				Rules:          sarifRules,
			}},
			Results: results,
		}},
	}
}

func sarifLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
