// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const assetsDir = "../../../deploy/observability"

// contractMetrics parses the metric names from the package doc comment.
func contractMetrics(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("obs.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^//\t(haven_idp_[a-z0-9_]+)`)
	out := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out[m[1]] = true
	}
	if len(out) < 15 {
		t.Fatalf("parsed only %d contract metrics", len(out))
	}
	return out
}

var (
	reHaven    = regexp.MustCompile(`\b(haven_[a-z0-9_]+)`)
	reSelector = regexp.MustCompile(`([a-zA-Z_:][a-zA-Z0-9_:]*)\s*\{`)
)

// checkExpr asserts every metric the PromQL expression references is in the
// contract (histogram _bucket/_sum/_count series allowed).
func checkExpr(t *testing.T, where, expr string, contract map[string]bool) {
	t.Helper()
	// drop label matcher bodies so label names are not mistaken for metrics
	for _, m := range reHaven.FindAllStringSubmatch(expr, -1) {
		name := m[1]
		base := name
		for _, suf := range []string{"_bucket", "_sum", "_count"} {
			if strings.HasSuffix(name, suf) {
				base = strings.TrimSuffix(name, suf)
			}
		}
		if !contract[name] && !(base != name && contract[base]) {
			t.Errorf("%s: metric %q is not in the obs.go contract", where, name)
		}
	}
	for _, m := range reSelector.FindAllStringSubmatch(expr, -1) {
		if n := m[1]; !strings.HasPrefix(n, "haven_idp_") && n != "up" {
			t.Errorf("%s: selector on non-contract metric %q", where, n)
		}
	}
}

func TestRulesAreWellFormedAndMatchContract(t *testing.T) {
	contract := contractMetrics(t)
	raw, err := os.ReadFile(filepath.Join(assetsDir, "prometheus-rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Kind string `json:"kind"`
		Spec struct {
			Groups []struct {
				Name  string `json:"name"`
				Rules []struct {
					Alert       string            `json:"alert"`
					Expr        string            `json:"expr"`
					For         string            `json:"for"`
					Labels      map[string]string `json:"labels"`
					Annotations map[string]string `json:"annotations"`
				} `json:"rules"`
			} `json:"groups"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Kind != "PrometheusRule" || len(doc.Spec.Groups) == 0 {
		t.Fatalf("kind=%q groups=%d", doc.Kind, len(doc.Spec.Groups))
	}
	seen := map[string]bool{}
	for _, g := range doc.Spec.Groups {
		if g.Name == "" || len(g.Rules) == 0 {
			t.Errorf("group %q malformed", g.Name)
		}
		for _, r := range g.Rules {
			if r.Alert == "" || seen[r.Alert] {
				t.Errorf("alert name %q empty or duplicated", r.Alert)
			}
			seen[r.Alert] = true
			if strings.TrimSpace(r.Expr) == "" {
				t.Errorf("%s: empty expr", r.Alert)
			}
			if sev := r.Labels["severity"]; sev != "critical" && sev != "warning" && sev != "info" {
				t.Errorf("%s: severity %q", r.Alert, sev)
			}
			for _, k := range []string{"summary", "description", "action"} {
				if strings.TrimSpace(r.Annotations[k]) == "" {
					t.Errorf("%s: missing annotation %s", r.Alert, k)
				}
			}
			if strings.Count(r.Expr, "(") != strings.Count(r.Expr, ")") || strings.Count(r.Expr, "{") != strings.Count(r.Expr, "}") {
				t.Errorf("%s: unbalanced expr", r.Alert)
			}
			checkExpr(t, r.Alert, r.Expr, contract)
		}
	}
	for _, want := range []string{"HavenIdpDown", "HavenIdpStoreDown", "HavenIdp5xxRatio", "HavenIdpLatencyP99",
		"HavenIdpLoginFailureSpike", "HavenIdpRefreshTokenReuse", "HavenIdpCodeReplay", "HavenIdpLockoutBurst",
		"HavenIdpAdminAuthFailures", "HavenIdpSigningKeyStale", "HavenIdpAuditDropping", "HavenIdpAuditWebhookErrors"} {
		if !seen[want] {
			t.Errorf("missing alert %s", want)
		}
	}
}

type dashPanel struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Title   string `json:"title"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
	Panels []dashPanel `json:"panels"`
}

func TestDashboardMatchesContract(t *testing.T) {
	contract := contractMetrics(t)
	raw, err := os.ReadFile(filepath.Join(assetsDir, "grafana-dashboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		UID           string      `json:"uid"`
		SchemaVersion int         `json:"schemaVersion"`
		Panels        []dashPanel `json:"panels"`
		Templating    struct {
			List []struct {
				Name  string          `json:"name"`
				Type  string          `json:"type"`
				Query json.RawMessage `json:"query"`
			} `json:"list"`
		} `json:"templating"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if d.UID == "" || d.SchemaVersion < 36 {
		t.Errorf("uid=%q schemaVersion=%d", d.UID, d.SchemaVersion)
	}
	vars := map[string]bool{}
	for _, v := range d.Templating.List {
		vars[v.Name] = true
		if v.Type == "query" {
			checkExpr(t, "variable "+v.Name, string(v.Query), contract)
		}
	}
	if !vars["datasource"] || !vars["realm"] {
		t.Errorf("template variables: %v", vars)
	}
	core := map[string]bool{"timeseries": true, "stat": true, "row": true, "gauge": true, "table": true, "bargauge": true}
	ids := map[int]bool{}
	nExpr := 0
	var walk func([]dashPanel)
	walk = func(ps []dashPanel) {
		for _, p := range ps {
			if p.ID == 0 || ids[p.ID] {
				t.Errorf("panel %q: id %d missing or duplicated", p.Title, p.ID)
			}
			ids[p.ID] = true
			if !core[p.Type] {
				t.Errorf("panel %q: non-core type %q", p.Title, p.Type)
			}
			for _, tg := range p.Targets {
				nExpr++
				checkExpr(t, p.Title, tg.Expr, contract)
			}
			walk(p.Panels)
		}
	}
	walk(d.Panels)
	if nExpr < 15 {
		t.Errorf("only %d expressions", nExpr)
	}
}

func TestScrapeAssets(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(assetsDir, "servicemonitor.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var sm struct {
		Kind string `json:"kind"`
		Spec struct {
			Endpoints []struct {
				Port string `json:"port"`
			} `json:"endpoints"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &sm); err != nil {
		t.Fatal(err)
	}
	if sm.Kind != "ServiceMonitor" || len(sm.Spec.Endpoints) != 1 || sm.Spec.Endpoints[0].Port != "metrics" {
		t.Errorf("servicemonitor: %+v", sm)
	}
	raw, err = os.ReadFile(filepath.Join(assetsDir, "prometheus-scrape-config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var sc struct {
		ScrapeConfigs []struct {
			JobName string `json:"job_name"`
		} `json:"scrape_configs"`
	}
	if err := yaml.Unmarshal(raw, &sc); err != nil {
		t.Fatal(err)
	}
	if len(sc.ScrapeConfigs) != 1 || sc.ScrapeConfigs[0].JobName != "haven-idp" {
		t.Errorf("scrape config: %+v", sc)
	}
}
