// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package posture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/zyvorai/haven/internal/keycloak"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	Realm       string   `json:"realm"`
	ClientID    string   `json:"clientId,omitempty"`
	Title       string   `json:"title"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation"`
}

type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type RealmReport struct {
	Realm       string    `json:"realm"`
	Score       int       `json:"score"`
	Fingerprint string    `json:"fingerprint"`
	ClientCount int       `json:"clientCount"`
	Counts      Counts    `json:"counts"`
	Findings    []Finding `json:"findings"`
}

type Report struct {
	Score       int           `json:"score"`
	Grade       string        `json:"grade"`
	Fingerprint string        `json:"fingerprint"`
	Baseline    string        `json:"baseline,omitempty"`
	Drifted     bool          `json:"drifted,omitempty"`
	RealmCount  int           `json:"realmCount"`
	ClientCount int           `json:"clientCount"`
	Counts      Counts        `json:"counts"`
	Findings    []Finding     `json:"findings"`
	Realms      []RealmReport `json:"realms"`
}

type Options struct {
	Baseline string
}

type rule struct {
	id          string
	severity    Severity
	title       string
	remediation string
}

var rules = map[string]rule{
	"HAVEN001": {"HAVEN001", SeverityCritical, "Wildcard redirect URI", "Replace wildcard redirects with exact HTTPS callback URIs."},
	"HAVEN002": {"HAVEN002", SeverityHigh, "Insecure redirect URI", "Use HTTPS for every non-loopback redirect URI."},
	"HAVEN003": {"HAVEN003", SeverityHigh, "Wildcard web origin", "Replace '*' with explicit trusted origins."},
	"HAVEN004": {"HAVEN004", SeverityHigh, "Public client allows password grants", "Disable Direct Access Grants for browser/native public clients."},
	"HAVEN005": {"HAVEN005", SeverityHigh, "Public auth-code client does not require PKCE S256", "Set the client PKCE code challenge method to S256."},
	"HAVEN006": {"HAVEN006", SeverityHigh, "Implicit flow enabled", "Disable implicit flow and use Authorization Code + PKCE."},
	"HAVEN007": {"HAVEN007", SeverityHigh, "Public client has service accounts enabled", "Disable service accounts or convert the client to a confidential workload client."},
	"HAVEN008": {"HAVEN008", SeverityMedium, "Confidential client allows password grants", "Prefer Authorization Code or Client Credentials and disable Direct Access Grants."},
	"HAVEN009": {"HAVEN009", SeverityMedium, "Bearer-only client has interactive flow enabled", "Disable browser flows on bearer-only resource-server clients."},
	"HAVEN010": {"HAVEN010", SeverityMedium, "Auth-code client has no redirect URI", "Configure at least one exact callback URI or disable Standard Flow."},
	"HAVEN011": {"HAVEN011", SeverityMedium, "Realm permits self-registration without verified email", "Require email verification when self-registration is enabled."},
	"HAVEN012": {"HAVEN012", SeverityMedium, "Realm brute-force protection disabled", "Enable Keycloak brute-force detection for interactive user realms."},
	"HAVEN013": {"HAVEN013", SeverityLow, "Disabled client remains configured", "Remove stale clients or document why they are intentionally retained."},
}

func Evaluate(realms []keycloak.Realm, clients map[string][]keycloak.Client, opts Options) Report {
	sortedRealms := append([]keycloak.Realm(nil), realms...)
	sort.Slice(sortedRealms, func(i, j int) bool { return sortedRealms[i].Realm < sortedRealms[j].Realm })

	report := Report{Baseline: strings.TrimSpace(opts.Baseline)}
	for _, realm := range sortedRealms {
		rr := evaluateRealm(realm, clients[realm.Realm])
		report.Realms = append(report.Realms, rr)
		report.Findings = append(report.Findings, rr.Findings...)
		report.ClientCount += rr.ClientCount
		addCounts(&report.Counts, rr.Counts)
	}
	report.RealmCount = len(report.Realms)
	report.Score = score(report.Counts)
	report.Grade = grade(report.Score)
	report.Fingerprint = fingerprintReport(report.Realms)
	if report.Baseline != "" {
		report.Drifted = normalizeFingerprint(report.Baseline) != normalizeFingerprint(report.Fingerprint)
	}
	return report
}

func evaluateRealm(realm keycloak.Realm, clients []keycloak.Client) RealmReport {
	sortedClients := append([]keycloak.Client(nil), clients...)
	sort.Slice(sortedClients, func(i, j int) bool { return sortedClients[i].ClientID < sortedClients[j].ClientID })

	rr := RealmReport{Realm: realm.Realm}
	if realm.RegistrationAllowed && !realm.VerifyEmail {
		rr.Findings = append(rr.Findings, finding("HAVEN011", realm.Realm, "", "registrationAllowed=true, verifyEmail=false"))
	}
	if realm.Enabled && !realm.BruteForceProtected && realm.Realm != "master" {
		rr.Findings = append(rr.Findings, finding("HAVEN012", realm.Realm, "", "bruteForceProtected=false"))
	}

	for _, client := range sortedClients {
		if isBuiltInClient(client.ClientID) {
			continue
		}
		rr.ClientCount++
		rr.Findings = append(rr.Findings, evaluateClient(realm.Realm, client)...)
	}
	for _, f := range rr.Findings {
		increment(&rr.Counts, f.Severity)
	}
	rr.Score = score(rr.Counts)
	rr.Fingerprint = fingerprintRealm(realm, sortedClients)
	return rr
}

func evaluateClient(realm string, c keycloak.Client) []Finding {
	var out []Finding
	if !c.Enabled {
		out = append(out, finding("HAVEN013", realm, c.ClientID, "enabled=false"))
	}
	if c.Protocol != "" && c.Protocol != "openid-connect" {
		return out
	}

	for _, raw := range c.RedirectURIs {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}
		if containsUnsafeWildcard(u) {
			out = append(out, finding("HAVEN001", realm, c.ClientID, u))
		}
		if isInsecureRedirect(u) {
			out = append(out, finding("HAVEN002", realm, c.ClientID, u))
		}
	}
	for _, origin := range c.WebOrigins {
		if strings.TrimSpace(origin) == "*" || strings.Contains(origin, "*") {
			out = append(out, finding("HAVEN003", realm, c.ClientID, origin))
		}
	}
	if c.PublicClient && c.DirectAccessGrantsEnabled {
		out = append(out, finding("HAVEN004", realm, c.ClientID, "publicClient=true, directAccessGrantsEnabled=true"))
	}
	if c.PublicClient && c.StandardFlowEnabled && !hasPKCES256(c) {
		out = append(out, finding("HAVEN005", realm, c.ClientID, "pkce.code.challenge.method is not S256"))
	}
	if c.ImplicitFlowEnabled {
		out = append(out, finding("HAVEN006", realm, c.ClientID, "implicitFlowEnabled=true"))
	}
	if c.PublicClient && c.ServiceAccountsEnabled {
		out = append(out, finding("HAVEN007", realm, c.ClientID, "publicClient=true, serviceAccountsEnabled=true"))
	}
	if !c.PublicClient && !c.BearerOnly && c.DirectAccessGrantsEnabled {
		out = append(out, finding("HAVEN008", realm, c.ClientID, "directAccessGrantsEnabled=true"))
	}
	if c.BearerOnly && (c.StandardFlowEnabled || c.ImplicitFlowEnabled || c.DirectAccessGrantsEnabled) {
		out = append(out, finding("HAVEN009", realm, c.ClientID, "bearerOnly=true with an interactive grant enabled"))
	}
	if c.StandardFlowEnabled && len(c.RedirectURIs) == 0 {
		out = append(out, finding("HAVEN010", realm, c.ClientID, "standardFlowEnabled=true, redirectUris=[]"))
	}
	return out
}

func finding(id, realm, clientID, evidence string) Finding {
	r := rules[id]
	return Finding{
		RuleID:      r.id,
		Severity:    r.severity,
		Realm:       realm,
		ClientID:    clientID,
		Title:       r.title,
		Evidence:    evidence,
		Remediation: r.remediation,
	}
}

func containsUnsafeWildcard(raw string) bool {
	if raw == "*" {
		return true
	}
	return strings.Contains(raw, "*")
}

func isInsecureRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return false
	}
	if strings.EqualFold(u.Scheme, "https") {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return true
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

func hasPKCES256(c keycloak.Client) bool {
	for _, key := range []string{"pkce.code.challenge.method", "pkceCodeChallengeMethod"} {
		if strings.EqualFold(strings.TrimSpace(c.Attributes[key]), "S256") {
			return true
		}
	}
	return false
}

func isBuiltInClient(id string) bool {
	switch id {
	case "account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console":
		return true
	default:
		return false
	}
}

func increment(c *Counts, s Severity) {
	switch s {
	case SeverityCritical:
		c.Critical++
	case SeverityHigh:
		c.High++
	case SeverityMedium:
		c.Medium++
	case SeverityLow:
		c.Low++
	default:
		c.Info++
	}
}

func addCounts(dst *Counts, src Counts) {
	dst.Critical += src.Critical
	dst.High += src.High
	dst.Medium += src.Medium
	dst.Low += src.Low
	dst.Info += src.Info
}

func score(c Counts) int {
	penalty := c.Critical*30 + c.High*15 + c.Medium*7 + c.Low*3
	if penalty > 100 {
		penalty = 100
	}
	return 100 - penalty
}

func grade(s int) string {
	switch {
	case s >= 95:
		return "A"
	case s >= 85:
		return "B"
	case s >= 70:
		return "C"
	case s >= 50:
		return "D"
	default:
		return "F"
	}
}

func normalizeFingerprint(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "sha256:")
}

type fingerprintClient struct {
	ClientID                  string            `json:"clientId"`
	Enabled                   bool              `json:"enabled"`
	PublicClient              bool              `json:"publicClient"`
	BearerOnly                bool              `json:"bearerOnly"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	RedirectURIs              []string          `json:"redirectUris"`
	WebOrigins                []string          `json:"webOrigins"`
	Attributes                map[string]string `json:"attributes"`
}

type fingerprintRealmModel struct {
	Realm               string              `json:"realm"`
	Enabled             bool                `json:"enabled"`
	RegistrationAllowed bool                `json:"registrationAllowed"`
	VerifyEmail         bool                `json:"verifyEmail"`
	BruteForceProtected bool                `json:"bruteForceProtected"`
	Clients             []fingerprintClient `json:"clients"`
}

func fingerprintRealm(realm keycloak.Realm, clients []keycloak.Client) string {
	model := fingerprintRealmModel{
		Realm:               realm.Realm,
		Enabled:             realm.Enabled,
		RegistrationAllowed: realm.RegistrationAllowed,
		VerifyEmail:         realm.VerifyEmail,
		BruteForceProtected: realm.BruteForceProtected,
	}
	for _, c := range clients {
		if isBuiltInClient(c.ClientID) {
			continue
		}
		redirects := append([]string(nil), c.RedirectURIs...)
		origins := append([]string(nil), c.WebOrigins...)
		sort.Strings(redirects)
		sort.Strings(origins)
		attrs := map[string]string{}
		for _, k := range []string{"pkce.code.challenge.method", "pkceCodeChallengeMethod"} {
			if v, ok := c.Attributes[k]; ok {
				attrs[k] = v
			}
		}
		model.Clients = append(model.Clients, fingerprintClient{
			ClientID:                  c.ClientID,
			Enabled:                   c.Enabled,
			PublicClient:              c.PublicClient,
			BearerOnly:                c.BearerOnly,
			StandardFlowEnabled:       c.StandardFlowEnabled,
			ImplicitFlowEnabled:       c.ImplicitFlowEnabled,
			DirectAccessGrantsEnabled: c.DirectAccessGrantsEnabled,
			ServiceAccountsEnabled:    c.ServiceAccountsEnabled,
			RedirectURIs:              redirects,
			WebOrigins:                origins,
			Attributes:                attrs,
		})
	}
	sort.Slice(model.Clients, func(i, j int) bool { return model.Clients[i].ClientID < model.Clients[j].ClientID })
	return hashJSON(model)
}

func fingerprintReport(realms []RealmReport) string {
	items := make([]struct {
		Realm       string `json:"realm"`
		Fingerprint string `json:"fingerprint"`
	}, 0, len(realms))
	for _, r := range realms {
		items = append(items, struct {
			Realm       string `json:"realm"`
			Fingerprint string `json:"fingerprint"`
		}{r.Realm, r.Fingerprint})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Realm < items[j].Realm })
	return hashJSON(items)
}

func hashJSON(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
