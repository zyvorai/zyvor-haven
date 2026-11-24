// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"github.com/zyvorai/haven/internal/idmodel"
	"github.com/zyvorai/haven/internal/posture"
)

func severityRank(s posture.Severity) int {
	switch s {
	case posture.SeverityCritical:
		return 5
	case posture.SeverityHigh:
		return 4
	case posture.SeverityMedium:
		return 3
	case posture.SeverityLow:
		return 2
	case posture.SeverityInfo:
		return 1
	}
	return 0
}

// SeverityAtLeast reports whether s is at or above threshold. An unknown or
// empty threshold matches nothing (the gate is disabled).
func SeverityAtLeast(s, threshold posture.Severity) bool {
	t := severityRank(threshold)
	return t > 0 && severityRank(s) >= t
}

type findingKey struct{ rule, realm, client string }

func keyOf(f posture.Finding) findingKey { return findingKey{f.RuleID, f.Realm, f.ClientID} }

// Gate evaluates Guard on the live state (nil = nothing) and on the state
// after applying desired, and reports the findings that would appear (New),
// disappear (Fixed), and those New ones at or above threshold (Blocked).
func Gate(desired, live *Spec, threshold posture.Severity) GateResult {
	var res GateResult
	res.Before = evaluate(live)
	res.After = evaluate(overlay(desired, live))

	before := map[findingKey]bool{}
	for _, f := range res.Before.Findings {
		before[keyOf(f)] = true
	}
	after := map[findingKey]bool{}
	for _, f := range res.After.Findings {
		after[keyOf(f)] = true
		if !before[keyOf(f)] {
			res.New = append(res.New, f)
			if SeverityAtLeast(f.Severity, threshold) {
				res.Blocked = append(res.Blocked, f)
			}
		}
	}
	for _, f := range res.Before.Findings {
		if !after[keyOf(f)] {
			res.Fixed = append(res.Fixed, f)
		}
	}
	return res
}

func evaluate(s *Spec) posture.Report {
	if s == nil {
		return posture.Evaluate(nil, nil, posture.Options{})
	}
	realm, clients := toModel(s)
	return posture.Evaluate([]idmodel.Realm{realm}, map[string][]idmodel.Client{realm.Name: clients}, posture.Options{})
}

func ptr[T any](v T) *T { return &v }

// pick returns desired, else live, else the secure default.
func pick[T any](d, l *T, def T) *T {
	if d != nil {
		return d
	}
	if l != nil {
		return l
	}
	return ptr(def)
}

// overlay computes the spec that results from applying desired onto live.
func overlay(desired, live *Spec) *Spec {
	if desired == nil {
		return live
	}
	var l Spec
	if live != nil {
		l = *live
	}
	out := Spec{APIVersion: desired.APIVersion, Kind: desired.Kind, Realm: desired.Realm, DisplayName: desired.DisplayName}
	if out.DisplayName == "" {
		out.DisplayName = l.DisplayName
	}
	out.Enabled = pick(desired.Enabled, l.Enabled, true)
	d, ls := desired.Settings, l.Settings
	out.Settings = Settings{
		SelfRegistration:          pick(d.SelfRegistration, ls.SelfRegistration, false),
		EmailVerificationRequired: pick(d.EmailVerificationRequired, ls.EmailVerificationRequired, false),
		BruteForceProtection:      pick(d.BruteForceProtection, ls.BruteForceProtection, true),
		TransportSecurity:         pick(d.TransportSecurity, ls.TransportSecurity, "external"),
		PasswordPolicy:            pick(d.PasswordPolicy, ls.PasswordPolicy, "length(12)"),
		AccessTokenSeconds:        pick(d.AccessTokenSeconds, ls.AccessTokenSeconds, 300),
		SessionIdleSeconds:        pick(d.SessionIdleSeconds, ls.SessionIdleSeconds, 1800),
		AuthEvents:                pick(d.AuthEvents, ls.AuthEvents, true),
		AdminEvents:               pick(d.AdminEvents, ls.AdminEvents, true),
		RefreshTokenRotation:      pick(d.RefreshTokenRotation, ls.RefreshTokenRotation, true),
	}
	byID := map[string]int{}
	for _, c := range l.Clients {
		byID[c.ClientID] = len(out.Clients)
		out.Clients = append(out.Clients, c)
	}
	for _, c := range desired.Clients {
		if i, ok := byID[c.ClientID]; ok {
			out.Clients[i] = c
		} else {
			byID[c.ClientID] = len(out.Clients)
			out.Clients = append(out.Clients, c)
		}
	}
	return &out
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// toModel maps a resolved Spec to the Guard model.
func toModel(s *Spec) (idmodel.Realm, []idmodel.Client) {
	st := s.Settings
	r := idmodel.Realm{
		ID: s.Realm, Name: s.Realm, DisplayName: s.DisplayName,
		Enabled:                   boolOr(s.Enabled, true),
		SelfRegistration:          boolOr(st.SelfRegistration, false),
		EmailVerificationRequired: boolOr(st.EmailVerificationRequired, false),
		BruteForceProtection:      boolOr(st.BruteForceProtection, true),
		Hardening: &idmodel.Hardening{
			TransportSecurity:     st.TransportSecurity,
			PasswordPolicy:        st.PasswordPolicy,
			AccessTokenTTLSeconds: st.AccessTokenSeconds,
			SessionIdleTTLSeconds: st.SessionIdleSeconds,
			AuthEventsLogged:      st.AuthEvents,
			AdminEventsLogged:     st.AdminEvents,
			RefreshTokenRotation:  st.RefreshTokenRotation,
		},
	}
	var cs []idmodel.Client
	for _, c := range s.Clients {
		mc := idmodel.Client{
			ID: c.ClientID, ClientID: c.ClientID, Name: c.Name,
			Enabled:        boolOr(c.Enabled, true),
			Public:         c.Public,
			Protocol:       "openid-connect",
			RedirectURIs:   append([]string(nil), c.RedirectURIs...),
			Origins:        append([]string(nil), c.Origins...),
			AuthCodeFlow:   boolOr(c.AuthCodeFlow, !c.ServiceAccount),
			ServiceAccount: c.ServiceAccount,
		}
		mc.BackchannelLogoutURL = c.BackchannelLogoutURL
		if boolOr(c.RequirePKCE, c.Public) {
			mc.PKCEMethod = "S256"
			mc.Attrs = map[string]string{"pkce.code.challenge.method": "S256"}
		}
		cs = append(cs, mc)
	}
	return r, cs
}
