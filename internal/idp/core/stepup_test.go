// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"slices"
	"testing"
	"time"
)

func TestDecideStepUp(t *testing.T) {
	all := StepUpPolicy{Enabled: true, OnNewDevice: true, OnIPChange: true, IdleAfter: time.Hour,
		OnMaxAge: true, SensitiveScopes: []string{"offline_access", "roles"}, SensitiveAuthMaxAge: 5 * time.Minute}
	cases := []struct {
		name string
		p    StepUpPolicy
		s    RiskSignals
		want []string
	}{
		{"disabled never fires", StepUpPolicy{OnNewDevice: true, OnIPChange: true, IdleAfter: 1, OnMaxAge: true,
			SensitiveScopes: []string{"roles"}}, RiskSignals{NewDevice: true, IPChanged: true, IdleFor: time.Hour,
			Scopes: []string{"roles"}, MaxAgeRequested: true}, nil},
		{"zero policy", StepUpPolicy{}, RiskSignals{NewDevice: true}, nil},
		{"enabled but no rule on", StepUpPolicy{Enabled: true}, RiskSignals{NewDevice: true, IPChanged: true}, nil},
		{"calm", all, RiskSignals{}, nil},
		{"new device", all, RiskSignals{NewDevice: true}, []string{ReasonNewDevice}},
		{"new device rule off", StepUpPolicy{Enabled: true, OnIPChange: true}, RiskSignals{NewDevice: true}, nil},
		{"ip change", all, RiskSignals{IPChanged: true}, []string{ReasonIPChanged}},
		{"idle just below", all, RiskSignals{IdleFor: time.Hour - time.Second}, nil},
		{"idle exactly", all, RiskSignals{IdleFor: time.Hour}, []string{ReasonIdle}},
		{"idle rule off (0)", StepUpPolicy{Enabled: true}, RiskSignals{IdleFor: 1000 * time.Hour}, nil},
		{"sensitive fresh login, max age 5m", all, RiskSignals{Scopes: []string{"openid", "roles"}}, nil},
		{"sensitive, auth too old", all, RiskSignals{Scopes: []string{"openid", "roles"}, AuthAge: 5*time.Minute + time.Second},
			[]string{ReasonSensitiveScope}},
		{"sensitive, auth at the limit", all, RiskSignals{Scopes: []string{"roles"}, AuthAge: 5 * time.Minute}, nil},
		{"non-sensitive scopes", all, RiskSignals{Scopes: []string{"openid", "profile", "email"}, AuthAge: time.Hour}, nil},
		{"sensitive, max age 0 = always", StepUpPolicy{Enabled: true, SensitiveScopes: []string{"offline_access"}},
			RiskSignals{Scopes: []string{"offline_access"}}, []string{ReasonSensitiveScope}},
		{"max_age", all, RiskSignals{MaxAgeRequested: true}, []string{ReasonMaxAge}},
		{"max_age rule off", StepUpPolicy{Enabled: true, OnNewDevice: true}, RiskSignals{MaxAgeRequested: true}, nil},
		{"everything, fixed order", all, RiskSignals{NewDevice: true, IPChanged: true, IdleFor: 2 * time.Hour,
			Scopes: []string{"roles"}, AuthAge: time.Hour, MaxAgeRequested: true},
			[]string{ReasonNewDevice, ReasonIPChanged, ReasonIdle, ReasonSensitiveScope, ReasonMaxAge}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DecideStepUp(c.p, c.s)
			if !slices.Equal(got.Reasons, c.want) {
				t.Fatalf("reasons %v, want %v", got.Reasons, c.want)
			}
			if got.Required != (len(c.want) > 0) {
				t.Fatalf("required=%v with reasons %v", got.Required, c.want)
			}
		})
	}
}

// Enforce only decides whether the caller acts; the decision itself must not
// change, or report-only mode would show something other than the real one.
func TestDecideStepUpIgnoresEnforce(t *testing.T) {
	a := StepUpPolicy{Enabled: true, OnNewDevice: true}
	b := a
	b.Enforce = true
	s := RiskSignals{NewDevice: true}
	if x, y := DecideStepUp(a, s), DecideStepUp(b, s); !x.Required || !slices.Equal(x.Reasons, y.Reasons) || x.Required != y.Required {
		t.Fatalf("%v vs %v", x, y)
	}
}
