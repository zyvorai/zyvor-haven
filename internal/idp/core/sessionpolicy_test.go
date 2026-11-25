// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"testing"
	"time"
)

func TestSessionPolicyBounds(t *testing.T) {
	day := 24 * time.Hour
	for name, c := range map[string]struct {
		in        SessionPolicy
		idle, abs time.Duration
	}{
		"defaults":         {SessionPolicy{}, 7 * day, 30 * day},
		"given":            {SessionPolicy{RememberIdle: 2 * day, RememberMax: 5 * day}, 2 * day, 5 * day},
		"huge max":         {SessionPolicy{RememberIdle: 400 * day, RememberMax: 4000 * day}, 90 * day, 90 * day},
		"tiny":             {SessionPolicy{RememberIdle: time.Second, RememberMax: time.Second}, time.Hour, day},
		"negative":         {SessionPolicy{RememberIdle: -1, RememberMax: -1}, 7 * day, 30 * day},
		"idle over max":    {SessionPolicy{RememberIdle: 20 * day, RememberMax: 3 * day}, 3 * day, 3 * day},
		"default idle cap": {SessionPolicy{RememberMax: 2 * day}, 2 * day, 2 * day},
	} {
		idle, abs := c.in.RememberLifetimes()
		if idle != c.idle || abs != c.abs {
			t.Errorf("%s: idle %v max %v, want %v %v", name, idle, abs, c.idle, c.abs)
		}
	}
	for name, p := range map[string]SessionPolicy{
		"zero": {}, "limit": {MaxSessions: 1000, OnLimit: SessionLimitDenyNew},
		"remember": {RememberMe: true, RememberIdle: time.Hour, RememberMax: 90 * day},
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, p := range map[string]SessionPolicy{
		"negative limit":   {MaxSessions: -1},
		"limit too high":   {MaxSessions: 1001},
		"action":           {OnLimit: "kick"},
		"max too long":     {RememberMax: 91 * day},
		"max too short":    {RememberMax: 23 * time.Hour},
		"idle too short":   {RememberIdle: time.Minute},
		"idle too long":    {RememberIdle: 91 * day},
		"idle over max":    {RememberIdle: 3 * day, RememberMax: 2 * day},
		"idle over def":    {RememberIdle: 31 * day},
		"negative max":     {RememberMax: -day},
		"negative idle":    {RememberIdle: -day},
		"negative both":    {RememberIdle: -day, RememberMax: -day},
		"over default max": {RememberIdle: 60 * day},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
