// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package accessreview turns a realm snapshot into an access recertification
// report (who holds privileged access, which accounts look stale) and tracks
// reviewer decisions in an append-only campaign ledger. It never reads or
// stores credentials, and it never changes Keycloak: a "revoke" decision is a
// recorded work item for an administrator to carry out.
package accessreview

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/zyvorai/haven/internal/identityops"
)

const (
	MaxUsers          = 20000
	MaxPatternLen     = 128
	MaxNoteLen        = 500
	MaxCampaignsStore = 500
)

var (
	// A role or group is privileged when a token of its name is one of these,
	// or it carries the Keycloak realm-management "manage-" prefix.
	privilegedToken = regexp.MustCompile(`(?i)(^|[^a-z0-9])(admin|administrator|admins|owner|superuser|root|impersonation)([^a-z0-9]|$)`)
	managePrefix    = regexp.MustCompile(`(?i)(^|/)manage-[a-z-]+$`)
	// DefaultBreakGlassPattern matches common emergency-account names.
	DefaultBreakGlassPattern = `(?i)^(break[-_.]?glass|emergency|bg)[-_.a-z0-9]*$`
)

type Options struct {
	// BreakGlassPattern is an RE2 expression matched against usernames.
	BreakGlassPattern string `json:"breakGlassPattern,omitempty"`
}

type Item struct {
	Username       string   `json:"username"`
	Enabled        bool     `json:"enabled"`
	EmailVerified  bool     `json:"emailVerified"`
	RealmRoles     []string `json:"realmRoles,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	PendingActions []string `json:"pendingActions,omitempty"`
	Flags          []string `json:"flags,omitempty"`
	Risk           string   `json:"risk"`
}

type BreakGlass struct {
	Pattern  string   `json:"pattern"`
	Accounts []string `json:"accounts"`
	Warnings []string `json:"warnings,omitempty"`
}

type Summary struct {
	Users        int `json:"users"`
	WithAccess   int `json:"withAccess"`
	Privileged   int `json:"privileged"`
	StaleAccess  int `json:"staleAccess"`
	HighRisk     int `json:"highRisk"`
	MediumRisk   int `json:"mediumRisk"`
	BreakGlass   int `json:"breakGlass"`
	NoAccessOnly int `json:"noAccess"`
}

type Report struct {
	Realm      string     `json:"realm"`
	SnapshotID string     `json:"snapshotId,omitempty"`
	Summary    Summary    `json:"summary"`
	BreakGlass BreakGlass `json:"breakGlass"`
	Items      []Item     `json:"items"`
}

// IsPrivileged reports whether a realm role or group path grants admin-like access.
func IsPrivileged(name string) bool {
	return privilegedToken.MatchString(name) || managePrefix.MatchString(name)
}

// Analyze builds the report. Output is sorted and deterministic.
func Analyze(snap identityops.RealmSnapshot, opts Options) (Report, error) {
	if len(snap.Users) > MaxUsers {
		return Report{}, fmt.Errorf("realm has %d users, maximum for a review is %d", len(snap.Users), MaxUsers)
	}
	pattern := strings.TrimSpace(opts.BreakGlassPattern)
	if pattern == "" {
		pattern = DefaultBreakGlassPattern
	}
	if len(pattern) > MaxPatternLen {
		return Report{}, fmt.Errorf("break-glass pattern is limited to %d bytes", MaxPatternLen)
	}
	bg, err := regexp.Compile(pattern) // RE2: linear time
	if err != nil {
		return Report{}, fmt.Errorf("invalid break-glass pattern: %w", err)
	}

	access := map[string]identityops.UserAccess{}
	for _, a := range snap.UserAccess {
		access[a.Username] = a
	}
	rep := Report{Realm: snap.Realm, SnapshotID: snap.ID, BreakGlass: BreakGlass{Pattern: pattern, Accounts: []string{}}}
	rep.Summary.Users = len(snap.Users)
	enabledBG := 0

	for _, u := range snap.Users {
		if strings.HasPrefix(u.Username, "service-account-") {
			rep.Summary.Users--
			continue
		}
		a := access[u.Username]
		roles := dedupSorted(a.RealmRoles)
		groups := dedupSorted(a.Groups)
		isBG := bg.MatchString(u.Username)
		hasAccess := len(roles)+len(groups) > 0
		if !hasAccess && !isBG {
			rep.Summary.NoAccessOnly++
			continue
		}
		it := Item{
			Username: u.Username, Enabled: u.Enabled, EmailVerified: u.EmailVerified,
			RealmRoles: roles, Groups: groups, PendingActions: dedupSorted(u.RequiredActions),
		}
		privileged := anyPrivileged(roles) || anyPrivileged(groups)
		if privileged {
			it.Flags = append(it.Flags, "privileged")
			rep.Summary.Privileged++
		}
		if !u.Enabled && hasAccess {
			it.Flags = append(it.Flags, "disabled-with-access")
			rep.Summary.StaleAccess++
		}
		if privileged && u.Enabled && !u.EmailVerified {
			it.Flags = append(it.Flags, "privileged-unverified-email")
		}
		if privileged && u.Enabled && len(it.PendingActions) > 0 {
			it.Flags = append(it.Flags, "privileged-pending-actions")
		}
		if isBG {
			it.Flags = append(it.Flags, "break-glass")
			rep.BreakGlass.Accounts = append(rep.BreakGlass.Accounts, u.Username)
			rep.Summary.BreakGlass++
			if u.Enabled {
				enabledBG++
			} else {
				rep.BreakGlass.Warnings = append(rep.BreakGlass.Warnings, "break-glass account "+u.Username+" is disabled and cannot be used in an emergency")
			}
			if !privileged {
				rep.BreakGlass.Warnings = append(rep.BreakGlass.Warnings, "break-glass account "+u.Username+" holds no privileged role or group")
			}
		}
		it.Risk = risk(it, privileged)
		switch it.Risk {
		case "high":
			rep.Summary.HighRisk++
		case "medium":
			rep.Summary.MediumRisk++
		}
		if hasAccess {
			rep.Summary.WithAccess++
		}
		rep.Items = append(rep.Items, it)
	}
	switch {
	case len(rep.BreakGlass.Accounts) == 0:
		rep.BreakGlass.Warnings = append(rep.BreakGlass.Warnings, "no break-glass accounts matched; keep at least two emergency admin accounts excluded from SSO dependencies")
	case enabledBG < 2:
		rep.BreakGlass.Warnings = append(rep.BreakGlass.Warnings, fmt.Sprintf("only %d enabled break-glass account(s); keep at least two", enabledBG))
	}
	sort.Strings(rep.BreakGlass.Warnings)
	sort.Strings(rep.BreakGlass.Accounts)
	order := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(rep.Items, func(i, j int) bool {
		a, b := rep.Items[i], rep.Items[j]
		if order[a.Risk] != order[b.Risk] {
			return order[a.Risk] < order[b.Risk]
		}
		return a.Username < b.Username
	})
	if rep.Items == nil {
		rep.Items = []Item{}
	}
	return rep, nil
}

func risk(it Item, privileged bool) string {
	has := func(f string) bool {
		for _, x := range it.Flags {
			if x == f {
				return true
			}
		}
		return false
	}
	switch {
	case privileged && (!it.Enabled || has("privileged-unverified-email") || has("privileged-pending-actions")):
		return "high"
	case has("disabled-with-access"), privileged:
		return "medium"
	default:
		return "low"
	}
}

func anyPrivileged(names []string) bool {
	for _, n := range names {
		if IsPrivileged(n) {
			return true
		}
	}
	return false
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

var errNotFound = errors.New("not found")

// ErrNotFound is returned for unknown campaigns.
var ErrNotFound = errNotFound
