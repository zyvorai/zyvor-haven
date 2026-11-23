// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kcimport

import (
	"sort"
)

// maxListedPerCode bounds how many warnings of one code are listed
// individually; every warning is still counted in WarningCounts.
const maxListedPerCode = 25

// Warning is one thing that was skipped, altered or not migrated. Code is a
// stable machine identifier; Message is for humans. Neither ever contains
// secrets, password hashes or other credential material.
type Warning struct {
	Code    string `json:"code"`
	Where   string `json:"where,omitempty"`
	Message string `json:"message"`
}

// Counts summarizes what was mapped.
type Counts struct {
	Roles                int `json:"roles"`
	Groups               int `json:"groups"`
	Clients              int `json:"clients"`
	Users                int `json:"users"`
	UsersWithPassword    int `json:"usersWithPassword"`
	UsersWithoutPassword int `json:"usersWithoutPassword"`
}

// Report says what was mapped and everything that was not.
type Report struct {
	SourceRealm string `json:"sourceRealm,omitempty"`
	TargetRealm string `json:"targetRealm"`
	Mapped      Counts `json:"mapped"`
	// NewSecretClients lists confidential clients that get a NEW secret when
	// the realm file is applied; secrets in the export are never read.
	NewSecretClients []string `json:"newSecretClients,omitempty"`
	// NotMigrated counts whole feature areas that have no haven-idp equivalent.
	NotMigrated map[string]int `json:"notMigrated,omitempty"`
	// WarningCounts is the number of warnings per code.
	WarningCounts map[string]int `json:"warningCounts,omitempty"`
	// Warnings lists up to 25 warnings per code, sorted by code then location.
	Warnings          []Warning `json:"warnings,omitempty"`
	WarningsTruncated bool      `json:"warningsTruncated,omitempty"`
}

type collector struct {
	counts map[string]int
	list   []Warning
	trunc  bool
}

func newCollector() *collector { return &collector{counts: map[string]int{}} }

func (c *collector) add(code, where, msg string) {
	c.counts[code]++
	if c.counts[code] > maxListedPerCode {
		c.trunc = true
		return
	}
	c.list = append(c.list, Warning{Code: code, Where: where, Message: msg})
}

func (c *collector) finish(r *Report) {
	sort.SliceStable(c.list, func(i, j int) bool {
		a, b := c.list[i], c.list[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Where < b.Where
	})
	r.Warnings = c.list
	if len(c.counts) > 0 {
		r.WarningCounts = c.counts
	}
	r.WarningsTruncated = c.trunc
}
