// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package accessreview

import (
	"github.com/zyvorai/haven/internal/idp"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/identityops"
)

func TestIsPrivileged(t *testing.T) {
	cases := map[string]bool{
		"admin": true, "realm-admin": true, "Platform_Admin": true, "/Admins": true, "/eng/admin": true,
		"manage-users": true, "/realm-management/manage-clients": true, "impersonation": true,
		"administrator": true, "root": true,
		"badminton": false, "administrate": false, "viewer": false, "offline_access": false, "": false,
		"uma_authorization": false, "default-roles-acme": false,
	}
	for in, want := range cases {
		if got := IsPrivileged(in); got != want {
			t.Errorf("IsPrivileged(%q)=%v want %v", in, got, want)
		}
	}
}

func snapshot() identityops.RealmSnapshot {
	return identityops.RealmSnapshot{
		ID: "snap1", Realm: "acme",
		Users: []idp.User{
			{Username: "alice", Enabled: true, EmailVerified: true},
			{Username: "bob", Enabled: true, EmailVerified: false},
			{Username: "carol", Enabled: false, EmailVerified: true},
			{Username: "dave", Enabled: true, EmailVerified: true},
			{Username: "erin", Enabled: true, EmailVerified: true, RequiredActions: []string{"UPDATE_PASSWORD", "UPDATE_PASSWORD"}},
			{Username: "breakglass1", Enabled: true, EmailVerified: true},
			{Username: "service-account-ci", Enabled: true},
			{Username: "idle", Enabled: true, EmailVerified: true},
		},
		UserAccess: []identityops.UserAccess{
			{Username: "alice", RealmRoles: []string{"realm-admin"}},
			{Username: "bob", Groups: []string{"/ops/admin"}},
			{Username: "carol", RealmRoles: []string{"viewer"}},
			{Username: "dave", RealmRoles: []string{"viewer", "viewer"}},
			{Username: "erin", RealmRoles: []string{"admin"}},
			{Username: "breakglass1", RealmRoles: []string{"admin"}},
		},
	}
}

func TestAnalyze(t *testing.T) {
	rep, err := Analyze(snapshot(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Item{}
	for _, it := range rep.Items {
		byName[it.Username] = it
	}
	want := map[string]struct {
		risk  string
		flags []string
	}{
		"alice":       {"medium", []string{"privileged"}},
		"bob":         {"high", []string{"privileged", "privileged-unverified-email"}},
		"carol":       {"medium", []string{"disabled-with-access"}},
		"dave":        {"low", nil},
		"erin":        {"high", []string{"privileged", "privileged-pending-actions"}},
		"breakglass1": {"medium", []string{"privileged", "break-glass"}},
	}
	for name, w := range want {
		it, ok := byName[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if it.Risk != w.risk || strings.Join(it.Flags, ",") != strings.Join(w.flags, ",") {
			t.Errorf("%s: risk=%s flags=%v want %s %v", name, it.Risk, it.Flags, w.risk, w.flags)
		}
	}
	if _, ok := byName["idle"]; ok {
		t.Error("user without access must not be listed")
	}
	if _, ok := byName["service-account-ci"]; ok {
		t.Error("service accounts are out of scope")
	}
	if len(byName["dave"].RealmRoles) != 1 || len(byName["erin"].PendingActions) != 1 {
		t.Error("duplicates not collapsed")
	}
	if rep.Items[0].Risk != "high" || rep.Items[len(rep.Items)-1].Risk != "low" {
		t.Errorf("not sorted by risk: %v", rep.Items)
	}
	if rep.Summary.Users != 7 || rep.Summary.Privileged != 4 || rep.Summary.StaleAccess != 1 || rep.Summary.NoAccessOnly != 1 {
		t.Errorf("summary %+v", rep.Summary)
	}
	if len(rep.BreakGlass.Accounts) != 1 || len(rep.BreakGlass.Warnings) != 1 || !strings.Contains(rep.BreakGlass.Warnings[0], "only 1") {
		t.Errorf("break glass %+v", rep.BreakGlass)
	}
}

func TestAnalyzeBreakGlassWarnings(t *testing.T) {
	s := identityops.RealmSnapshot{Realm: "r", Users: []idp.User{{Username: "emergency-a", Enabled: false}}}
	rep, err := Analyze(s, Options{})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.BreakGlass.Warnings, "|")
	for _, w := range []string{"disabled", "no privileged role", "only 0"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing warning %q in %q", w, joined)
		}
	}
	rep, _ = Analyze(identityops.RealmSnapshot{Realm: "r"}, Options{})
	if len(rep.BreakGlass.Warnings) != 1 || rep.Items == nil {
		t.Errorf("empty realm: %+v", rep)
	}
}

func TestAnalyzeHostileOptions(t *testing.T) {
	for name, opts := range map[string]Options{
		"bad regexp":  {BreakGlassPattern: "("},
		"long regexp": {BreakGlassPattern: strings.Repeat("a", MaxPatternLen+1)},
	} {
		if _, err := Analyze(identityops.RealmSnapshot{Realm: "r"}, opts); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	big := identityops.RealmSnapshot{Realm: "r", Users: make([]idp.User, MaxUsers+1)}
	if _, err := Analyze(big, Options{}); err == nil {
		t.Error("oversize realm accepted")
	}
	// Catastrophic-backtracking style pattern is safe under RE2.
	if _, err := Analyze(snapshot(), Options{BreakGlassPattern: "^(a+)+$"}); err != nil {
		t.Errorf("RE2 pattern rejected: %v", err)
	}
}

func newStore(t *testing.T) *Store { t.Helper(); return NewStore(t.TempDir()) }

func TestCampaignLifecycle(t *testing.T) {
	st := newStore(t)
	rep, _ := Analyze(snapshot(), Options{})
	c, err := st.Create(rep, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusOpen || len(c.Items) != 6 {
		t.Fatalf("campaign %+v", c)
	}
	info, err := os.Stat(filepath.Join(st.dir, c.ID+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v err %v", info, err)
	}
	if _, err := st.Close(c.ID); err == nil {
		t.Fatal("closed with pending items")
	}
	for _, it := range c.Items {
		act := ActionCertify
		if it.Username == "carol" {
			act = ActionRevoke
		}
		if _, err := st.Decide(c.ID, it.Username, act, "rev1", "ok because"); err != nil {
			t.Fatalf("%s: %v", it.Username, err)
		}
	}
	// change of mind keeps history
	c, err = st.Decide(c.ID, "alice", ActionDefer, "rev2", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.History) != 7 {
		t.Fatalf("history %d", len(c.History))
	}
	if _, err := st.Close(c.ID); err == nil {
		t.Fatal("closed with deferred item")
	}
	if _, err = st.Decide(c.ID, "alice", ActionCertify, "rev2", ""); err != nil {
		t.Fatal(err)
	}
	c, err = st.Close(c.ID)
	if err != nil || c.Status != StatusClosed || c.ClosedAt == nil {
		t.Fatalf("close: %+v %v", c, err)
	}
	if w := c.RevokeWorkItems(); len(w) != 1 || w[0] != "carol" {
		t.Fatalf("work items %v", w)
	}
	if _, err := st.Decide(c.ID, "alice", ActionCertify, "rev", ""); err == nil {
		t.Fatal("decision accepted on closed campaign")
	}
	list, _ := st.List("acme")
	other, _ := st.List("nope")
	if len(list) != 1 || len(other) != 0 {
		t.Fatalf("list %d %d", len(list), len(other))
	}
}

func TestDecideRejectsHostileInput(t *testing.T) {
	st := newStore(t)
	rep, _ := Analyze(snapshot(), Options{})
	c, _ := st.Create(rep, "admin")
	cases := []struct{ name, id, user, action, reviewer, note string }{
		{"bad action", c.ID, "alice", "delete", "r", ""},
		{"empty reviewer", c.ID, "alice", ActionCertify, "", ""},
		{"reviewer with newline", c.ID, "alice", ActionCertify, "a\nb", ""},
		{"long note", c.ID, "alice", ActionCertify, "r", strings.Repeat("n", MaxNoteLen+1)},
		{"revoke without note", c.ID, "alice", ActionRevoke, "r", "  "},
		{"unknown user", c.ID, "mallory", ActionCertify, "r", ""},
		{"break-glass revoke", c.ID, "breakglass1", ActionRevoke, "r", "why"},
		{"traversal id", "../../etc/passwd", "alice", ActionCertify, "r", ""},
		{"unknown id", "ar-0000000000000000", "alice", ActionCertify, "r", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := st.Decide(tc.id, tc.user, tc.action, tc.reviewer, tc.note); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := st.Get("../x"); err != ErrNotFound {
		t.Fatalf("traversal get: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	st := newStore(t)
	if _, err := st.Create(Report{Realm: "r", Items: []Item{}}, "admin"); err == nil {
		t.Error("empty campaign accepted")
	}
	rep, _ := Analyze(snapshot(), Options{})
	if _, err := st.Create(rep, "bad user!"); err == nil {
		t.Error("bad creator accepted")
	}
	if _, err := st.Create(Report{}, "admin"); err == nil {
		t.Error("missing realm accepted")
	}
}
