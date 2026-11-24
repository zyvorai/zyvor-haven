// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package identityops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

func TestPlanUndoProtectsAndOrders(t *testing.T) {
	snap := sampleSnapshot()
	snap.ID = "s1"
	d := SnapshotDiff{
		LiveFingerprint: "fp",
		Clients:         ChangeSet{Added: []string{"haven-admin", "rogue"}, Removed: []string{"grafana"}},
		Users:           ChangeSet{Added: []string{"carol", "service-account-rogue"}, Removed: []string{"alice"}},
		Roles:           ChangeSet{Added: []string{"temp"}, Removed: []string{"viewer"}},
		Access:          ChangeSet{Added: []string{"carol role:admin"}, Removed: []string{"alice role:admin"}},
	}
	plan, err := PlanUndo(snap, d, AllChanges(d), []string{"haven-admin"})
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	var order []string
	for _, s := range plan.Steps {
		status[s.Kind+":"+s.Name] = s.Status
		if s.Status == StatusPlanned {
			order = append(order, s.Action+" "+s.Kind+" "+s.Name)
		}
	}
	for k, want := range map[string]string{
		"client:haven-admin":         StatusSkipped,
		"user:service-account-rogue": StatusSkipped,
		"role:temp":                  StatusUnsupported,
		"access:carol role:admin":    StatusUnsupported,
		"client:rogue":               StatusPlanned,
		"user:carol":                 StatusPlanned,
		"role:viewer":                StatusPlanned,
		"access:alice role:admin":    StatusPlanned,
		"user:alice":                 StatusPlanned,
	} {
		if status[k] != want {
			t.Errorf("%s: %q, want %q", k, status[k], want)
		}
	}
	// Dependencies first, deletions last.
	want := []string{"recreate role viewer", "recreate client grafana", "recreate user alice", "grant access alice role:admin", "delete client rogue", "delete user carol"}
	if strings.Join(order, "|") != strings.Join(want, "|") {
		t.Errorf("order:\n got %v\nwant %v", order, want)
	}
}

func TestPlanUndoRejectsBadSelections(t *testing.T) {
	d := SnapshotDiff{Users: ChangeSet{Added: []string{"carol"}}}
	snap := sampleSnapshot()
	cases := map[string][]ChangeRef{
		"none":            nil,
		"not in diff":     {{KindUser, "alice", ChangeAdded}},
		"wrong direction": {{KindUser, "carol", ChangeRemoved}},
		"bad kind":        {{"realm", "x", ChangeAdded}},
		"bad change":      {{KindUser, "carol", "deleted"}},
		"long name":       {{KindUser, strings.Repeat("a", 600), ChangeAdded}},
	}
	for name, sel := range cases {
		if _, err := PlanUndo(snap, d, sel, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	many := make([]ChangeRef, maxUndoChanges+1)
	if _, err := PlanUndo(snap, d, many, nil); err == nil {
		t.Error("oversized selection accepted")
	}
	// Duplicates collapse.
	p, err := PlanUndo(snap, d, []ChangeRef{{KindUser, "carol", ChangeAdded}, {KindUser, "carol", ChangeAdded}}, nil)
	if err != nil || len(p.Steps) != 1 {
		t.Errorf("dedupe: %v %v", err, p.Steps)
	}
}

type failingProvider struct {
	idp.Provider
	calls []string
}

func (f *failingProvider) CreateRole(_ context.Context, _ string, r idp.Role) error {
	f.calls = append(f.calls, "role "+r.Name)
	return &idp.StatusError{Code: 500, Body: []byte(`{"secret":"hunter2-from-backend"}`)}
}
func (f *failingProvider) CreateGroup(_ context.Context, _ string, g idp.Group) error {
	f.calls = append(f.calls, "group "+g.Name)
	return nil
}
func (f *failingProvider) CreateClient(_ context.Context, _ string, c idp.Client) error {
	f.calls = append(f.calls, "client "+c.ClientID)
	return nil
}

func TestApplyUndoStopsAtFirstFailureAndDoesNotLeakBackendBody(t *testing.T) {
	snap := sampleSnapshot()
	d := SnapshotDiff{Roles: ChangeSet{Removed: []string{"viewer"}}, Groups: ChangeSet{Removed: []string{"/engineering"}}, Clients: ChangeSet{Removed: []string{"grafana"}}}
	plan, err := PlanUndo(snap, d, AllChanges(d), nil)
	if err != nil {
		t.Fatal(err)
	}
	fp := &failingProvider{}
	out := ApplyUndo(context.Background(), fp, snap, plan)
	if len(fp.calls) != 1 || fp.calls[0] != "role viewer" {
		t.Fatalf("steps after the failure ran: %v", fp.calls)
	}
	got := map[string]string{}
	for _, s := range out.Steps {
		got[s.Kind] = s.Status
		if strings.Contains(s.Note, "hunter2") {
			t.Errorf("backend body leaked into the result: %q", s.Note)
		}
	}
	if got[KindRole] != StatusFailed || got[KindGroup] != StatusNotRun || got[KindClient] != StatusNotRun {
		t.Errorf("statuses: %v", got)
	}
	if !strings.Contains(out.Steps[0].Note, "500") {
		t.Errorf("failure note should name the status: %q", out.Steps[0].Note)
	}
}

func TestApplyUndoSkipsNonPlannedSteps(t *testing.T) {
	snap := sampleSnapshot()
	d := SnapshotDiff{Roles: ChangeSet{Added: []string{"temp"}}}
	plan, _ := PlanUndo(snap, d, AllChanges(d), nil)
	fp := &failingProvider{}
	out := ApplyUndo(context.Background(), fp, snap, plan)
	if len(fp.calls) != 0 || out.Steps[0].Status != StatusUnsupported {
		t.Errorf("unsupported step executed: %v %v", fp.calls, out.Steps)
	}
}

func TestProviderSecretsAreNotReplayed(t *testing.T) {
	got := withoutSecrets(map[string]string{"clientId": "x", "clientSecret": "**********", "ClientSecretX": "y"})
	if len(got) != 1 || got["clientId"] != "x" {
		t.Errorf("%v", got)
	}
}

func TestUndoJournal(t *testing.T) {
	s := NewStore(t.TempDir())
	rec, err := NewUndoRecord("op", UndoPlan{SnapshotID: "s1", Realm: "r", LiveFingerprint: "fp",
		Steps: []UndoStep{{Kind: KindUser, Name: "carol", Status: StatusPlanned}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveUndo(rec); err != nil {
		t.Fatal(err)
	}
	rec.Outcome = OutcomeCompleted
	if err := s.SaveUndo(rec); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListUndos("r")
	if err != nil || len(list) != 1 || list[0].Outcome != OutcomeCompleted {
		t.Fatalf("%v %+v", err, list)
	}
	if other, _ := s.ListUndos("other"); len(other) != 0 {
		t.Error("realm filter broken")
	}
	fi, err := os.Stat(filepath.Join(s.root, "time-machine-undo", rec.ID+".json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	if err := s.SaveUndo(UndoRecord{ID: "../escape"}); err == nil {
		t.Error("path traversal in id accepted")
	}
	_ = errors.New
}
