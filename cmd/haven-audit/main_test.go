// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/posture"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEvaluatePolicyAgainstSingleAndMultiExports(t *testing.T) {
	pol := write(t, "p.json", `{"version":1,"rules":[{"id":"T","severity":"high","title":"tls","path":"sslRequired","op":"eq","value":"all"}]}`)
	cases := []struct {
		name, export string
		want         int
		wantErr      bool
	}{
		{"single violating", `{"realm":"a","sslRequired":"none"}`, 1, false},
		{"single ok", `{"realm":"a","sslRequired":"all"}`, 0, false},
		{"array", `[{"realm":"a","sslRequired":"none"},{"realm":"b","sslRequired":"external"},{"realm":"c","sslRequired":"all"}]`, 2, false},
		{"garbage", `not json`, 0, true},
		{"scalar", `42`, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evaluatePolicy(pol, []byte(tc.export))
			if (err != nil) != tc.wantErr || len(got) != tc.want {
				t.Fatalf("got %d findings, err=%v", len(got), err)
			}
		})
	}
}

func TestEvaluatePolicyRejectsBadPolicyFile(t *testing.T) {
	if _, err := evaluatePolicy(filepath.Join(t.TempDir(), "missing.json"), []byte(`{}`)); err == nil {
		t.Error("missing policy accepted")
	}
	bad := write(t, "bad.json", `{"version":1,"rules":[{"id":"X","severity":"high","title":"t","path":"clients[].secret","op":"present"}]}`)
	if _, err := evaluatePolicy(bad, []byte(`{}`)); err == nil {
		t.Error("credential path accepted")
	}
}

func TestLimitedRejectsOversizeInput(t *testing.T) {
	if _, err := limited(strings.NewReader(strings.Repeat("x", 1024))); err != nil {
		t.Fatal(err)
	}
	if _, err := limited(&infinite{}); err == nil {
		t.Fatal("unbounded reader accepted")
	}
}

type infinite struct{}

func (infinite) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

func TestShouldFailUsesGivenCounts(t *testing.T) {
	if shouldFail(posture.Counts{Medium: 2}, "high") {
		t.Error("medium must not trip high")
	}
	if !shouldFail(posture.Counts{High: 1}, "high") {
		t.Error("high must trip high")
	}
	if shouldFail(posture.Counts{Critical: 3}, "none") {
		t.Error("none never fails")
	}
}
