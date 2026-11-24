// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestDeviceFlowEnabledParseValidate(t *testing.T) {
	src := `apiVersion: ` + APIVersion + `
kind: ` + KindRealm + `
realm: acme
clients:
  - clientId: cli
    public: true
    deviceFlowEnabled: true
`
	s, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Clients[0].DeviceFlowEnabled {
		t.Fatalf("parsed %+v", s.Clients[0])
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Clients[0].Public, s.Clients[0].ServiceAccount = false, true
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "clients[0].deviceFlowEnabled") {
		t.Fatalf("service account + device flow: %v", err)
	}
}

func TestDeviceFlowEnabledDiffApplyRead(t *testing.T) {
	d := okSpec()
	d.Clients[0].DeviceFlowEnabled = true

	plan := Diff(d, nil, Options{})
	var shown bool
	for _, c := range plan.Changes {
		if c.Kind == KindOfClient && c.Name == "web" {
			for _, f := range c.Fields {
				shown = shown || (f.Field == "deviceFlowEnabled" && f.New == "true")
			}
		}
	}
	if !shown {
		t.Fatalf("create diff lacks the field: %+v", plan.Changes)
	}
	// Clients that never use it do not grow a "deviceFlowEnabled: false" line.
	var buf bytes.Buffer
	Diff(okSpec(), nil, Options{}).Render(&buf, false)
	if strings.Contains(buf.String(), "deviceFlowEnabled") {
		t.Fatalf("plan mentions an unused flag:\n%s", buf.String())
	}

	f := newFake()
	applyAll(t, fakeSC{f}, d, Options{})
	live := liveFrom(t, f, "acme")
	if !webDevice(live) {
		t.Fatalf("read back: %+v", live.Clients)
	}
	if plan := Diff(d, live, Options{}); len(plan.Changes) != 0 {
		t.Fatalf("drift: %+v", plan.Changes)
	}
	// Switching it off shows an update and clears it live.
	off := okSpec()
	plan = Diff(off, live, Options{})
	if len(plan.Changes) != 1 || !reflect.DeepEqual(plan.Changes[0].Fields, []FieldChange{{Field: "deviceFlowEnabled", Old: "true"}}) {
		t.Fatalf("off diff: %+v", plan.Changes)
	}
	applyAll(t, fakeSC{f}, off, Options{})
	if webDevice(liveFrom(t, f, "acme")) {
		t.Fatal("flag not cleared")
	}
}

func webDevice(s *Spec) bool {
	for _, c := range s.Clients {
		if c.ClientID == "web" {
			return c.DeviceFlowEnabled
		}
	}
	return false
}
