// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

func TestBackchannelLogoutURLParseValidate(t *testing.T) {
	src := `apiVersion: ` + APIVersion + `
kind: ` + KindRealm + `
realm: acme
clients:
  - clientId: web
    public: true
    redirectUris: ["https://a.example/cb"]
    backchannelLogoutUrl: https://a.example/bc
`
	s, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if s.Clients[0].BackchannelLogoutURL != "https://a.example/bc" {
		t.Fatalf("parsed %+v", s.Clients[0])
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"http://a.example/bc", "https://u:p@a.example/bc", "https://a.example/bc#x"} {
		s.Clients[0].BackchannelLogoutURL = u
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), "clients[0].backchannelLogoutUrl") {
			t.Errorf("%q: %v", u, err)
		}
	}
	s.Clients[0].BackchannelLogoutURL = "http://localhost:3000/bc"
	if err := s.Validate(); err != nil {
		t.Errorf("loopback http: %v", err)
	}
}

func TestBackchannelLogoutURLDiffAndApply(t *testing.T) {
	d := okSpec()
	d.Clients[0].BackchannelLogoutURL = "https://a.example/bc"

	// Create shows the field.
	plan := Diff(d, nil, Options{})
	var found bool
	for _, c := range plan.Changes {
		if c.Kind == KindOfClient && c.Name == "web" {
			for _, f := range c.Fields {
				found = found || (f.Field == "backchannelLogoutUrl" && f.New == "https://a.example/bc")
			}
		}
	}
	if !found {
		t.Fatalf("create diff lacks the field: %+v", plan.Changes)
	}

	// Apply, read back, no drift.
	f := newFake()
	applyAll(t, fakeSC{f}, d, Options{})
	live := liveFrom(t, f, "acme")
	if got := webURL(live); got != "https://a.example/bc" {
		t.Fatalf("read back: %+v", live.Clients)
	}
	if plan := Diff(d, live, Options{}); len(plan.Changes) != 0 {
		t.Fatalf("drift: %+v", plan.Changes)
	}

	// Change shows an update.
	d2 := okSpec()
	d2.Clients[0].BackchannelLogoutURL = "https://a.example/bc2"
	plan = Diff(d2, live, Options{})
	if len(plan.Changes) != 1 || plan.Changes[0].Action != ActionUpdate ||
		!reflect.DeepEqual(plan.Changes[0].Fields, []FieldChange{{Field: "backchannelLogoutUrl", Old: "https://a.example/bc", New: "https://a.example/bc2"}}) {
		t.Fatalf("update diff: %+v", plan.Changes)
	}

	// Removing it from the file clears it.
	d3 := okSpec()
	plan = Diff(d3, live, Options{})
	if len(plan.Changes) != 1 || plan.Changes[0].Fields[0].Field != "backchannelLogoutUrl" || plan.Changes[0].Fields[0].New != "" {
		t.Fatalf("clear diff: %+v", plan.Changes)
	}
	applyAll(t, fakeSC{f}, d3, Options{})
	if got := webURL(liveFrom(t, f, "acme")); got != "" {
		t.Fatalf("not cleared: %q", got)
	}
	for _, c := range f.clients["acme"] {
		if _, has := c.Attributes["backchannel.logout.url"]; has {
			t.Fatalf("attribute left behind: %+v", c.Attributes)
		}
	}
}

func TestBackchannelLogoutURLFromExportAttribute(t *testing.T) {
	f := newFake()
	applyAll(t, fakeSC{f}, okSpec(), Options{})
	for i, c := range f.clients["acme"] {
		if c.ClientID == "web" {
			f.clients["acme"][i].Attributes = map[string]string{"backchannel.logout.url": "https://kc.example/bc"}
		}
	}
	if got := webURL(liveFrom(t, f, "acme")); got != "https://kc.example/bc" {
		t.Fatalf("attribute not read: %q", got)
	}
}

func webURL(s *Spec) string {
	for _, c := range s.Clients {
		if c.ClientID == "web" {
			return c.BackchannelLogoutURL
		}
	}
	return "<missing>"
}

func liveFrom(t *testing.T, p idp.Provider, realm string) *Spec {
	t.Helper()
	live, err := Read(context.Background(), p, realm)
	if err != nil {
		t.Fatal(err)
	}
	return live
}
