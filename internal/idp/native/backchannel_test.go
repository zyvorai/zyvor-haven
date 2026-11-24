// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import (
	"testing"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/configcode"
)

func TestBackchannelLogoutURLAgainstRealAdmin(t *testing.T) {
	c, _ := realClient(t, false)
	if err := c.CreateRealm(ctx(), idp.Realm{Realm: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateClient(ctx(), "r", idp.Client{
		ClientID: "app", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
		RedirectURIs:         []string{"https://app.example.com/cb"},
		BackchannelLogoutURL: "https://app.example.com/bc",
	}); err != nil {
		t.Fatal(err)
	}
	cls, err := c.ListClients(ctx(), "r")
	if err != nil || len(cls) != 1 || cls[0].BackchannelLogoutURL != "https://app.example.com/bc" {
		t.Fatalf("list: %+v %v", cls, err)
	}
	got, err := c.GetClient(ctx(), "r", cls[0].ID)
	if err != nil || got.BackchannelLogoutURL != "https://app.example.com/bc" {
		t.Fatalf("get: %+v %v", got, err)
	}
	got.BackchannelLogoutURL = "https://app.example.com/bc2"
	if err := c.UpdateClient(ctx(), "r", got.ID, *got); err != nil {
		t.Fatal(err)
	}
	if g, _ := c.GetClient(ctx(), "r", got.ID); g.BackchannelLogoutURL != "https://app.example.com/bc2" {
		t.Fatalf("update lost the url: %+v", g)
	}

	// Validation: a remote http URL is refused with 400.
	bad := *got
	bad.BackchannelLogoutURL = "http://app.example.com/bc"
	if err := c.UpdateClient(ctx(), "r", got.ID, bad); idp.AsStatus(err) == nil || idp.AsStatus(err).Code != 400 {
		t.Fatalf("want 400, got %v", err)
	}
	if err := c.CreateClient(ctx(), "r", idp.Client{ClientID: "x", Enabled: true, BackchannelLogoutURL: "https://u:p@h.example/x"}); idp.AsStatus(err) == nil || idp.AsStatus(err).Code != 400 {
		t.Fatalf("want 400 for userinfo, got %v", err)
	}

	// An omitted key on PUT is a full replace: it clears the setting.
	got.BackchannelLogoutURL = ""
	if err := c.UpdateClient(ctx(), "r", got.ID, *got); err != nil {
		t.Fatal(err)
	}
	if g, _ := c.GetClient(ctx(), "r", got.ID); g.BackchannelLogoutURL != "" {
		t.Fatalf("not cleared: %+v", g)
	}
}

// Config as code set and clear the URL through the real admin handler.
func TestConfigcodeBackchannelLogoutURLAgainstRealAdmin(t *testing.T) {
	c, _ := realClient(t, false)
	spec := func(u string) *configcode.Spec {
		return &configcode.Spec{
			APIVersion: configcode.APIVersion, Kind: configcode.KindRealm, Realm: "acme",
			Clients: []configcode.Client{{ClientID: "web", Public: true,
				RedirectURIs: []string{"https://web.example.com/cb"}, BackchannelLogoutURL: u}},
		}
	}
	apply := func(s *configcode.Spec) {
		t.Helper()
		live, err := configcode.Read(ctx(), c, s.Realm)
		if err != nil {
			live = nil
		}
		if _, err := configcode.Apply(ctx(), c, configcode.Diff(s, live, configcode.Options{}), s); err != nil {
			t.Fatal(err)
		}
	}
	read := func() string {
		live, err := configcode.Read(ctx(), c, "acme")
		if err != nil {
			t.Fatal(err)
		}
		return live.Clients[0].BackchannelLogoutURL
	}
	apply(spec("https://web.example.com/bc"))
	if got := read(); got != "https://web.example.com/bc" {
		t.Fatalf("create: %q", got)
	}
	apply(spec("https://web.example.com/bc2"))
	if got := read(); got != "https://web.example.com/bc2" {
		t.Fatalf("update: %q", got)
	}
	apply(spec(""))
	if got := read(); got != "" {
		t.Fatalf("clear: %q", got)
	}
}
