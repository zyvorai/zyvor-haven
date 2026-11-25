// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kubeauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

type fakeAPI struct {
	clients  []idp.Client
	created  []idp.Client
	updated  []idp.Client
	onCreate func(*fakeAPI) error
	listErr  error
}

func (f *fakeAPI) ListClients(context.Context, string) ([]idp.Client, error) {
	return slices.Clone(f.clients), f.listErr
}

func (f *fakeAPI) CreateClient(_ context.Context, _ string, c idp.Client) error {
	if f.onCreate != nil {
		return f.onCreate(f)
	}
	f.created = append(f.created, c)
	c.ID = "id-" + c.ClientID
	f.clients = append(f.clients, c)
	return nil
}

func (f *fakeAPI) UpdateClient(_ context.Context, _, id string, c idp.Client) error {
	if id != c.ID {
		return errors.New("wrong id")
	}
	f.updated = append(f.updated, c)
	for i := range f.clients {
		if f.clients[i].ID == id {
			f.clients[i] = c
		}
	}
	return nil
}

func kubeClient(mut func(*idp.Client)) idp.Client {
	c := idp.Client{ID: "1", ClientID: "kubernetes", Enabled: true, PublicClient: true, DeviceFlowEnabled: true,
		Attributes: map[string]string{pkceAttr: "S256"}}
	if mut != nil {
		mut(&c)
	}
	return c
}

func TestEnsureCreatesOnceAndIsIdempotent(t *testing.T) {
	f := &fakeAPI{clients: []idp.Client{{ID: "9", ClientID: "Kubernetes", Enabled: true}}} // ids are case-sensitive
	spec := ClientSpec{ClientID: "kubernetes"}
	r, err := EnsureClient(context.Background(), f, "r", spec)
	if err != nil || r.Action != ClientCreated {
		t.Fatalf("%+v %v", r, err)
	}
	c := f.created[0]
	if !c.PublicClient || !c.DeviceFlowEnabled || c.ServiceAccountsEnabled || c.StandardFlowEnabled || c.DirectAccessGrantsEnabled ||
		c.ImplicitFlowEnabled || len(c.RedirectURIs) != 0 || c.Secret != "" || c.Attributes[pkceAttr] != "S256" || !c.Enabled {
		t.Fatalf("least-privilege public device client expected: %+v", c)
	}
	for i := 0; i < 2; i++ {
		r, err = EnsureClient(context.Background(), f, "r", spec)
		if err != nil || r.Action != ClientUnchanged || len(f.created) != 1 || len(f.updated) != 0 {
			t.Fatalf("not idempotent: %+v %v", r, err)
		}
	}
}

func TestEnsureWithRedirects(t *testing.T) {
	f := &fakeAPI{}
	r, err := EnsureClient(context.Background(), f, "r", ClientSpec{ClientID: "kubernetes", Redirects: []string{"http://localhost:8000"}})
	if err != nil || r.Action != ClientCreated || len(r.Warnings) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if c := f.created[0]; !c.StandardFlowEnabled || c.Attributes[pkceAttr] != "S256" || c.RedirectURIs[0] != "http://localhost:8000" {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []string{"http://evil.example/cb", "https://*.example.com/cb", "myapp://cb", "https://u:p@h.example/cb",
		"https://h.example/cb#x", "javascript:alert(1)", "", "http://localhost.evil.example/cb", "http://127.0.0.1.evil.example/"} {
		f := &fakeAPI{}
		if _, err := EnsureClient(context.Background(), f, "r", ClientSpec{ClientID: "kubernetes", Redirects: []string{bad}}); err == nil || len(f.created) != 0 {
			t.Errorf("redirect %q accepted", bad)
		}
	}
}

func TestEnsureExistingClient(t *testing.T) {
	spec := ClientSpec{ClientID: "kubernetes", Redirects: []string{"http://localhost:8000"}}
	// Never converted or enabled, even with Update.
	for name, mut := range map[string]func(*idp.Client){
		"confidential":    func(c *idp.Client) { c.PublicClient = false },
		"service account": func(c *idp.Client) { c.ServiceAccountsEnabled = true },
		"bearer only":     func(c *idp.Client) { c.BearerOnly = true },
		"disabled":        func(c *idp.Client) { c.Enabled = false },
	} {
		for _, update := range []bool{false, true} {
			f := &fakeAPI{clients: []idp.Client{kubeClient(mut)}}
			s := spec
			s.Update = update
			if _, err := EnsureClient(context.Background(), f, "r", s); err == nil || len(f.updated)+len(f.created) != 0 {
				t.Errorf("%s (update=%v) was changed or accepted: %v", name, update, err)
			}
		}
	}
	// Differences are reported and only applied with Update, additively.
	old := kubeClient(func(c *idp.Client) {
		c.DeviceFlowEnabled, c.Attributes = false, nil
		c.Name, c.RedirectURIs, c.WebOrigins = "Mine", []string{"https://dash.example.com/cb"}, []string{"https://dash.example.com"}
		c.BackchannelLogoutURL = "https://dash.example.com/bc"
	})
	f := &fakeAPI{clients: []idp.Client{old}}
	r, err := EnsureClient(context.Background(), f, "r", spec)
	if err == nil || !strings.Contains(err.Error(), "--update-client") || len(f.updated) != 0 || len(r.Changes) == 0 {
		t.Fatalf("changed without --update-client: %+v %v", r, err)
	}
	s := spec
	s.Update = true
	r, err = EnsureClient(context.Background(), f, "r", s)
	if err != nil || r.Action != ClientUpdated {
		t.Fatalf("%+v %v", r, err)
	}
	u := f.updated[0]
	if !u.DeviceFlowEnabled || !u.StandardFlowEnabled || u.Attributes[pkceAttr] != "S256" || u.Name != "Mine" ||
		!slices.Equal(u.RedirectURIs, []string{"https://dash.example.com/cb", "http://localhost:8000"}) ||
		len(u.WebOrigins) != 1 || u.BackchannelLogoutURL == "" {
		t.Fatalf("update lost or missed settings: %+v", u)
	}
	// The non-loopback redirect that the cluster now trusts is pointed out.
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "dash.example.com") {
		t.Fatalf("warnings %v", r.Warnings)
	}
}

func TestEnsureCreateRace(t *testing.T) {
	// A conflict on create means: look again and judge what is there.
	for name, c := range map[string]struct {
		winner idp.Client
		ok     bool
	}{
		"good":         {kubeClient(nil), true},
		"confidential": {kubeClient(func(c *idp.Client) { c.PublicClient = false }), false},
	} {
		f := &fakeAPI{onCreate: func(f *fakeAPI) error { f.clients = []idp.Client{c.winner}; return &idp.StatusError{Code: 409} }}
		r, err := EnsureClient(context.Background(), f, "r", ClientSpec{ClientID: "kubernetes"})
		if (err == nil) != c.ok || (c.ok && r.Action != ClientUnchanged) {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
	f := &fakeAPI{onCreate: func(*fakeAPI) error { return &idp.StatusError{Code: 422} }}
	if _, err := EnsureClient(context.Background(), f, "r", ClientSpec{ClientID: "kubernetes"}); err == nil {
		t.Error("a refused create (guard) must fail")
	}
	f = &fakeAPI{listErr: errors.New("boom")}
	if _, err := EnsureClient(context.Background(), f, "r", ClientSpec{ClientID: "kubernetes"}); err == nil || len(f.created) != 0 {
		t.Error("created although the list failed")
	}
}
