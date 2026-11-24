// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type captureMailer struct {
	mu   sync.Mutex
	sent []mail.Message
}

func (m *captureMailer) Send(_ context.Context, msg mail.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

func (m *captureMailer) messages() []mail.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mail.Message(nil), m.sent...)
}

// realClient wires native.Client to the real admin and OIDC handlers over a
// memstore. withMail controls whether the admin API has a mailer.
func realClient(t *testing.T, withMail bool) (*Client, *captureMailer) {
	t.Helper()
	const rlm, secret = "platform", "admin-secret-for-tests-0123456789abcdef"
	st := memstore.New()
	h := password.New(password.TestParams)
	sg := keys.New(st, keys.Options{})
	cm := &captureMailer{}
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	if _, err := bootstrap.Run(context.Background(), st, h, sg, bootstrap.Options{Realm: rlm, AdminClientSecret: secret}); err != nil {
		t.Fatal(err)
	}
	acfg := admin.Config{Store: st, Signer: sg, Hasher: h, BaseURL: srv.URL, AdminRealm: rlm}
	if withMail {
		acfg.Actions = &actions.Service{Store: st, Mailer: cm, BaseURL: srv.URL}
	}
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: st, Signer: sg, Hasher: h, BaseURL: srv.URL}))
	mux.Handle("/admin/v1/", admin.New(acfg))
	handler = mux
	return New(Config{BaseURL: srv.URL, Realm: rlm, ClientID: "haven-admin", ClientSecret: secret, HTTP: srv.Client()}), cm
}

func userID(t *testing.T, c *Client, name string) string {
	t.Helper()
	us, err := c.ListUsers(ctx(), "platform", name)
	if err != nil || len(us) == 0 {
		t.Fatalf("find %s: %v", name, err)
	}
	return us[0].ID
}

func TestUserMailerAgainstRealAdmin(t *testing.T) {
	c, cm := realClient(t, true)
	var m idp.UserMailer = c // optional interface, not part of Provider
	if err := c.CreateUser(ctx(), "platform", idp.User{Username: "dana", Email: "dana@example.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateUser(ctx(), "platform", idp.User{Username: "nomail", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	id := userID(t, c, "dana")

	if err := m.SendVerifyEmail(ctx(), "platform", id); err != nil {
		t.Fatal(err)
	}
	if err := m.SendResetEmail(ctx(), "platform", id); err != nil {
		t.Fatal(err)
	}
	if got := cm.messages(); len(got) != 2 || got[0].To != "dana@example.com" || got[1].To != "dana@example.com" {
		t.Fatalf("mail: %+v", got)
	}

	// No address on file: a plain 400 StatusError.
	err := m.SendResetEmail(ctx(), "platform", userID(t, c, "nomail"))
	if se := idp.AsStatus(err); se == nil || se.Code != 400 {
		t.Fatalf("no email: %v", err)
	}
	// Unknown user.
	if err := m.SendVerifyEmail(ctx(), "platform", "nope"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}

	// One reset mail is out already; two more are allowed, the next is limited.
	for i := 0; i < 2; i++ {
		if err := m.SendResetEmail(ctx(), "platform", id); err != nil {
			t.Fatal(err)
		}
	}
	err = m.SendResetEmail(ctx(), "platform", id)
	if !errors.Is(err, idp.ErrRateLimited) || errors.Is(err, idp.ErrConflict) {
		t.Fatalf("rate limit: %v", err)
	}
	if se := idp.AsStatus(err); se == nil || se.Code != 429 {
		t.Fatalf("status not reachable: %v", err)
	}
	if strings.Contains(err.Error(), "{") {
		t.Fatalf("error should be the clear sentinel text: %q", err)
	}
}

func TestUserMailerNotConfigured(t *testing.T) {
	c, _ := realClient(t, false)
	if err := c.CreateUser(ctx(), "platform", idp.User{Username: "dana", Email: "dana@example.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	id := userID(t, c, "dana")
	for name, f := range map[string]func(context.Context, string, string) error{
		"verify": c.SendVerifyEmail, "reset": c.SendResetEmail,
	} {
		err := f(ctx(), "platform", id)
		if !errors.Is(err, idp.ErrEmailNotConfigured) {
			t.Errorf("%s: %v", name, err)
		}
		if errors.Is(err, idp.ErrConflict) {
			t.Errorf("%s: must not read as a conflict", name)
		}
	}
}
