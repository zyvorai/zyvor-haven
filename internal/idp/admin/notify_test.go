// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type noticeMail struct {
	mu   sync.Mutex
	msgs []mail.Message
}

func (n *noticeMail) Send(_ context.Context, m mail.Message) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgs = append(n.msgs, m)
	return nil
}

func (n *noticeMail) all() []mail.Message {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]mail.Message(nil), n.msgs...)
}

func newMailEnv(t *testing.T, withMail bool) (*env, *noticeMail) {
	t.Helper()
	st := memstore.New()
	h := password.New(password.TestParams)
	sg := keys.New(st, keys.Options{})
	e := &env{t: t, st: st, signer: sg, hasher: h}
	nm := &noticeMail{}
	var handler http.Handler
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(e.srv.Close)
	if _, err := bootstrap.Run(context.Background(), st, h, sg, bootstrap.Options{Realm: realm, AdminClientSecret: adminSecret}); err != nil {
		t.Fatal(err)
	}
	cfg := admin.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL, AdminRealm: realm}
	if withMail {
		cfg.Actions = &actions.Service{Store: st, Mailer: nm, BaseURL: e.srv.URL}
	}
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL}))
	mux.Handle("/admin/v1/", admin.New(cfg))
	handler = mux
	e.token = e.clientToken(realm, "haven-admin", adminSecret)
	return e, nm
}

// waitMail polls until n messages arrived or a deadline passes.
func waitMail(nm *noticeMail, n int) []mail.Message {
	for i := 0; i < 200 && len(nm.all()) < n; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	return nm.all()
}

func TestAdminPasswordResetSendsNotice(t *testing.T) {
	e, nm := newMailEnv(t, true)
	r := "/realms/" + realm
	id := e.createID(r+"/users", map[string]any{"username": "carol", "email": "carol@example.com", "enabled": true})
	nid := e.createID(r+"/users", map[string]any{"username": "noaddr", "enabled": true})

	// Rejected changes send nothing.
	e.api(400, "PUT", r+"/users/"+id+"/password", map[string]any{"type": "password", "value": "short"})
	e.api(400, "PUT", r+"/users/"+id+"/password", map[string]any{"type": "otp", "value": goodPW})
	e.api(404, "PUT", r+"/users/nope/password", map[string]any{"type": "password", "value": goodPW})
	// No address on file: the change works, nothing is sent.
	e.api(204, "PUT", r+"/users/"+nid+"/password", map[string]any{"value": goodPW})

	e.api(204, "PUT", r+"/users/"+id+"/password", map[string]any{"type": "password", "value": goodPW, "temporary": true})
	waitMail(nm, 1)
	time.Sleep(100 * time.Millisecond) // a spurious extra mail would land by now
	ms := nm.all()
	if len(ms) != 1 {
		t.Fatalf("want exactly one notice, got %d: %+v", len(ms), ms)
	}
	m := ms[0]
	if m.To != "carol@example.com" || !strings.Contains(m.Subject, "was changed") || !strings.Contains(m.Text, "an administrator") {
		t.Fatalf("notice: %+v", m)
	}
	for _, s := range []string{m.Text, m.HTML, m.Subject} {
		if strings.Contains(s, goodPW) || strings.Contains(s, "http") || strings.Contains(s, "token") {
			t.Errorf("notice leaks credential or link: %q", s)
		}
	}
}

func TestAdminPasswordResetNoNoticeWithoutMailer(t *testing.T) {
	e, nm := newMailEnv(t, false)
	r := "/realms/" + realm
	id := e.createID(r+"/users", map[string]any{"username": "dave", "email": "dave@example.com", "enabled": true})
	e.api(204, "PUT", r+"/users/"+id+"/password", map[string]any{"value": goodPW})
	time.Sleep(100 * time.Millisecond)
	if n := len(nm.all()); n != 0 {
		t.Fatalf("%d emails with mail disabled", n)
	}
}
