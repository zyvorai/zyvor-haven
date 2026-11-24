// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type fakeMailer struct {
	mu   sync.Mutex
	sent []mail.Message
	fail error
}

func (f *fakeMailer) Send(_ context.Context, m mail.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeMailer) messages() []mail.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mail.Message(nil), f.sent...)
}

func mailEnv(t *testing.T) (*env, *fakeMailer) {
	fm := &fakeMailer{}
	e := newEnvWith(t, func(cfg *admin.Config, st *memstore.Store, base string) {
		cfg.Actions = &actions.Service{Store: st, Mailer: fm, BaseURL: base}
	})
	return e, fm
}

var mailRoutes = []struct{ route, purpose string }{
	{"send-verify-email", core.ActionVerifyEmail},
	{"send-reset-email", core.ActionResetPassword},
}

// liveTokens counts every outstanding token of the user for the purpose.
func liveTokens(t *testing.T, e *env, id, purpose string) int {
	t.Helper()
	n, err := e.st.CountActionTokens(context.Background(), realm, id, purpose, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSendMailRoutes(t *testing.T) {
	r := "/realms/" + realm
	for _, rt := range mailRoutes {
		t.Run(rt.route, func(t *testing.T) {
			e, fm := mailEnv(t)
			id := e.createID(r+"/users", map[string]any{"username": "dana", "email": "dana@example.com", "enabled": true})
			path := r + "/users/" + id + "/" + rt.route

			body := e.api(204, "POST", path, nil)
			if len(body) != 0 {
				t.Fatalf("body must be empty: %q", body)
			}
			msgs := fm.messages()
			if len(msgs) != 1 || msgs[0].To != "dana@example.com" {
				t.Fatalf("delivery: %+v", msgs)
			}
			// The link travels by email only. Extract it to check that the
			// response and the audit trail never carry it.
			link := msgs[0].Text
			i := strings.Index(link, "token=")
			if i < 0 {
				t.Fatalf("mail has no link: %q", link)
			}
			tok := link[i+len("token="):]
			if tok == "" {
				t.Fatal("empty token in mail")
			}
			if strings.Contains(string(body), tok) || strings.Contains(string(body), "login-actions") {
				t.Fatalf("response leaks token or link: %s", body)
			}
			if n := liveTokens(t, e, id, rt.purpose); n != 1 {
				t.Fatalf("want 1 live token, got %d", n)
			}

			evs, err := e.st.ListEvents(context.Background(), realm, 50)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, ev := range evs {
				if ev.Type != "ADMIN_ACTION" || !strings.Contains(ev.Detail, "dana") {
					continue
				}
				found = true
				if strings.Contains(ev.Detail, tok) || strings.Contains(ev.Detail, "token") ||
					strings.Contains(ev.Detail, "http") || strings.Contains(ev.Detail, "login-actions") {
					t.Fatalf("audit detail leaks: %q", ev.Detail)
				}
			}
			if !found {
				t.Fatalf("no ADMIN_ACTION event: %+v", evs)
			}
		})
	}
}

func TestSendMailErrors(t *testing.T) {
	r := "/realms/" + realm
	for _, rt := range mailRoutes {
		t.Run(rt.route, func(t *testing.T) {
			e, fm := mailEnv(t)
			noMail := e.createID(r+"/users", map[string]any{"username": "nomail", "enabled": true})
			off := e.createID(r+"/users", map[string]any{"username": "off", "email": "off@example.com", "enabled": false})
			ok := e.createID(r+"/users", map[string]any{"username": "ok", "email": "ok@example.com", "enabled": true})
			p := func(id string) string { return r + "/users/" + id + "/" + rt.route }

			e.api(400, "POST", p(noMail), nil)
			e.api(400, "POST", p(off), nil)
			e.api(404, "POST", p("no-such-user"), nil)
			if n := len(fm.messages()); n != 0 {
				t.Fatalf("mail sent on error paths: %d", n)
			}

			// Auth: nothing without a valid admin token, and no mail.
			for name, tok := range map[string]string{"none": "", "garbage": "not.a.jwt"} {
				if code, _, _ := e.call("POST", p(ok), tok, nil); code != 401 {
					t.Errorf("%s: got %d want 401", name, code)
				}
			}
			e.createID(r+"/clients", map[string]any{"clientId": "rogue", "enabled": true, "serviceAccountsEnabled": true})
			secret := e.regen(realm, "rogue")
			if code, _, _ := e.call("POST", p(ok), e.clientToken(realm, "rogue", secret), nil); code != 403 {
				t.Errorf("non-admin client: got %d want 403", code)
			}
			if n := len(fm.messages()); n != 0 {
				t.Fatalf("mail sent without authorization: %d", n)
			}

			// Rate limit: three sends, the fourth is refused.
			for i := 1; i <= actions.MaxPerHour; i++ {
				e.api(204, "POST", p(ok), nil)
			}
			e.api(429, "POST", p(ok), nil)
			if n := len(fm.messages()); n != actions.MaxPerHour {
				t.Fatalf("429 must not send: %d messages", n)
			}
		})
	}
}

func TestSendMailNotConfigured(t *testing.T) {
	r := "/realms/" + realm
	e := newEnv(t) // Actions nil
	id := e.createID(r+"/users", map[string]any{"username": "dana", "email": "dana@example.com", "enabled": true})
	for _, rt := range mailRoutes {
		e.api(409, "POST", r+"/users/"+id+"/"+rt.route, nil)
	}
	// A service without a mailer is just as disabled.
	e2 := newEnvWith(t, func(cfg *admin.Config, st *memstore.Store, base string) {
		cfg.Actions = &actions.Service{Store: st, BaseURL: base}
	})
	id2 := e2.createID(r+"/users", map[string]any{"username": "dana", "email": "dana@example.com", "enabled": true})
	for _, rt := range mailRoutes {
		e2.api(409, "POST", r+"/users/"+id2+"/"+rt.route, nil)
	}
}

func TestSendMailSenderFails(t *testing.T) {
	r := "/realms/" + realm
	for _, rt := range mailRoutes {
		t.Run(rt.route, func(t *testing.T) {
			e, fm := mailEnv(t)
			fm.fail = errors.New("smtp: boom secret-host.internal")
			id := e.createID(r+"/users", map[string]any{"username": "dana", "email": "dana@example.com", "enabled": true})
			body := e.api(502, "POST", r+"/users/"+id+"/"+rt.route, nil)
			if strings.Contains(string(body), "boom") || strings.Contains(string(body), "secret-host") {
				t.Fatalf("502 leaks sender error: %s", body)
			}
			if n := liveTokens(t, e, id, rt.purpose); n != 0 {
				t.Fatalf("undelivered link must not stay live: %d tokens", n)
			}
		})
	}
}
