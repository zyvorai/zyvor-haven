// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type ecEnv struct {
	*env
	svc    *actions.Service // nil when email is not configured
	outbox *mail.Outbox
}

// newECEnv builds an admin API; withMail=false leaves email unconfigured.
func newECEnv(t *testing.T, withMail bool) *ecEnv {
	t.Helper()
	st := memstore.New()
	h := password.New(password.TestParams)
	sg := keys.New(st, keys.Options{})
	e := &env{t: t, st: st, signer: sg, hasher: h}
	var handler http.Handler
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(e.srv.Close)
	if _, err := bootstrap.Run(context.Background(), st, h, sg, bootstrap.Options{Realm: realm, AdminClientSecret: adminSecret}); err != nil {
		t.Fatal(err)
	}
	ec := &ecEnv{env: e, outbox: mail.NewOutbox(50)}
	cfg := admin.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL, AdminRealm: realm}
	if withMail {
		ec.svc = &actions.Service{Store: st, Mailer: ec.outbox, BaseURL: e.srv.URL}
		cfg.Actions = ec.svc
	}
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL}))
	mux.Handle("/admin/v1/", admin.New(cfg))
	handler = mux
	e.token = e.clientToken(realm, "haven-admin", adminSecret)
	return ec
}

func (ec *ecEnv) user(email string, verified bool) string {
	return ec.createID("/realms/"+realm+"/users", map[string]any{
		"username": "u1", "email": email, "enabled": true, "emailVerified": verified})
}

func (ec *ecEnv) stored(id string) core.User {
	ec.t.Helper()
	u, err := ec.st.GetUser(context.Background(), realm, id)
	if err != nil {
		ec.t.Fatal(err)
	}
	return u
}

func (ec *ecEnv) put(id string, body map[string]any) {
	ec.t.Helper()
	body["username"], body["enabled"] = "u1", true
	ec.api(204, "PUT", "/realms/"+realm+"/users/"+id, body)
}

// waitMail waits for the async mail to addr.
func (ec *ecEnv) waitMail(addr string) (mail.Message, bool) {
	for i := 0; i < 300; i++ {
		if m, ok := ec.outbox.Last(addr); ok {
			return m, true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return mail.Message{}, false
}

// settle gives a wrongly sent async mail time to arrive.
func settle() { time.Sleep(200 * time.Millisecond) }

var tokenRE = regexp.MustCompile(`token=([^\s"<&]+)`)

func tokenOf(t *testing.T, m mail.Message) string {
	t.Helper()
	g := tokenRE.FindStringSubmatch(m.Text)
	if g == nil {
		t.Fatalf("no token link in %q", m.Text)
	}
	tok, err := url.QueryUnescape(g[1])
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestEmailChangeUnverifiesAndMailsNewAddressOnly(t *testing.T) {
	ec := newECEnv(t, true)
	id := ec.user("old@example.com", true)
	ec.put(id, map[string]any{"email": "new@example.com"})
	if u := ec.stored(id); u.Email != "new@example.com" || u.EmailVerified {
		t.Fatalf("want new unverified address, got %q verified=%v", u.Email, u.EmailVerified)
	}
	if _, ok := ec.waitMail("new@example.com"); !ok {
		t.Fatal("no verification mail to new address")
	}
	settle()
	if _, ok := ec.outbox.Last("old@example.com"); ok {
		t.Fatal("mail sent to the old address")
	}
	if n := len(ec.outbox.Messages()); n != 1 {
		t.Fatalf("want exactly 1 mail, got %d", n)
	}
}

func TestEmailChangeExplicitVerifiedHonoured(t *testing.T) {
	ec := newECEnv(t, true)
	id := ec.user("old@example.com", false)
	ec.put(id, map[string]any{"email": "new@example.com", "emailVerified": true})
	if u := ec.stored(id); u.Email != "new@example.com" || !u.EmailVerified {
		t.Fatalf("explicit verified not honoured: %+v", u)
	}
	settle()
	if n := len(ec.outbox.Messages()); n != 0 {
		t.Fatalf("mail sent for admin-asserted address: %d", n)
	}
}

func TestEmailCaseOnlyChangeIsNoChange(t *testing.T) {
	ec := newECEnv(t, true)
	id := ec.user("old@example.com", true)
	ec.put(id, map[string]any{"email": " OLD@Example.com ", "emailVerified": true})
	if u := ec.stored(id); !u.EmailVerified {
		t.Fatal("case-only change unverified the address")
	}
	settle()
	if n := len(ec.outbox.Messages()); n != 0 {
		t.Fatalf("mail sent on case-only change: %d", n)
	}
}

func TestEmailClearUnverifiesAndSendsNothing(t *testing.T) {
	ec := newECEnv(t, true)
	id := ec.user("old@example.com", true)
	ec.put(id, map[string]any{"email": "", "emailVerified": true})
	if u := ec.stored(id); u.Email != "" || u.EmailVerified {
		t.Fatalf("clear: %+v", u)
	}
	settle()
	if n := len(ec.outbox.Messages()); n != 0 {
		t.Fatalf("mail sent on clear: %d", n)
	}
}

func TestEmailChangeKillsOldLinksAndResetsRateLimit(t *testing.T) {
	ec := newECEnv(t, true)
	ctx := context.Background()
	id := ec.user("old@example.com", false)
	u := ec.stored(id)
	rl, err := ec.st.GetRealm(ctx, realm)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < actions.MaxPerHour; i++ {
		if err := ec.svc.Send(ctx, rl, u, core.ActionVerifyEmail, actions.SendOpts{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := ec.svc.Send(ctx, rl, u, core.ActionResetPassword, actions.SendOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := ec.svc.Send(ctx, rl, u, core.ActionVerifyEmail, actions.SendOpts{}); !errors.Is(err, actions.ErrRateLimited) {
		t.Fatalf("precondition: want rate limited, got %v", err)
	}
	oldMsg, ok := ec.outbox.Last("old@example.com")
	if !ok {
		t.Fatal("no old mail")
	}
	oldTok := tokenOf(t, oldMsg)
	since := time.Now().Add(-time.Hour)

	ec.put(id, map[string]any{"email": "new@example.com"})

	// The new-address mail was sent despite the earlier flood, so the limit
	// was not counting the old tokens: only its own token remains.
	m, ok := ec.waitMail("new@example.com")
	if !ok {
		t.Fatal("new-address mail was rate limited or not sent")
	}
	if n, err := ec.st.CountActionTokens(ctx, realm, id, core.ActionResetPassword, since); err != nil || n != 0 {
		t.Fatalf("reset tokens after change: %d, %v", n, err)
	}
	if n, err := ec.st.CountActionTokens(ctx, realm, id, core.ActionVerifyEmail, since); err != nil || n != 1 {
		t.Fatalf("verify tokens after change: want only the new one, got %d, %v", n, err)
	}
	if _, _, err := ec.svc.Redeem(ctx, realm, oldTok, core.ActionVerifyEmail); !errors.Is(err, actions.ErrInvalidToken) {
		t.Fatalf("old link still redeems: %v", err)
	}
	if _, _, err := ec.svc.Redeem(ctx, realm, tokenOf(t, m), core.ActionVerifyEmail); err != nil {
		t.Fatalf("new link: %v", err)
	}
}

func TestEmailChangeWithoutMailerStillUnverifies(t *testing.T) {
	ec := newECEnv(t, false)
	id := ec.user("old@example.com", true)
	ec.put(id, map[string]any{"email": "new@example.com"})
	if u := ec.stored(id); u.Email != "new@example.com" || u.EmailVerified {
		t.Fatalf("got %+v", u)
	}
}
