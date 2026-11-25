// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// The account console together with the session controls.

// signInRemembered is signIn with "keep me signed in" ticked.
func (b *conBrowser) signInRemembered(user, pw string) core.Session {
	t := b.e.t
	t.Helper()
	target := base + "auth?" + authQuery(nil).Encode()
	delete(b.cookies, ssoCookie)
	m := csrfRe.FindStringSubmatch(b.do("GET", target, nil).Body.String())
	w := b.do("POST", target, url.Values{"csrf": {m[1]}, "username": {user}, "password": {pw}, "remember_me": {"on"}})
	if w.Code != 302 || b.cookies[ssoCookie] == nil {
		t.Fatalf("login failed: %d %s", w.Code, w.Body)
	}
	return b.session()
}

func (e *conEnv) sessionPolicy(p core.SessionPolicy) {
	e.t.Helper()
	e.must(e.st.PutSessionPolicy(context.Background(), "r", p))
}

func TestAccountSessionsHideWithdrawnRememberedSessions(t *testing.T) {
	e := newConEnv(t, conOpts{})
	e.sessionPolicy(core.SessionPolicy{RememberMe: true})
	old := e.visitor("old-laptop", "192.0.2.10").signInRemembered("alice", "alice-pass")
	now := e.visitor("this-one", "192.0.2.11")
	now.signIn("alice", "alice-pass")
	if !strings.Contains(now.get("sessions"), old.ID) {
		t.Fatal("remembered session not listed while the option is on")
	}
	e.sessionPolicy(core.SessionPolicy{})
	if body := now.get("sessions"); strings.Contains(body, old.ID) {
		t.Fatal("a remembered session that no longer works is listed as active")
	}
}

// Changing the password renews the cookie of a remembered session without
// shortening or lengthening it.
func TestAccountPasswordChangeKeepsRememberedSession(t *testing.T) {
	e := newConEnv(t, conOpts{})
	e.sessionPolicy(core.SessionPolicy{RememberMe: true, MaxSessions: 5})
	a := e.visitor("laptop", "192.0.2.10")
	before := a.signInRemembered("alice", "alice-pass")
	oldCookie := a.cookies[ssoCookie].Value
	e.wantRedirect(a.post("password", "action", "change", "current", "alice-pass", "password", "new-password-1", "confirm", "new-password-1"),
		acctRoot+"/password?m=password", "password change")
	ck := a.cookies[ssoCookie]
	after := a.session()
	if ck.Value == oldCookie || after.ID != before.ID || !ck.Expires.Equal(before.ExpiresAt.Truncate(time.Second)) ||
		before.ExpiresAt.Sub(before.CreatedAt) != core.DefaultRememberMax {
		t.Fatalf("cookie %v, session %v..%v", ck.Expires, after.CreatedAt, after.ExpiresAt)
	}
	idle, err := e.st.SessionRememberIdle(context.Background(), "r", after.ID)
	e.must(err)
	if idle != core.DefaultRememberIdle {
		t.Fatalf("remember mark lost: %v", idle)
	}
	e.now = e.now.Add(5 * 24 * time.Hour)
	if w := a.do("GET", base+"auth?"+authQuery(nil).Encode(), nil); !isCode(w) {
		t.Fatalf("remembered session gone after the change: %d", w.Code)
	}
}

// In a realm that refuses new sessions, signing one out on the account page
// frees its slot.
func TestAccountSignOutFreesSessionLimitSlot(t *testing.T) {
	e := newConEnv(t, conOpts{})
	e.sessionPolicy(core.SessionPolicy{MaxSessions: 2, OnLimit: core.SessionLimitDenyNew})
	first := e.visitor("first", "192.0.2.10").signIn("alice", "alice-pass")
	keeper := e.visitor("keeper", "192.0.2.11")
	keeper.signIn("alice", "alice-pass")
	third := e.visitor("third", "192.0.2.12")
	login := func() bool {
		target := base + "auth?" + authQuery(nil).Encode()
		m := csrfRe.FindStringSubmatch(third.do("GET", target, nil).Body.String())
		return isCode(third.do("POST", target, url.Values{"csrf": {m[1]}, "username": {"alice"}, "password": {"alice-pass"}}))
	}
	if login() {
		t.Fatal("limit not applied")
	}
	e.wantRedirect(keeper.post("sessions", "action", "revoke", "sid", first.ID), acctRoot+"/sessions?m=session", "revoke")
	if !login() {
		t.Fatal("the freed slot cannot be used")
	}
}
