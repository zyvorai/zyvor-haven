// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/sessions"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type recNotifier struct {
	mu   sync.Mutex
	got  []core.Session
	rlms []string
}

func (n *recNotifier) Notify(_ context.Context, realm string, s core.Session) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, s)
	n.rlms = append(n.rlms, realm)
}

func (n *recNotifier) sessions() []core.Session {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]core.Session(nil), n.got...)
}

const cookieHash = "COOKIEHASH-super-secret-value-0123"

func sessEnv(t *testing.T) (*env, *recNotifier) {
	n := &recNotifier{}
	e := newEnvWith(t, func(cfg *admin.Config, st *memstore.Store, _ string) {
		cfg.Sessions = &sessions.Service{Store: st, Notifier: n}
	})
	return e, n
}

var sessSeq int

// putSession stores a session. age sets CreatedAt (now-age); the session is
// live unless idle/abs are given as past offsets.
func (e *env) putSession(userID string, age, idleIn, absIn time.Duration, clients ...string) core.Session {
	e.t.Helper()
	sessSeq++
	now := time.Now().UTC()
	s := core.Session{
		ID: fmt.Sprintf("sid-%d", sessSeq), CookieHash: fmt.Sprintf("%s-%d", cookieHash, sessSeq),
		Realm: realm, UserID: userID, AuthTime: now.Add(-age), LastSeen: now.Add(-age),
		IdleExpires: now.Add(idleIn), ExpiresAt: now.Add(absIn), IP: "203.0.113.7",
		UserAgent: "UA/1.0", Clients: clients, CreatedAt: now.Add(-age),
	}
	if err := e.st.PutSession(context.Background(), s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) mkUser(name string) string {
	return e.createID("/realms/"+realm+"/users", map[string]any{"username": name, "enabled": true})
}

func (e *env) listSessions(path string) (out []idp.Session, raw []byte) {
	e.t.Helper()
	raw = e.api(200, "GET", path, nil)
	if err := json.Unmarshal(raw, &out); err != nil {
		e.t.Fatal(err)
	}
	return out, raw
}

func ids(ss []idp.Session) []string {
	var out []string
	for _, s := range ss {
		out = append(out, s.ID)
	}
	return out
}

func TestListSessions(t *testing.T) {
	e, _ := sessEnv(t)
	r := "/realms/" + realm
	alice, bob := e.mkUser("alice"), e.mkUser("bob")
	h := time.Hour
	old := e.putSession(alice, 3*h, h, 5*h, "app")
	mid := e.putSession(bob, 2*h, h, 5*h)
	newest := e.putSession(alice, h, h, 5*h, "app", "wiki")
	e.putSession(alice, 4*h, -time.Minute, 5*h) // idle-expired
	e.putSession(alice, 4*h, h, -time.Minute)   // absolute-expired
	ghost := e.putSession("gone-user", 30*time.Minute, h, 5*h)

	all, raw := e.listSessions(r + "/sessions")
	if got, want := ids(all), []string{ghost.ID, newest.ID, mid.ID, old.ID}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("all, newest first without expired: got %v want %v", got, want)
	}
	if all[0].Username != "" || all[1].Username != "alice" || all[2].Username != "bob" {
		t.Fatalf("usernames: %+v", all)
	}
	if fmt.Sprint(all[1].Clients) != "[app wiki]" || all[2].Clients == nil || all[1].IPAddress != "203.0.113.7" || all[1].UserAgent != "UA/1.0" {
		t.Fatalf("fields: %+v", all[1])
	}
	if strings.Contains(string(raw), cookieHash) || strings.Contains(strings.ToLower(string(raw)), "cookie") {
		t.Fatalf("cookie hash leaked: %s", raw)
	}

	byUser, _ := e.listSessions(r + "/sessions?userId=" + alice)
	if got := ids(byUser); fmt.Sprint(got) != fmt.Sprint([]string{newest.ID, old.ID}) {
		t.Fatalf("by user: %v", got)
	}
	perUser, raw2 := e.listSessions(r + "/users/" + alice + "/sessions")
	if fmt.Sprint(ids(perUser)) != fmt.Sprint(ids(byUser)) || strings.Contains(string(raw2), cookieHash) {
		t.Fatalf("per-user route: %v", ids(perUser))
	}
	e.api(404, "GET", r+"/users/nope/sessions", nil)

	two, _ := e.listSessions(r + "/sessions?max=2")
	if len(two) != 2 || two[0].ID != ghost.ID {
		t.Fatalf("max=2: %v", ids(two))
	}
	e.api(400, "GET", r+"/sessions?max=x", nil)
	e.api(404, "GET", "/realms/nope/sessions", nil)
}

func TestListSessionsFindsLiveBehindExpired(t *testing.T) {
	e, _ := sessEnv(t)
	u := e.mkUser("alice")
	live := e.putSession(u, 24*time.Hour, time.Hour, 5*time.Hour) // oldest, live
	for i := 0; i < 5; i++ {
		e.putSession(u, time.Duration(i+1)*time.Minute, -time.Second, time.Hour) // newer, dead
	}
	got, _ := e.listSessions("/realms/" + realm + "/sessions?max=1")
	if len(got) != 1 || got[0].ID != live.ID {
		t.Fatalf("live session hidden behind expired ones: %v", ids(got))
	}
}

func TestListSessionsCap(t *testing.T) {
	e, _ := sessEnv(t)
	u := e.mkUser("alice")
	for i := 0; i < 510; i++ {
		e.putSession(u, time.Duration(i)*time.Second, time.Hour, 2*time.Hour)
	}
	if got, _ := e.listSessions("/realms/" + realm + "/sessions?max=9999"); len(got) != 500 {
		t.Fatalf("cap: got %d", len(got))
	}
	if got, _ := e.listSessions("/realms/" + realm + "/sessions"); len(got) != 100 {
		t.Fatalf("default: got %d", len(got))
	}
}

func (e *env) putRefresh(hash, sid, scope string) {
	e.t.Helper()
	err := e.st.PutRefreshToken(context.Background(), core.RefreshToken{
		TokenHash: hash, FamilyID: hash, Realm: realm, ClientID: "app", UserID: "u", SessionID: sid,
		Scope: scope, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) revoked(hash string) bool {
	e.t.Helper()
	t, err := e.st.GetRefreshToken(context.Background(), hash)
	if err != nil {
		e.t.Fatal(err)
	}
	return t.Revoked
}

func (e *env) adminEvents() []core.Event {
	e.t.Helper()
	evs, err := e.st.ListEvents(context.Background(), realm, 100)
	if err != nil {
		e.t.Fatal(err)
	}
	return evs
}

func TestEndSession(t *testing.T) {
	e, n := sessEnv(t)
	r := "/realms/" + realm
	u := e.mkUser("alice")
	s := e.putSession(u, time.Minute, time.Hour, 2*time.Hour, "app")
	other := e.putSession(u, time.Minute, time.Hour, 2*time.Hour, "app")
	e.putRefresh("rt-normal", s.ID, "openid")
	e.putRefresh("rt-offline", s.ID, "openid offline_access")
	e.putRefresh("rt-other", other.ID, "openid")

	if body := e.api(204, "DELETE", r+"/sessions/"+s.ID, nil); len(body) != 0 {
		t.Fatalf("body: %q", body)
	}
	if _, err := e.st.GetSession(context.Background(), realm, s.ID); err == nil {
		t.Fatal("session still stored")
	}
	if _, err := e.st.GetSession(context.Background(), realm, other.ID); err != nil {
		t.Fatalf("other session must survive: %v", err)
	}
	if !e.revoked("rt-normal") || e.revoked("rt-offline") || e.revoked("rt-other") {
		t.Fatalf("revocation: normal=%v offline=%v other=%v", e.revoked("rt-normal"), e.revoked("rt-offline"), e.revoked("rt-other"))
	}
	if got := n.sessions(); len(got) != 1 || got[0].ID != s.ID || got[0].UserID != u || n.rlms[0] != realm || fmt.Sprint(got[0].Clients) != "[app]" {
		t.Fatalf("notifier: %+v", got)
	}

	found := false
	for _, ev := range e.adminEvents() {
		if ev.Type == "ADMIN_ACTION" && strings.HasPrefix(ev.Detail, "session ") {
			found = true
			if ev.Detail != "session "+s.ID || strings.Contains(ev.Detail, cookieHash) || strings.Contains(ev.Detail, "203.0.113.7") || strings.Contains(ev.Detail, "rt-") {
				t.Fatalf("audit detail: %q", ev.Detail)
			}
		}
	}
	if !found {
		t.Fatal("no ADMIN_ACTION session event")
	}

	// Already gone / unknown: 404, no second notification.
	e.api(404, "DELETE", r+"/sessions/"+s.ID, nil)
	e.api(404, "DELETE", r+"/sessions/never", nil)
	if len(n.sessions()) != 1 {
		t.Fatalf("notified again: %d", len(n.sessions()))
	}
}

func TestEndUserSessions(t *testing.T) {
	e, n := sessEnv(t)
	r := "/realms/" + realm
	alice, bob := e.mkUser("alice"), e.mkUser("bob")
	a1 := e.putSession(alice, time.Minute, time.Hour, 2*time.Hour, "app")
	a2 := e.putSession(alice, time.Minute, time.Hour, 2*time.Hour)
	b1 := e.putSession(bob, time.Minute, time.Hour, 2*time.Hour)
	e.putRefresh("rt-a1", a1.ID, "openid")

	var out struct{ Ended int }
	if err := json.Unmarshal(e.api(200, "DELETE", r+"/users/"+alice+"/sessions", nil), &out); err != nil || out.Ended != 2 {
		t.Fatalf("ended: %+v %v", out, err)
	}
	got := map[string]bool{}
	for _, s := range n.sessions() {
		got[s.ID] = true
	}
	if len(got) != 2 || !got[a1.ID] || !got[a2.ID] {
		t.Fatalf("notified: %v", got)
	}
	if !e.revoked("rt-a1") {
		t.Fatal("refresh token not revoked")
	}
	if _, err := e.st.GetSession(context.Background(), realm, b1.ID); err != nil {
		t.Fatalf("bob's session must survive: %v", err)
	}
	// Second call: user exists, nothing to end.
	if err := json.Unmarshal(e.api(200, "DELETE", r+"/users/"+alice+"/sessions", nil), &out); err != nil || out.Ended != 0 {
		t.Fatalf("second: %+v", out)
	}
	e.api(404, "DELETE", r+"/users/nope/sessions", nil)

	found := false
	for _, ev := range e.adminEvents() {
		if ev.Type == "ADMIN_ACTION" && ev.Detail == "user-sessions alice" {
			found = true
		}
	}
	if !found {
		t.Fatal("no user-sessions audit event")
	}
}

func TestSessionRoutesAuth(t *testing.T) {
	e, n := sessEnv(t)
	r := "/realms/" + realm
	u := e.mkUser("alice")
	s := e.putSession(u, time.Minute, time.Hour, 2*time.Hour, "app")
	e.createID(r+"/clients", map[string]any{"clientId": "rogue", "enabled": true, "serviceAccountsEnabled": true})
	rogue := e.clientToken(realm, "rogue", e.regen(realm, "rogue"))

	for _, rt := range []struct{ m, p string }{
		{"GET", r + "/sessions"}, {"GET", r + "/users/" + u + "/sessions"},
		{"DELETE", r + "/sessions/" + s.ID}, {"DELETE", r + "/users/" + u + "/sessions"},
	} {
		if code, _, _ := e.call(rt.m, rt.p, "", nil); code != 401 {
			t.Errorf("%s %s without token: %d", rt.m, rt.p, code)
		}
		if code, _, _ := e.call(rt.m, rt.p, rogue, nil); code != 403 {
			t.Errorf("%s %s non-admin client: %d", rt.m, rt.p, code)
		}
	}
	if _, err := e.st.GetSession(context.Background(), realm, s.ID); err != nil || len(n.sessions()) != 0 {
		t.Fatal("rejected calls must not end sessions")
	}
}

func TestDisableUserEndsSessions(t *testing.T) {
	e, n := sessEnv(t)
	r := "/realms/" + realm
	u := e.mkUser("alice")
	s := e.putSession(u, time.Minute, time.Hour, 2*time.Hour, "app")
	e.putRefresh("rt", s.ID, "openid")

	// An update that keeps the user enabled leaves the session alone.
	e.api(204, "PUT", r+"/users/"+u, map[string]any{"username": "alice", "enabled": true, "firstName": "A"})
	if len(n.sessions()) != 0 {
		t.Fatal("session ended by a plain update")
	}
	e.api(204, "PUT", r+"/users/"+u, map[string]any{"username": "alice", "enabled": false})
	if _, err := e.st.GetSession(context.Background(), realm, s.ID); err == nil {
		t.Fatal("session survived disabling the user")
	}
	if got := n.sessions(); len(got) != 1 || got[0].ID != s.ID || !e.revoked("rt") {
		t.Fatalf("notify/revoke: %+v", got)
	}
}

func TestResetPasswordEndsSessions(t *testing.T) {
	e, n := sessEnv(t)
	r := "/realms/" + realm
	u := e.mkUser("alice")
	s := e.putSession(u, time.Minute, time.Hour, 2*time.Hour, "app")
	e.api(204, "PUT", r+"/users/"+u+"/password", map[string]any{"type": "password", "value": goodPW})
	if _, err := e.st.GetSession(context.Background(), realm, s.ID); err == nil {
		t.Fatal("session survived an admin password reset")
	}
	if got := n.sessions(); len(got) != 1 || got[0].ID != s.ID {
		t.Fatalf("notify: %+v", got)
	}
	// A rejected reset (policy/empty) must not end anything.
	s2 := e.putSession(u, time.Minute, time.Hour, 2*time.Hour)
	e.api(400, "PUT", r+"/users/"+u+"/password", map[string]any{"type": "password", "value": ""})
	if _, err := e.st.GetSession(context.Background(), realm, s2.ID); err != nil {
		t.Fatal("invalid reset ended a session")
	}
}

func TestDeleteUserNotifiesSessions(t *testing.T) {
	e, n := sessEnv(t)
	r := "/realms/" + realm
	u := e.mkUser("alice")
	s := e.putSession(u, time.Minute, time.Hour, 2*time.Hour, "app")
	e.api(204, "DELETE", r+"/users/"+u, nil)
	if got := n.sessions(); len(got) != 1 || got[0].ID != s.ID {
		t.Fatalf("clients not notified before delete: %+v", got)
	}
	if _, err := e.st.GetSession(context.Background(), realm, s.ID); err == nil {
		t.Fatal("session row survived user deletion")
	}
	// Unknown user: nothing to notify, still 404.
	e.api(404, "DELETE", r+"/users/"+u, nil)
}
