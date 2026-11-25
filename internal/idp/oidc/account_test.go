// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/backchannel"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/sessions"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/totp"
)

// ---- harness ----

type acctNotifier struct {
	mu   sync.Mutex
	sids []string
}

func (n *acctNotifier) Notify(_ context.Context, _ string, s core.Session) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sids = append(n.sids, s.ID)
}

func (n *acctNotifier) got() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := slices.Clone(n.sids)
	slices.Sort(out)
	return out
}

type conEnv struct {
	t      *testing.T
	st     *memstore.Store
	h      *Provider
	now    time.Time
	realm  core.Realm
	notify *acctNotifier
	outbox *mail.Outbox
}

const acctRoot = "/realms/r/account"

type conOpts struct {
	realm func(*core.Realm)
	store func(*memstore.Store) core.Store
	notif func(core.Store, func() time.Time) sessions.Notifier
}

func newConEnv(t *testing.T, o conOpts) *conEnv {
	t.Helper()
	ctx := context.Background()
	e := &conEnv{t: t, now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC), st: memstore.New(),
		notify: &acctNotifier{}, outbox: mail.NewOutbox(20)}
	e.realm = core.Realm{Name: "r", Enabled: true, BruteForceProtection: true, RefreshTokenRotation: true,
		AuthEventsLogged: true, AdminEventsLogged: true, AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour,
		SessionIdleTTL: 2 * time.Hour, PasswordPolicy: "length(8)"}
	if o.realm != nil {
		o.realm(&e.realm)
	}
	e.must(e.st.CreateRealm(ctx, e.realm))
	for _, u := range []core.User{
		{ID: "u-alice", Realm: "r", Username: "alice", Email: "alice@example.test", FirstName: "Alice", Enabled: true, EmailVerified: true, PasswordHash: "H:alice-pass"},
		{ID: "u-bob", Realm: "r", Username: "bob", Email: "bob-secret@example.test", FirstName: "Bobby", Enabled: true, EmailVerified: true, PasswordHash: "H:bob-pass"},
	} {
		e.must(e.st.CreateUser(ctx, u))
	}
	e.must(e.st.CreateClient(ctx, core.Client{ID: "c1", Realm: "r", ClientID: "app", Name: "Demo app", Enabled: true, Public: true, AuthCodeFlow: true, RedirectURIs: []string{cb}}))
	clock := func() time.Time { return e.now }
	var store core.Store = e.st
	if o.store != nil {
		store = o.store(e.st)
	}
	var n sessions.Notifier = e.notify
	if o.notif != nil {
		n = o.notif(store, clock)
	}
	box, err := secretbox.New([]byte("0123456789abcdef0123456789abcdef"))
	e.must(err)
	e.h = New(Config{Store: store, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{}, BaseURL: "https://idp.example",
		Clock: clock, CSRFKey: []byte("0123456789abcdef0123456789abcdef"), SecretBox: box,
		Sessions: &sessions.Service{Store: store, Notifier: n},
		Actions:  &actions.Service{Store: store, Mailer: e.outbox, BaseURL: "https://idp.example", Clock: clock}})
	return e
}

func (e *conEnv) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

// browser is a cookie jar plus a source address.
type conBrowser struct {
	e       *conEnv
	ua, ip  string
	cookies map[string]*http.Cookie
}

func (e *conEnv) visitor(ua, ip string) *conBrowser {
	return &conBrowser{e: e, ua: ua, ip: ip, cookies: map[string]*http.Cookie{}}
}

func (b *conBrowser) clone() *conBrowser {
	n := b.e.visitor(b.ua, b.ip)
	for k, v := range b.cookies {
		c := *v
		n.cookies[k] = &c
	}
	return n
}

func (b *conBrowser) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", b.ua)
	req.RemoteAddr = b.ip + ":4000"
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.e.h.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return w
}

// signIn runs the real login form.
func (b *conBrowser) signIn(user, pw string) core.Session {
	t := b.e.t
	t.Helper()
	target := base + "auth?" + authQuery(nil).Encode()
	delete(b.cookies, ssoCookie)
	w := b.do("GET", target, nil)
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no login form: %d %s", w.Code, w.Body)
	}
	w = b.do("POST", target, url.Values{"csrf": {m[1]}, "username": {user}, "password": {pw}})
	if w.Code != 302 || b.cookies[ssoCookie] == nil {
		t.Fatalf("login failed: %d %s", w.Code, w.Body)
	}
	return b.session()
}

func (b *conBrowser) session() core.Session {
	b.e.t.Helper()
	ck := b.cookies[ssoCookie]
	if ck == nil {
		b.e.t.Fatal("no SSO cookie")
	}
	s, err := b.e.st.GetSessionByCookie(context.Background(), "r", actions.Hash(ck.Value))
	b.e.must(err)
	return s
}

// get loads an account page ("" = overview) and expects 200.
func (b *conBrowser) get(slug string) string {
	b.e.t.Helper()
	target := acctRoot
	if slug != "" {
		target += "/" + slug
	}
	w := b.do("GET", target, nil)
	if w.Code != 200 {
		b.e.t.Fatalf("GET %s: %d %s", target, w.Code, w.Body)
	}
	return w.Body.String()
}

// csrf loads the page to obtain a token and its cookie.
func (b *conBrowser) csrf(slug string) string {
	b.e.t.Helper()
	m := csrfRe.FindStringSubmatch(b.get(slug))
	if m != nil {
		return m[1]
	}
	if ck := b.cookies[acctCSRFCookie]; ck != nil {
		return ck.Value // a page without forms still sets the cookie
	}
	b.e.t.Fatalf("no csrf token on %q", slug)
	return ""
}

// post submits an account form with a fresh CSRF token.
func (b *conBrowser) post(slug string, kv ...string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	f := url.Values{"csrf": {b.csrf(slug)}}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Set(kv[i], kv[i+1])
	}
	return b.do("POST", acctRoot+"/"+slug, f)
}

func (e *conEnv) wantRedirect(w *httptest.ResponseRecorder, to, what string) {
	e.t.Helper()
	if w.Code != 303 || w.Header().Get("Location") != to {
		e.t.Fatalf("%s: got %d %q %s", what, w.Code, w.Header().Get("Location"), w.Body)
	}
}

func (e *conEnv) wantStatus(w *httptest.ResponseRecorder, code int, text, what string) {
	e.t.Helper()
	if w.Code != code || !strings.Contains(w.Body.String(), text) {
		e.t.Fatalf("%s: got %d (want %d containing %q): %s", what, w.Code, code, text, w.Body)
	}
}

func (e *conEnv) sessionIDs(user string) []string {
	e.t.Helper()
	ss, err := e.st.ListSessions(context.Background(), "r", user, 100)
	e.must(err)
	var out []string
	for _, s := range ss {
		out = append(out, s.ID)
	}
	slices.Sort(out)
	return out
}

func (e *conEnv) refresh(hash, user, sid, scope string) {
	e.t.Helper()
	e.must(e.st.PutRefreshToken(context.Background(), core.RefreshToken{TokenHash: hash, FamilyID: "f-" + hash, Realm: "r",
		ClientID: "app", UserID: user, SessionID: sid, Scope: scope, ExpiresAt: e.now.Add(time.Hour), CreatedAt: e.now}))
}

func (e *conEnv) revoked(hash string) bool {
	e.t.Helper()
	t, err := e.st.GetRefreshToken(context.Background(), hash)
	e.must(err)
	return t.Revoked
}

func (e *conEnv) events(user string) []core.Event {
	e.t.Helper()
	all, err := e.st.ListEvents(context.Background(), "r", 1000)
	e.must(err)
	return slices.DeleteFunc(all, func(ev core.Event) bool { return ev.UserID != user })
}

func (e *conEnv) hasEvent(user, typ string) bool {
	return slices.ContainsFunc(e.events(user), func(ev core.Event) bool { return ev.Type == typ })
}

func (e *conEnv) user(id string) core.User {
	e.t.Helper()
	u, err := e.st.GetUser(context.Background(), "r", id)
	e.must(err)
	return u
}

// owned is everything one user owns in the fixtures.
type owned struct {
	deviceHash, grantID, agentID, credID, secretHash string
}

// seed gives a user a known device, a consent grant and an agent with one
// credential. tag makes every visible string unique to the user.
func (e *conEnv) seed(user, tag string) owned {
	e.t.Helper()
	ctx := context.Background()
	var o owned
	e.must(e.st.PutStepUpPolicy(ctx, "r", core.StepUpPolicy{Enabled: true}))
	o.deviceHash = deviceHash(tag + "-device-cookie")
	e.must(e.st.TouchDevice(ctx, core.KnownDevice{Realm: "r", UserID: user, Hash: o.deviceHash, IPHash: "x",
		FirstSeen: e.now.Add(-48 * time.Hour), LastSeen: e.now.Add(-time.Hour)}, 10))
	cs, ok := core.StoreAs[core.ConsentStore](e.st)
	if !ok {
		e.t.Fatal("no consent store")
	}
	g, err := cs.PutConsentGrant(ctx, core.ConsentGrant{Realm: "r", UserID: user, ClientID: tag + "-client", ClientName: tag + "-appname",
		Scopes: []string{"openid"}, Resources: []string{"https://" + tag + ".example/api"}, CreatedAt: e.now, ExpiresAt: e.now.Add(24 * time.Hour)}, e.now)
	e.must(err)
	o.grantID = g.ID
	as, ok := core.StoreAs[core.AgentStore](e.st)
	if !ok {
		e.t.Fatal("no agent store")
	}
	ag, err := as.CreateAgent(ctx, core.Agent{Realm: "r", Name: tag + "-agent", Kind: "agent", ClientID: "agent-" + tag, OwnerUserID: user,
		AllowedScopes: []string{"mcp:" + tag}, TokenTTL: 300, Enabled: true})
	e.must(err)
	o.agentID = ag.ID
	o.secretHash = HashSecret(tag + "-secret")
	cr, err := as.CreateAgentCredential(ctx, core.AgentCredential{Realm: "r", AgentID: ag.ID, SecretHash: o.secretHash,
		Scopes: []string{"mcp:" + tag}, Note: tag + "-note", CreatedBy: "admin-person", CreatedAt: e.now, ExpiresAt: e.now.Add(24 * time.Hour)},
		5, e.now)
	e.must(err)
	o.credID = cr.ID
	return o
}

func (e *conEnv) cred(o owned) core.AgentCredential {
	e.t.Helper()
	as, _ := core.StoreAs[core.AgentStore](e.st)
	list, err := as.ListAgentCredentials(context.Background(), "r", o.agentID)
	e.must(err)
	for _, c := range list {
		if c.ID == o.credID {
			return c
		}
	}
	e.t.Fatal("credential vanished")
	return core.AgentCredential{}
}

func (e *conEnv) grantActive(o owned) bool {
	e.t.Helper()
	cs, _ := core.StoreAs[core.ConsentStore](e.st)
	g, err := cs.GetConsentGrant(context.Background(), "r", o.grantID)
	e.must(err)
	return g.RevokedAt.IsZero()
}

func (e *conEnv) deviceKnown(user string, o owned) bool {
	e.t.Helper()
	st, _ := core.StoreAs[core.StepUpStore](e.st)
	_, err := st.GetDevice(context.Background(), "r", user, o.deviceHash)
	if errors.Is(err, idp.ErrNotFound) {
		return false
	}
	e.must(err)
	return true
}

var acctSlugs = []string{"", "sessions", "devices", "security", "password", "applications", "agents", "activity"}

var acctPostSlugs = []string{"sessions", "devices", "password", "applications", "agents"}

// ---- access control ----

func TestAccountNeedsLiveSession(t *testing.T) {
	cases := []struct {
		name string
		mut  func(e *conEnv, b *conBrowser)
		want int
	}{
		{"no cookie", func(_ *conEnv, b *conBrowser) { delete(b.cookies, ssoCookie) }, 401},
		{"made-up cookie", func(_ *conEnv, b *conBrowser) { b.cookies[ssoCookie] = &http.Cookie{Name: ssoCookie, Value: "nope"} }, 401},
		{"idle expired", func(e *conEnv, _ *conBrowser) { e.now = e.now.Add(3 * time.Hour) }, 401},
		{"ended", func(e *conEnv, b *conBrowser) {
			s := b.session()
			_, err := e.st.TakeSession(context.Background(), "r", s.ID)
			e.must(err)
		}, 401},
		{"user disabled", func(e *conEnv, _ *conBrowser) {
			u := e.user("u-alice")
			u.Enabled = false
			e.must(e.st.UpdateUser(context.Background(), u))
		}, 403},
		{"user deleted", func(e *conEnv, _ *conBrowser) { e.must(e.st.DeleteUser(context.Background(), "r", "u-alice")) }, 0},
		{"email unverified in a realm that requires it", func(e *conEnv, _ *conBrowser) {
			e.realm.EmailVerificationRequired = true
			e.must(e.st.UpdateRealm(context.Background(), e.realm))
			u := e.user("u-alice")
			u.EmailVerified = false
			e.must(e.st.UpdateUser(context.Background(), u))
		}, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newConEnv(t, conOpts{})
			e.seed("u-alice", "alicemark")
			b := e.visitor("UA", "192.0.2.1")
			b.signIn("alice", "alice-pass")
			csrf := b.csrf("sessions")
			tc.mut(e, b)
			for _, slug := range acctSlugs {
				w := b.do("GET", strings.TrimSuffix(acctRoot+"/"+slug, "/"), nil)
				if w.Code != tc.want && (tc.want != 0 || (w.Code != 401 && w.Code != 403)) {
					t.Fatalf("GET %q: %d, want %d", slug, w.Code, tc.want)
				}
				if s := w.Body.String(); strings.Contains(s, "alicemark") || strings.Contains(s, "alice@example.test") {
					t.Fatalf("GET %q leaked account data", slug)
				}
			}
			for _, slug := range acctPostSlugs {
				w := b.do("POST", acctRoot+"/"+slug, url.Values{"csrf": {csrf}, "action": {"revoke-others"}})
				if w.Code != 401 && w.Code != 403 {
					t.Fatalf("POST %q: %d", slug, w.Code)
				}
			}
		})
	}
}

// bareStore hides every optional interface.
type bareStore struct{ core.Store }

func TestAccountOffWithoutStore(t *testing.T) {
	e := newConEnv(t, conOpts{store: func(s *memstore.Store) core.Store { return bareStore{s} }})
	b := e.visitor("UA", "192.0.2.1")
	b.signIn("alice", "alice-pass")
	for _, slug := range acctSlugs {
		w := b.do("GET", strings.TrimSuffix(acctRoot+"/"+slug, "/"), nil)
		if w.Code != 404 {
			t.Fatalf("GET %q: %d", slug, w.Code)
		}
	}
	if w := b.do("POST", acctRoot+"/sessions", url.Values{}); w.Code != 404 {
		t.Fatalf("POST: %d", w.Code)
	}
	if e.h.accountLink("r") != "" {
		t.Fatal("link offered although the console is off")
	}
}

// onlyAccount offers the account store but no devices, consents or agents.
type onlyAccount struct {
	core.Store
	core.AccountStore
}

func TestAccountHidesUnavailableSections(t *testing.T) {
	e := newConEnv(t, conOpts{store: func(s *memstore.Store) core.Store { return onlyAccount{s, s} }})
	b := e.visitor("UA", "192.0.2.1")
	b.signIn("alice", "alice-pass")
	body := b.get("")
	for _, slug := range []string{"devices", "applications", "agents"} {
		if strings.Contains(body, `href="`+acctRoot+"/"+slug+`"`) {
			t.Errorf("menu lists unavailable %s", slug)
		}
		if w := b.do("GET", acctRoot+"/"+slug, nil); w.Code != 404 {
			t.Errorf("GET %s: %d", slug, w.Code)
		}
		if w := b.do("POST", acctRoot+"/"+slug, url.Values{}); w.Code != 404 {
			t.Errorf("POST %s: %d", slug, w.Code)
		}
	}
	sec := b.get("security")
	for _, p := range []string{"/totp", "/passkeys"} {
		if strings.Contains(sec, acctRoot+p) {
			t.Errorf("security page links unavailable %s", p)
		}
	}
}

func TestAccountPageHeadersAndTheme(t *testing.T) {
	e := newConEnv(t, conOpts{})
	e.seed("u-alice", "alicemark")
	b := e.visitor(`<script>alert(1)</script>`, "192.0.2.1")
	b.signIn("alice", "alice-pass")
	for _, slug := range acctSlugs {
		w := b.do("GET", strings.TrimSuffix(acctRoot+"/"+slug, "/"), nil)
		body := w.Body.String()
		h := w.Header()
		if w.Code != 200 {
			t.Fatalf("%q: %d %s", slug, w.Code, body)
		}
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Frame-Options") != "DENY" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%q: headers %v", slug, h)
		}
		csp := h.Get("Content-Security-Policy")
		m := regexp.MustCompile(`style-src 'nonce-([^']+)'`).FindStringSubmatch(csp)
		if m == nil || !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") || strings.Contains(csp, "unsafe") {
			t.Fatalf("%q: CSP %q", slug, csp)
		}
		if strings.Count(body, "<style") != 1 || !strings.Contains(body, `<style nonce="`+m[1]+`">`) ||
			strings.Contains(body, "style=") || strings.Contains(body, "<script") {
			t.Errorf("%q: style or script rules broken", slug)
		}
		if !strings.Contains(body, `<main class="console">`) || !strings.Contains(body, `<svg class="hero"`) {
			t.Errorf("%q: not the console theme", slug)
		}
		if slug != "password" && !strings.Contains(body, `aria-current="page"`) {
			t.Errorf("%q: current section not marked", slug)
		}
		ck := cookieNamed(w, acctCSRFCookie)
		if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != acctRoot {
			t.Errorf("%q: csrf cookie %+v", slug, ck)
		}
	}
	if s := b.get("sessions"); !strings.Contains(s, "&lt;script&gt;") {
		t.Error("user agent not shown escaped")
	}
}

// User A must see nothing of user B on any page.
func TestAccountShowsOnlyOwnData(t *testing.T) {
	e := newConEnv(t, conOpts{})
	bobB := e.visitor("BobOnlyBrowser/1.0 bobmark", "203.0.113.99")
	bs := bobB.signIn("bob", "bob-pass")
	bob := e.seed("u-bob", "bobmark")
	alice := e.seed("u-alice", "alicemark")
	ctx := context.Background()
	e.must(e.st.AppendEvent(ctx, core.Event{Time: e.now, Realm: "r", Type: "LOGIN", UserID: "u-bob", ClientID: "bobmark-eventclient", IP: "203.0.113.77"}))
	a := e.visitor("AliceUA", "192.0.2.1")
	a.signIn("alice", "alice-pass")

	secrets := []string{"bobmark", "BobOnlyBrowser", "203.0.113.", "bob-secret", "Bobby", "u-bob", bs.ID, bob.grantID, bob.agentID, bob.credID,
		bob.deviceHash, deviceHandle("r", "u-bob", bob.deviceHash), alice.deviceHash, alice.secretHash, bob.secretHash, "admin-person"}
	for _, slug := range acctSlugs {
		body := a.get(slug)
		for _, s := range secrets {
			if strings.Contains(body, s) {
				t.Errorf("page %q contains %q", slug, s)
			}
		}
		// Parameters naming another user change nothing.
		w := a.do("GET", strings.TrimSuffix(acctRoot+"/"+slug, "/")+"?user=u-bob&userId=u-bob&user_id=u-bob&owner=u-bob&sid="+bs.ID, nil)
		for _, s := range secrets {
			if strings.Contains(w.Body.String(), s) {
				t.Errorf("page %q with parameters contains %q", slug, s)
			}
		}
	}
	for slug, want := range map[string]string{"applications": "alicemark-appname", "agents": "alicemark-note",
		"devices": deviceHandle("r", "u-alice", alice.deviceHash), "sessions": "AliceUA", "activity": "Signed in to an application"} {
		if !strings.Contains(a.get(slug), want) {
			t.Errorf("page %q lacks the user's own %q", slug, want)
		}
	}
}

// User A must change nothing of user B, whatever id is submitted, and must not
// be able to tell B's ids from ids that do not exist.
func TestAccountCannotTouchAnotherUser(t *testing.T) {
	e := newConEnv(t, conOpts{})
	bobB := e.visitor("BobUA", "203.0.113.99")
	bs := bobB.signIn("bob", "bob-pass")
	bob := e.seed("u-bob", "bobmark")
	alice := e.seed("u-alice", "alicemark")
	e.refresh("rt-bob", "u-bob", bs.ID, "openid")
	a := e.visitor("AliceUA", "192.0.2.1")
	a.signIn("alice", "alice-pass")

	cases := []struct {
		name, slug string
		kv         []string
	}{
		{"bob session", "sessions", []string{"action", "revoke", "sid", bs.ID}},
		{"missing session", "sessions", []string{"action", "revoke", "sid", "does-not-exist"}},
		{"bob device handle", "devices", []string{"action", "forget", "device", deviceHandle("r", "u-bob", bob.deviceHash)}},
		{"bob device hash", "devices", []string{"action", "forget", "device", bob.deviceHash}},
		{"alice-shaped handle of bob hash", "devices", []string{"action", "forget", "device", deviceHandle("r", "u-alice", bob.deviceHash)}},
		{"bob grant", "applications", []string{"action", "revoke", "grant_id", bob.grantID}},
		{"missing grant", "applications", []string{"action", "revoke", "grant_id", "nope"}},
		{"bob agent and credential", "agents", []string{"action", "revoke", "agent_id", bob.agentID, "credential_id", bob.credID}},
		{"own agent, bob credential", "agents", []string{"action", "revoke", "agent_id", alice.agentID, "credential_id", bob.credID}},
		{"bob agent, own credential", "agents", []string{"action", "revoke", "agent_id", bob.agentID, "credential_id", alice.credID}},
		{"bob agent revoke all", "agents", []string{"action", "revoke-all", "agent_id", bob.agentID}},
		{"missing agent", "agents", []string{"action", "revoke-all", "agent_id", "nope"}},
		{"control characters", "agents", []string{"action", "revoke-all", "agent_id", "a\x00b"}},
		{"oversized id", "sessions", []string{"action", "revoke", "sid", strings.Repeat("x", 4000)}},
	}
	for i, tc := range cases {
		e.now = e.now.Add(time.Second)
		if i%8 == 7 { // stay under the POST limit without moving the sign-in out of the fresh window
			e.h = withFreshLimits(t, e)
		}
		w := a.post(tc.slug, append(tc.kv, "user_id", "u-bob")...)
		if w.Code != 404 || !strings.Contains(w.Body.String(), "was not found") {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body)
		}
		for _, s := range []string{"bobmark", bob.agentID, bs.ID, bob.grantID, "does-not-exist"} {
			if strings.Contains(w.Body.String(), s) {
				t.Fatalf("%s: response echoes %q", tc.name, s)
			}
		}
	}
	// "All" actions only ever mean the signed-in user's.
	for _, tc := range [][]string{{"sessions", "revoke-others"}, {"devices", "forget-all"}} {
		e.wantRedirect(a.post(tc[0], "action", tc[1], "user_id", "u-bob"),
			acctRoot+"/"+tc[0]+"?m="+map[string]string{"sessions": "sessions", "devices": "devices"}[tc[0]], tc[1])
	}
	if got := e.sessionIDs("u-bob"); !slices.Equal(got, []string{bs.ID}) {
		t.Fatalf("bob sessions changed: %v", got)
	}
	if !e.deviceKnown("u-bob", bob) || !e.grantActive(bob) || !e.cred(bob).RevokedAt.IsZero() || e.revoked("rt-bob") {
		t.Fatal("bob's data changed")
	}
	if !e.grantActive(alice) || !e.cred(alice).RevokedAt.IsZero() {
		t.Fatal("alice's data changed by a refused request")
	}
	if n := e.notify.got(); len(n) != 0 {
		t.Fatalf("notifications sent: %v", n)
	}
	for _, ev := range e.events("u-alice") {
		if strings.Contains(ev.Detail, bs.ID) || strings.Contains(ev.Detail, bob.agentID) || strings.Contains(ev.Detail, bob.grantID) {
			t.Fatalf("event detail echoes a submitted id: %q", ev.Detail)
		}
	}
	if !e.hasEvent("u-alice", "ACCOUNT_ACTION_ERROR") {
		t.Fatal("refused attempts not audited")
	}
}

// withFreshLimits returns the same server over the same data with every rate
// limit counter empty, so a table of attacks is not cut short by the limiter.
func withFreshLimits(t *testing.T, e *conEnv) *Provider {
	t.Helper()
	cfg := e.h.cfg
	cfg.Store = &limiterReset{Store: e.st, Store2: memstore.New()}
	cfg.Sessions = &sessions.Service{Store: cfg.Store, Notifier: e.notify}
	return New(cfg)
}

type limiterReset struct {
	*memstore.Store
	Store2 *memstore.Store
}

func (l *limiterReset) HitRateLimit(ctx context.Context, key string, now time.Time, w time.Duration, max int) (bool, error) {
	return l.Store2.HitRateLimit(ctx, key, now, w, max)
}

// ---- CSRF ----

func TestAccountCSRF(t *testing.T) {
	e := newConEnv(t, conOpts{})
	alice := e.seed("u-alice", "alicemark")
	e.seed("u-bob", "bobmark")
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	a2 := e.visitor("UA2", "192.0.2.2")
	a2.signIn("alice", "alice-pass")
	bobB := e.visitor("UA3", "192.0.2.3")
	bobB.signIn("bob", "bob-pass")

	otherSession, bobTok := a2.csrf("sessions"), bobB.csrf("sessions")
	good := a.csrf("sessions")
	// A token valid for the login form is not valid here.
	login := e.h.newCSRF("r")
	forms := map[string][]url.Values{
		"sessions":     {{"action": {"revoke-others"}}, {"action": {"revoke"}, "sid": {a2.session().ID}}, {"action": {"reauth"}, "password": {"alice-pass"}}},
		"devices":      {{"action": {"forget-all"}}},
		"applications": {{"action": {"revoke"}, "grant_id": {alice.grantID}}},
		"agents":       {{"action": {"revoke-all"}, "agent_id": {alice.agentID}}},
		"password":     {{"action": {"change"}, "current": {"alice-pass"}, "password": {"new-password-1"}, "confirm": {"new-password-1"}}},
	}
	attacks := []struct {
		name, form, cookie string
	}{
		{"nothing", "", ""},
		{"no form token", "", good},
		{"no cookie", good, ""},
		{"mismatch", good, otherSession},
		{"forged pair", "a.b", "a.b"},
		{"pair from another session of the same user", otherSession, otherSession},
		{"pair from another user", bobTok, bobTok},
		{"login form token pair", login, login},
	}
	for slug, fs := range forms {
		for _, form := range fs {
			for _, at := range attacks {
				b := a.clone()
				delete(b.cookies, acctCSRFCookie)
				if at.cookie != "" {
					b.cookies[acctCSRFCookie] = &http.Cookie{Name: acctCSRFCookie, Value: at.cookie}
				}
				f := url.Values{}
				for k, v := range form {
					f[k] = v
				}
				if at.form != "" {
					f.Set("csrf", at.form)
				}
				e.h = withFreshLimits(t, e)
				w := b.do("POST", acctRoot+"/"+slug, f)
				if w.Code != 403 {
					t.Fatalf("%s %v with %s: %d %s", slug, form, at.name, w.Code, w.Body)
				}
				if b.cookies[acctReauthCookie] != nil {
					t.Fatalf("%s: re-auth cookie issued without CSRF", at.name)
				}
			}
		}
	}
	if len(e.sessionIDs("u-alice")) != 2 || !e.deviceKnown("u-alice", alice) || !e.grantActive(alice) ||
		!e.cred(alice).RevokedAt.IsZero() || e.user("u-alice").PasswordHash != "H:alice-pass" || len(e.notify.got()) != 0 {
		t.Fatal("a request without a valid CSRF token changed something")
	}
	// GET never changes anything, whatever it carries.
	for slug := range forms {
		a.do("GET", acctRoot+"/"+slug+"?action=revoke-others&csrf="+url.QueryEscape(good), nil)
	}
	if len(e.sessionIDs("u-alice")) != 2 {
		t.Fatal("GET changed state")
	}
}

// ---- re-authentication ----

func destructive(o owned, otherSID string) map[string][][]string {
	return map[string][][]string{
		"sessions":     {{"action", "revoke", "sid", otherSID}, {"action", "revoke-others"}},
		"devices":      {{"action", "forget", "device", deviceHandle("r", "u-alice", o.deviceHash)}, {"action", "forget-all"}},
		"applications": {{"action", "revoke", "grant_id", o.grantID}},
		"agents":       {{"action", "revoke", "agent_id", o.agentID, "credential_id", o.credID}, {"action", "revoke-all", "agent_id", o.agentID}},
		"password":     {{"action", "change", "current", "alice-pass", "password", "new-password-1", "confirm", "new-password-1"}},
	}
}

func TestAccountDestructiveActionsNeedRecentAuth(t *testing.T) {
	e := newConEnv(t, conOpts{})
	alice := e.seed("u-alice", "alicemark")
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	a2 := e.visitor("UA2", "192.0.2.2")
	other := a2.signIn("alice", "alice-pass")
	e.now = e.now.Add(acctFresh) // exactly at the limit counts as stale

	for slug, acts := range destructive(alice, other.ID) {
		body := a.get(slug)
		if !strings.Contains(body, "Confirm it is you") || !strings.Contains(body, `name="password"`) {
			t.Fatalf("%s: no confirmation panel", slug)
		}
		if got := regexp.MustCompile(`name="action" value="([^"]+)"`).FindAllStringSubmatch(body, -1); len(got) != 1 || got[0][1] != "reauth" {
			t.Fatalf("%s: stale page offers actions: %v", slug, got)
		}
		for _, kv := range acts {
			w := a.post(slug, kv...)
			e.wantStatus(w, 403, "Confirm it is you before making changes", slug+" "+kv[1])
		}
	}
	unchanged := func(what string) {
		t.Helper()
		if len(e.sessionIDs("u-alice")) != 2 || !e.deviceKnown("u-alice", alice) || !e.grantActive(alice) ||
			!e.cred(alice).RevokedAt.IsZero() || e.user("u-alice").PasswordHash != "H:alice-pass" || len(e.notify.got()) != 0 {
			t.Fatalf("%s: something changed", what)
		}
	}
	unchanged("stale")

	e.h = withFreshLimits(t, e)
	e.wantStatus(a.post("sessions", "action", "reauth", "password", "bob-pass"), 403, "not correct", "wrong password")
	if a.cookies[acctReauthCookie] != nil {
		t.Fatal("cookie after a wrong password")
	}
	w := a.post("sessions", "action", "reauth", "password", "alice-pass")
	e.wantRedirect(w, acctRoot+"/sessions?m=reauth", "reauth")
	ck := cookieNamed(w, acctReauthCookie)
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != acctRoot || ck.MaxAge != 600 {
		t.Fatalf("re-auth cookie %+v", ck)
	}

	// The confirmation belongs to this session only.
	stolen := a2.clone()
	stolen.cookies[acctReauthCookie] = a.cookies[acctReauthCookie]
	e.wantStatus(stolen.post("applications", "action", "revoke", "grant_id", alice.grantID), 403, "Confirm it is you", "other session")
	// Neither does a proof of another purpose signed by the same server.
	forged := a2.clone()
	forged.cookies[acctReauthCookie] = &http.Cookie{Name: acctReauthCookie,
		Value: e.h.signPending("r", "u-alice", "pk-reauth", a2.session().ID, time.Hour)}
	e.wantStatus(forged.post("applications", "action", "revoke", "grant_id", alice.grantID), 403, "Confirm it is you", "other purpose")
	forged.cookies[acctReauthCookie] = &http.Cookie{Name: acctReauthCookie,
		Value: e.h.signPending("r", "u-bob", acctReauthPurpose, a2.session().ID, time.Hour)}
	e.wantStatus(forged.post("applications", "action", "revoke", "grant_id", alice.grantID), 403, "Confirm it is you", "other user")
	unchanged("foreign proofs")

	// And it expires.
	later := e.now
	e.now = e.now.Add(acctFresh + time.Second)
	e.wantStatus(a.post("applications", "action", "revoke", "grant_id", alice.grantID), 403, "Confirm it is you", "expired proof")
	e.now = later
	e.wantRedirect(a.post("applications", "action", "revoke", "grant_id", alice.grantID), acctRoot+"/applications?m=app", "within the window")
	if e.grantActive(alice) {
		t.Fatal("grant not revoked")
	}
	if !e.hasEvent("u-alice", "ACCOUNT_REAUTH") || !e.hasEvent("u-alice", "ACCOUNT_REAUTH_ERROR") || !e.hasEvent("u-alice", "CONSENT_REVOKE") {
		t.Fatal("re-auth or revoke not audited")
	}
}

func (e *conEnv) enrollTOTP(user string) []byte {
	e.t.Helper()
	seed := totp.NewSeed()
	e.must(e.st.PutTOTP(context.Background(), core.TOTPCredential{Realm: "r", UserID: user, CreatedAt: e.now,
		SealedSeed: e.h.cfg.SecretBox.Seal(seed, sealContext("r", user))}))
	won, err := e.st.ConfirmTOTP(context.Background(), "r", user, 1)
	e.must(err)
	if !won {
		e.t.Fatal("not confirmed")
	}
	return seed
}

func TestAccountReauthNeedsSecondFactor(t *testing.T) {
	e := newConEnv(t, conOpts{})
	alice := e.seed("u-alice", "alicemark")
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	seed := e.enrollTOTP("u-alice")
	e.now = e.now.Add(time.Hour)
	if !strings.Contains(a.get("applications"), `name="code"`) {
		t.Fatal("confirmation does not ask for a code")
	}
	for name, code := range map[string]string{"no code": "", "wrong code": "000000"} {
		if code == totp.Code(seed, e.now) {
			continue
		}
		e.wantStatus(a.post("applications", "action", "reauth", "password", "alice-pass", "code", code), 403, "Invalid code", name)
		if a.cookies[acctReauthCookie] != nil {
			t.Fatalf("%s: confirmed without a valid code", name)
		}
	}
	// A right code with a wrong password is refused and the code is not spent.
	code := totp.Code(seed, e.now)
	e.wantStatus(a.post("applications", "action", "reauth", "password", "nope", "code", code), 403, "not correct", "wrong password")
	e.wantRedirect(a.post("applications", "action", "reauth", "password", "alice-pass", "code", code), acctRoot+"/applications?m=reauth", "password and code")
	e.wantRedirect(a.post("applications", "action", "revoke", "grant_id", alice.grantID), acctRoot+"/applications?m=app", "revoke")
}

func TestAccountReauthNeedsSignInForPasskeyAndPasswordlessUsers(t *testing.T) {
	for name, mut := range map[string]func(*conEnv){
		"passkey user": func(e *conEnv) {
			e.must(e.st.AddPasskey(context.Background(), core.Passkey{Realm: "r", UserID: "u-alice", CredentialID: "pk1",
				PublicKey: []byte{1}, Name: "k", CreatedAt: e.now}))
		},
		"no password": func(e *conEnv) {
			u := e.user("u-alice")
			u.PasswordHash = ""
			e.must(e.st.UpdateUser(context.Background(), u))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newConEnv(t, conOpts{})
			alice := e.seed("u-alice", "alicemark")
			a := e.visitor("UA1", "192.0.2.1")
			a.signIn("alice", "alice-pass")
			mut(e)
			// A fresh sign-in still counts.
			if !strings.Contains(a.get("agents"), `value="revoke"`) {
				t.Fatal("fresh session cannot act")
			}
			e.now = e.now.Add(time.Hour)
			body := a.get("agents")
			if strings.Contains(body, `name="password"`) || !strings.Contains(body, "sign in again") {
				t.Fatalf("password confirmation offered: %s", body)
			}
			e.wantStatus(a.post("agents", "action", "reauth", "password", "alice-pass"), 403, "Sign out and sign in again", "password reauth")
			if a.cookies[acctReauthCookie] != nil {
				t.Fatal("confirmed by password")
			}
			e.wantStatus(a.post("agents", "action", "revoke-all", "agent_id", alice.agentID), 403, "Confirm it is you", "revoke")
		})
	}
}

func TestAccountLockedUserCannotReauth(t *testing.T) {
	e := newConEnv(t, conOpts{})
	e.seed("u-alice", "alicemark")
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	e.now = e.now.Add(time.Hour)
	u := e.user("u-alice")
	u.LockedUntil = e.now.Add(time.Hour)
	e.must(e.st.UpdateUser(context.Background(), u))
	e.wantStatus(a.post("agents", "action", "reauth", "password", "alice-pass"), 403, "not correct", "locked")
}

// ---- rate limits ----

func TestAccountPasswordGuessingIsLimited(t *testing.T) {
	e := newConEnv(t, conOpts{})
	e.seed("u-alice", "alicemark")
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	e.now = e.now.Add(time.Hour)
	for i := range mfaUserMax {
		e.wantStatus(a.post("agents", "action", "reauth", "password", "guess"+strconv.Itoa(i)), 403, "not correct", "guess")
	}
	e.wantStatus(a.post("agents", "action", "reauth", "password", "alice-pass"), 429, "Too many attempts", "after the limit")
	// A second session or address of the same user shares the budget.
	a2 := e.visitor("UA2", "198.51.100.5")
	a2.signIn("alice", "alice-pass")
	e.wantStatus(a2.post("password", "action", "change", "current", "alice-pass", "password", "new-password-1", "confirm", "new-password-1"),
		429, "Too many attempts", "password change")
	if a.cookies[acctReauthCookie] != nil || e.user("u-alice").PasswordHash != "H:alice-pass" {
		t.Fatal("limit not enforced")
	}
	e.now = e.now.Add(mfaWindow + time.Second)
	e.wantRedirect(a.post("agents", "action", "reauth", "password", "alice-pass"), acctRoot+"/agents?m=reauth", "next window")
}

func TestAccountRequestLimits(t *testing.T) {
	t.Run("post per user", func(t *testing.T) {
		e := newConEnv(t, conOpts{})
		var last int
		// Different addresses: only the per-user counter can stop this.
		a := e.visitor("UA1", "192.0.2.1")
		a.signIn("alice", "alice-pass")
		tok := a.csrf("sessions")
		ck := *a.cookies[acctCSRFCookie]
		for i := range acctPostUserMax + 1 {
			a.cookies[acctCSRFCookie] = &ck // every answer sets a new one
			a.ip = "198.51.100." + strconv.Itoa(i)
			last = a.do("POST", acctRoot+"/sessions", url.Values{"csrf": {tok}, "action": {"bogus"}}).Code
			if i < acctPostUserMax && last != 400 {
				t.Fatalf("request %d: %d", i, last)
			}
		}
		if last != 429 {
			t.Fatalf("not limited: %d", last)
		}
	})
	t.Run("post per address, before any session lookup", func(t *testing.T) {
		e := newConEnv(t, conOpts{})
		a := e.visitor("UA1", "192.0.2.1")
		for i := range acctPostIPMax {
			if w := a.do("POST", acctRoot+"/sessions", url.Values{}); w.Code != 401 {
				t.Fatalf("request %d: %d", i, w.Code)
			}
		}
		w := a.do("POST", acctRoot+"/sessions", url.Values{})
		if w.Code != 429 || w.Header().Get("Retry-After") == "" {
			t.Fatalf("not limited: %d", w.Code)
		}
	})
	t.Run("get per user", func(t *testing.T) {
		e := newConEnv(t, conOpts{})
		a := e.visitor("UA1", "192.0.2.1")
		a.signIn("alice", "alice-pass")
		for range acctGetUserMax {
			a.get("security")
		}
		if w := a.do("GET", acctRoot+"/security", nil); w.Code != 429 {
			t.Fatalf("not limited: %d", w.Code)
		}
		b := e.visitor("UA2", "192.0.2.1")
		b.signIn("bob", "bob-pass")
		b.get("security") // another user is unaffected
	})
}

type brokenLimiter struct{ *memstore.Store }

func (brokenLimiter) HitRateLimit(_ context.Context, _ string, _ time.Time, _ time.Duration, _ int) (bool, error) {
	return true, errors.New("limiter down")
}

func TestAccountFailsClosedWhenLimiterBreaks(t *testing.T) {
	e := newConEnv(t, conOpts{store: func(s *memstore.Store) core.Store { return brokenLimiter{s} }})
	e.seed("u-alice", "alicemark")
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	for _, m := range []string{"GET", "POST"} {
		w := a.do(m, acctRoot+"/agents", nil)
		if w.Code != 503 || strings.Contains(w.Body.String(), "alicemark") {
			t.Fatalf("%s: %d %s", m, w.Code, w.Body)
		}
	}
}

// ---- sessions ----

func TestAccountSessions(t *testing.T) {
	e := newConEnv(t, conOpts{})
	a := e.visitor("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15", "192.0.2.1")
	cur := a.signIn("alice", "alice-pass")
	b2 := e.visitor("Mozilla/5.0 (Windows NT 10.0; Win64) Firefox/130.0", "198.51.100.2")
	s2 := b2.signIn("alice", "alice-pass")
	b3 := e.visitor("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) CriOS/120", "198.51.100.3")
	s3 := b3.signIn("alice", "alice-pass")
	b4 := e.visitor("curl/8.0", "198.51.100.4")
	s4 := b4.signIn("alice", "alice-pass")
	e.refresh("rt2", "u-alice", s2.ID, "openid")
	e.refresh("rt2off", "u-alice", s2.ID, "openid offline_access")
	e.refresh("rtcur", "u-alice", cur.ID, "openid")

	body := a.get("sessions")
	for _, want := range []string{"Safari on macOS", "Firefox on Windows", "Chrome on iPhone", "curl", "198.51.100.2", "Demo app", "This device"} {
		if !strings.Contains(body, want) {
			t.Errorf("sessions page lacks %q", want)
		}
	}
	if strings.Count(body, "This device</span>") != 1 || strings.Index(body, "This device</span>") > strings.Index(body, "Firefox on Windows") {
		t.Error("current session not marked once and listed first")
	}
	if strings.Contains(body, `name="sid" value="`+cur.ID+`"`) {
		t.Error("the current session has a revoke button")
	}
	e.wantStatus(a.post("sessions", "action", "revoke", "sid", cur.ID), 400, "Use Sign out", "own session")

	e.wantRedirect(a.post("sessions", "action", "revoke", "sid", s2.ID), acctRoot+"/sessions?m=session", "revoke one")
	if got := e.notify.got(); !slices.Equal(got, []string{s2.ID}) {
		t.Fatalf("back-channel logout for %v, want %s", got, s2.ID)
	}
	if !e.revoked("rt2") || e.revoked("rt2off") || e.revoked("rtcur") {
		t.Fatal("wrong refresh tokens revoked")
	}
	if w := b2.do("GET", acctRoot, nil); w.Code != 401 {
		t.Fatalf("revoked session still works: %d", w.Code)
	}
	if strings.Contains(a.get("sessions"), "Firefox on Windows") {
		t.Fatal("revoked session still listed")
	}

	e.wantRedirect(a.post("sessions", "action", "revoke-others"), acctRoot+"/sessions?m=sessions", "revoke others")
	want := []string{s2.ID, s3.ID, s4.ID}
	slices.Sort(want)
	if got := e.notify.got(); !slices.Equal(got, want) {
		t.Fatalf("back-channel logout for %v, want %v", got, want)
	}
	if got := e.sessionIDs("u-alice"); !slices.Equal(got, []string{cur.ID}) {
		t.Fatalf("remaining sessions %v", got)
	}
	a.get("") // still signed in
	if !e.hasEvent("u-alice", "ACCOUNT_SESSION_REVOKED") || !e.hasEvent("u-alice", "ACCOUNT_SESSIONS_REVOKED") {
		t.Fatal("not audited")
	}
}

// The real notifier delivers a logout token naming the ended session to the
// client that took part in it.
func TestAccountRevokeSendsBackchannelLogout(t *testing.T) {
	var mu sync.Mutex
	var tokens []string
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		tokens = append(tokens, r.PostFormValue("logout_token"))
		w.WriteHeader(200)
	}))
	defer rp.Close()
	var n *backchannel.Notifier
	e := newConEnv(t, conOpts{notif: func(st core.Store, clock func() time.Time) sessions.Notifier {
		n = backchannel.New(backchannel.Config{Store: st, Signer: fakeSigner{now: clock}, BaseURL: "https://idp.example",
			AllowPrivate: true, Clock: clock})
		return n
	}})
	cl, err := e.st.GetClientByClientID(context.Background(), "r", "app")
	e.must(err)
	cl.BackchannelLogoutURI = rp.URL + "/logout"
	e.must(e.st.UpdateClient(context.Background(), cl))
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	b2 := e.visitor("UA2", "192.0.2.2")
	s2 := b2.signIn("alice", "alice-pass")
	b3 := e.visitor("UA3", "192.0.2.3")
	s3 := b3.signIn("alice", "alice-pass")

	sids := func() []string {
		n.Drain()
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, tok := range tokens {
			parts := strings.Split(tok, ".")
			if len(parts) != 3 {
				t.Fatalf("not a token: %q", tok)
			}
			raw, err := base64.RawURLEncoding.DecodeString(parts[1])
			e.must(err)
			var c map[string]any
			e.must(json.Unmarshal(raw, &c))
			if c["sub"] != "u-alice" || c["aud"] != "app" || c["events"] == nil {
				t.Fatalf("claims %v", c)
			}
			out = append(out, c["sid"].(string))
		}
		slices.Sort(out)
		return out
	}
	e.wantRedirect(a.post("sessions", "action", "revoke", "sid", s2.ID), acctRoot+"/sessions?m=session", "revoke one")
	if got := sids(); !slices.Equal(got, []string{s2.ID}) {
		t.Fatalf("delivered %v", got)
	}
	e.wantRedirect(a.post("sessions", "action", "revoke-others"), acctRoot+"/sessions?m=sessions", "revoke others")
	want := []string{s2.ID, s3.ID}
	slices.Sort(want)
	if got := sids(); !slices.Equal(got, want) {
		t.Fatalf("delivered %v want %v", got, want)
	}
}

// ---- password ----

func TestAccountChangePassword(t *testing.T) {
	e := newConEnv(t, conOpts{})
	ctx := context.Background()
	a := e.visitor("UA1", "192.0.2.1")
	cur := a.signIn("alice", "alice-pass")
	b2 := e.visitor("UA2", "192.0.2.2")
	s2 := b2.signIn("alice", "alice-pass")
	bobB := e.visitor("UA3", "192.0.2.3")
	bs := bobB.signIn("bob", "bob-pass")
	e.refresh("rtcur", "u-alice", cur.ID, "openid")
	e.refresh("rtoff", "u-alice", "", "offline_access")
	e.refresh("rtbob", "u-bob", bs.ID, "openid")
	u := e.user("u-alice")
	u.PendingActions = []string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}
	e.must(e.st.UpdateUser(ctx, u))
	for _, purpose := range []string{core.ActionResetPassword, actions.ActionChangeEmail} {
		e.must(e.st.PutActionToken(ctx, core.ActionToken{TokenHash: "t-" + purpose, Realm: "r", UserID: "u-alice", Purpose: purpose,
			CreatedAt: e.now, ExpiresAt: e.now.Add(time.Hour)}))
	}
	oldCookie := a.clone()

	change := func(cur, pw, confirm string) *httptest.ResponseRecorder {
		e.now = e.now.Add(mfaWindow + time.Second) // a fresh guessing window each time
		if e.now.Sub(a.session().AuthTime) >= acctFresh {
			a.post("password", "action", "reauth", "password", "alice-pass")
		}
		return a.post("password", "action", "change", "current", cur, "password", pw, "confirm", confirm)
	}
	for _, tc := range []struct {
		name, cur, pw, confirm, text string
		status                       int
	}{
		{"wrong current", "nope", "new-password-1", "new-password-1", "not correct", 403},
		{"no current", "", "new-password-1", "new-password-1", "not correct", 403},
		{"mismatch", "alice-pass", "new-password-1", "new-password-2", "do not match", 400},
		{"empty", "alice-pass", "", "", "Enter a new password", 400},
		{"unchanged", "alice-pass", "alice-pass", "alice-pass", "must differ", 400},
		{"policy", "alice-pass", "short", "short", "not allowed", 400},
		{"too long", "alice-pass", strings.Repeat("a", 1025), strings.Repeat("a", 1025), "Enter a new password", 400},
	} {
		e.wantStatus(change(tc.cur, tc.pw, tc.confirm), tc.status, tc.text, tc.name)
		if got := e.user("u-alice").PasswordHash; got != "H:alice-pass" {
			t.Fatalf("%s: password changed", tc.name)
		}
	}
	if len(e.sessionIDs("u-alice")) != 2 || e.revoked("rtcur") || len(e.notify.got()) != 0 {
		t.Fatal("refused attempts had side effects")
	}

	w := change("alice-pass", "new-password-1", "new-password-1")
	e.wantRedirect(w, acctRoot+"/password?m=password", "change")
	e.h.Drain()
	u = e.user("u-alice")
	if u.PasswordHash != "H:new-password-1" || !slices.Equal(u.PendingActions, []string{"VERIFY_EMAIL"}) {
		t.Fatalf("user %+v", u)
	}
	if got := e.sessionIDs("u-alice"); !slices.Equal(got, []string{cur.ID}) {
		t.Fatalf("sessions %v", got)
	}
	if got := e.notify.got(); !slices.Equal(got, []string{s2.ID}) {
		t.Fatalf("back-channel logout for %v", got)
	}
	if !e.revoked("rtcur") || !e.revoked("rtoff") || e.revoked("rtbob") {
		t.Fatal("refresh tokens")
	}
	if got := e.sessionIDs("u-bob"); !slices.Equal(got, []string{bs.ID}) {
		t.Fatal("bob signed out")
	}
	for _, purpose := range []string{core.ActionResetPassword, actions.ActionChangeEmail} {
		if _, err := e.st.ConsumeActionToken(ctx, "t-"+purpose); !errors.Is(err, idp.ErrNotFound) {
			t.Fatalf("%s link survived: %v", purpose, err)
		}
	}
	// The cookie is new, the session (sid) is the same, the old cookie is dead.
	ck := cookieNamed(w, ssoCookie)
	if ck == nil || ck.Value == oldCookie.cookies[ssoCookie].Value || !ck.HttpOnly || !ck.Secure || ck.Path != "/realms/r" {
		t.Fatalf("cookie %+v", ck)
	}
	if a.session().ID != cur.ID {
		t.Fatal("session id changed")
	}
	if w := oldCookie.do("GET", acctRoot, nil); w.Code != 401 {
		t.Fatalf("old cookie still works: %d", w.Code)
	}
	if !strings.Contains(a.get("password"), "Change password") {
		t.Fatal("new cookie does not work")
	}
	m, found := e.outbox.Last("alice@example.test")
	if !found || !strings.Contains(m.Text, "your account page") || strings.Contains(m.Text, "new-password-1") || strings.Contains(m.Text, "http") {
		t.Fatalf("notification %v %q", found, m.Text)
	}
	if !e.hasEvent("u-alice", "UPDATE_PASSWORD") || !e.hasEvent("u-alice", "UPDATE_PASSWORD_ERROR") {
		t.Fatal("not audited")
	}
	for _, ev := range e.events("u-alice") {
		for _, s := range []string{"new-password", "alice-pass", "H:", "nope"} {
			if strings.Contains(ev.Detail, s) {
				t.Fatalf("event detail leaks %q: %q", s, ev.Detail)
			}
		}
	}
	// The new password signs in, the old one does not.
	e.visitor("UA4", "192.0.2.4").signIn("alice", "new-password-1")
}

type brokenRotate struct{ *memstore.Store }

func (brokenRotate) RotateSessionCookie(context.Context, string, string, string, string) error {
	return errors.New("rotate down")
}

// If the cookie cannot be replaced the current session ends instead.
func TestAccountChangePasswordEndsSessionWhenRotationFails(t *testing.T) {
	e := newConEnv(t, conOpts{store: func(s *memstore.Store) core.Store { return brokenRotate{s} }})
	a := e.visitor("UA1", "192.0.2.1")
	cur := a.signIn("alice", "alice-pass")
	w := a.post("password", "action", "change", "current", "alice-pass", "password", "new-password-1", "confirm", "new-password-1")
	e.wantStatus(w, 500, "Sign in again", "rotation failure")
	if len(e.sessionIDs("u-alice")) != 0 || !slices.Contains(e.notify.got(), cur.ID) || a.cookies[ssoCookie] != nil {
		t.Fatalf("session survived: %v %v", e.sessionIDs("u-alice"), e.notify.got())
	}
}

func TestAccountPasswordless(t *testing.T) {
	e := newConEnv(t, conOpts{})
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	u := e.user("u-alice")
	u.PasswordHash = ""
	e.must(e.st.UpdateUser(context.Background(), u))
	body := a.get("password")
	if strings.Contains(body, `name="current"`) || !strings.Contains(body, "no password") {
		t.Fatalf("form offered: %s", body)
	}
	e.wantStatus(a.post("password", "action", "change", "current", "", "password", "new-password-1", "confirm", "new-password-1"),
		409, "no password", "change")
	if e.user("u-alice").PasswordHash != "" {
		t.Fatal("password was set")
	}
}

// ---- devices, applications, agents ----

func TestAccountDevices(t *testing.T) {
	e := newConEnv(t, conOpts{})
	o1 := e.seed("u-alice", "one")
	st, _ := core.StoreAs[core.StepUpStore](e.st)
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass") // policy on: this browser is remembered
	body := a.get("devices")
	if strings.Count(body, "This browser</span>") != 1 || strings.Count(body, `name="device"`) != 2 {
		t.Fatalf("devices page: %s", body)
	}
	if strings.Contains(body, o1.deviceHash) || strings.Contains(body, a.cookies[deviceCookie].Value) {
		t.Fatal("page exposes a device hash or cookie")
	}
	e.wantRedirect(a.post("devices", "action", "forget", "device", deviceHandle("r", "u-alice", o1.deviceHash)), acctRoot+"/devices?m=device", "forget")
	if e.deviceKnown("u-alice", o1) {
		t.Fatal("device still known")
	}
	if l, _ := st.ListDevices(context.Background(), "r", "u-alice"); len(l) != 1 {
		t.Fatalf("%d devices", len(l))
	}
	e.wantRedirect(a.post("devices", "action", "forget-all"), acctRoot+"/devices?m=devices", "forget all")
	if l, _ := st.ListDevices(context.Background(), "r", "u-alice"); len(l) != 0 {
		t.Fatalf("%d devices", len(l))
	}
	if !e.hasEvent("u-alice", "ACCOUNT_DEVICE_REMOVED") || !e.hasEvent("u-alice", "ACCOUNT_DEVICES_REMOVED") {
		t.Fatal("not audited")
	}
	e.must(st.PutStepUpPolicy(context.Background(), "r", core.StepUpPolicy{}))
	if !strings.Contains(a.get("devices"), "does not remember devices") {
		t.Fatal("no note about the policy being off")
	}
}

func TestAccountApplicationsAndAgents(t *testing.T) {
	e := newConEnv(t, conOpts{})
	ctx := context.Background()
	o := e.seed("u-alice", "alicemark")
	e.must(e.st.PutRefreshToken(ctx, core.RefreshToken{TokenHash: "rtapp", FamilyID: "f", Realm: "r", ClientID: "alicemark-client",
		UserID: "u-alice", Scope: "openid offline_access", ExpiresAt: e.now.Add(time.Hour)}))
	as, _ := core.StoreAs[core.AgentStore](e.st)
	second, err := as.CreateAgentCredential(ctx, core.AgentCredential{Realm: "r", AgentID: o.agentID, SecretHash: HashSecret("two"),
		Note: "second", CreatedAt: e.now, ExpiresAt: e.now.Add(time.Hour)}, 5, e.now)
	e.must(err)
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")

	e.wantRedirect(a.post("applications", "action", "revoke", "grant_id", o.grantID), acctRoot+"/applications?m=app", "revoke app")
	if e.grantActive(o) || !e.revoked("rtapp") {
		t.Fatal("grant or refresh token survived")
	}
	if strings.Contains(a.get("applications"), "alicemark-appname") {
		t.Fatal("revoked grant still listed")
	}
	cs, _ := core.StoreAs[core.ConsentStore](e.st)
	rcs, err := cs.ListConsentReceipts(ctx, "r", "u-alice", 0, 0)
	e.must(err)
	if len(rcs) == 0 || rcs[len(rcs)-1].Type != core.ReceiptRevoke || rcs[len(rcs)-1].Actor != "u-alice" {
		t.Fatalf("receipts %+v", rcs)
	}

	body := a.get("agents")
	for _, want := range []string{"alicemark-agent", "alicemark-note", "second", "mcp:alicemark", o.credID, "Revoke all credentials"} {
		if !strings.Contains(body, want) {
			t.Errorf("agents page lacks %q", want)
		}
	}
	e.wantRedirect(a.post("agents", "action", "revoke", "agent_id", o.agentID, "credential_id", o.credID), acctRoot+"/agents?m=cred", "revoke cred")
	if c := e.cred(o); c.RevokedAt.IsZero() || c.RevokedBy != "user:u-alice" {
		t.Fatalf("cred %+v", c)
	}
	e.wantStatus(a.post("agents", "action", "revoke", "agent_id", o.agentID, "credential_id", o.credID), 409, "already ended", "again")
	if !strings.Contains(a.get("agents"), "Revoked") {
		t.Fatal("state not shown")
	}
	e.wantRedirect(a.post("agents", "action", "revoke-all", "agent_id", o.agentID), acctRoot+"/agents?m=creds", "revoke all")
	list, err := as.ListAgentCredentials(ctx, "r", o.agentID)
	e.must(err)
	for _, c := range list {
		if c.Active(e.now) {
			t.Fatalf("active credential left: %s (second=%s)", c.ID, second.ID)
		}
	}
	if !e.hasEvent("u-alice", "AGENT_CREDENTIAL_REVOKED") {
		t.Fatal("not audited")
	}
}

// ---- activity ----

func TestAccountActivity(t *testing.T) {
	e := newConEnv(t, conOpts{})
	ctx := context.Background()
	add := func(user, typ, ip, detail string) {
		e.must(e.st.AppendEvent(ctx, core.Event{Time: e.now, Realm: "r", Type: typ, UserID: user, ClientID: "app", IP: ip, Detail: detail}))
	}
	add("u-alice", "LOGIN_ERROR", "203.0.113.5", "invalid_credentials detail-must-not-show")
	add("u-alice", "ADMIN_CREATE", "203.0.113.6", "user mallory")
	add("u-alice", "AGENT_TOKEN", "203.0.113.7", "agent=x")
	add("u-alice", "TOTP_RESET", "", "admin")
	add("u-bob", "UPDATE_PASSWORD", "203.0.113.8", "")
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	// A noisy realm must not push the user's events out.
	for range 300 {
		add("u-bob", "LOGIN", "203.0.113.9", "")
	}
	body := a.get("activity")
	for _, want := range []string{"Failed sign-in attempt", "203.0.113.5", "Signed in to an application", "reset by an administrator"} {
		if !strings.Contains(body, want) {
			t.Errorf("lacks %q", want)
		}
	}
	for _, bad := range []string{"detail-must-not-show", "mallory", "203.0.113.6", "203.0.113.7", "203.0.113.8", "203.0.113.9", "Password changed"} {
		if strings.Contains(body, bad) {
			t.Errorf("shows %q", bad)
		}
	}
	e.realm.AuthEventsLogged = false
	e.must(e.st.UpdateRealm(ctx, e.realm))
	if !strings.Contains(a.get("activity"), "does not currently record") {
		t.Error("no note when events are off")
	}
}

// ---- links from other pages ----

func TestAccountLinksFromOtherPages(t *testing.T) {
	e := newConEnv(t, conOpts{})
	a := e.visitor("UA1", "192.0.2.1")
	a.signIn("alice", "alice-pass")
	// Relative links must resolve to the console.
	resolve := func(page, href string) string {
		u, err := url.Parse(page)
		e.must(err)
		r, err := u.Parse(href)
		e.must(err)
		return r.Path
	}
	for _, page := range []string{base + "logout", acctRoot + "/totp", acctRoot + "/passkeys", acctRoot + "/email", acctRoot + "/consents"} {
		w := a.do("GET", page, nil)
		m := regexp.MustCompile(`<a href="([./a-z]*account)">(?:Manage your account instead|Back to your account)</a>`).FindStringSubmatch(w.Body.String())
		if w.Code != 200 || m == nil {
			t.Fatalf("%s: %d, no link", page, w.Code)
		}
		if got := resolve(page, m[1]); got != acctRoot {
			t.Errorf("%s: link resolves to %s", page, got)
		}
	}
	for _, render := range []func(w http.ResponseWriter){
		func(w http.ResponseWriter) {
			e.h.deviceRender(w, e.realm, 200, deviceView{Title: "t", Mode: "done", Approved: true})
		},
		func(w http.ResponseWriter) {
			e.h.cibaRender(w, e.realm, 200, cibaView{Title: "t", Mode: "done", Approved: true})
		},
	} {
		w := httptest.NewRecorder()
		render(w)
		if !strings.Contains(w.Body.String(), `href="`+acctRoot+`/activity"`) {
			t.Errorf("done page lacks the account link: %s", w.Body)
		}
	}
}

func TestUASummary(t *testing.T) {
	for ua, want := range map[string]string{
		"":          "Unknown browser",
		"something": "Unknown browser",
		"Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36":          "Chrome on Linux",
		"Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537 Edg/120":         "Edge on Windows",
		"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) Version/17 Safari/604": "Safari on iPad",
		"Mozilla/5.0 (Linux; Android 14) Firefox/130":                         "Firefox on Android",
		"Mozilla/5.0 (Windows NT 10.0)":                                       "Browser on Windows",
	} {
		if got := uaSummary(ua); got != want {
			t.Errorf("%q: %q want %q", ua, got, want)
		}
	}
}
