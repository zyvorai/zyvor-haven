// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

const cibaAuthPath = "/realms/r/protocol/openid-connect/ext/ciba/auth"

type cenv struct {
	t   *testing.T
	st  *memstore.Store
	h   *Provider
	box *mail.Outbox
	now time.Time
	mu  sync.Mutex
}

type cibaOpts struct {
	noMail   bool
	wrap     func(core.Store) core.Store
	mutRealm func(*core.Realm)
}

func newCEnv(t *testing.T, o cibaOpts) *cenv {
	t.Helper()
	e := &cenv{t: t, st: memstore.New(), box: mail.NewOutbox(100), now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	c := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	rl := core.Realm{Name: "r", Enabled: true, BruteForceProtection: true, AuthEventsLogged: true,
		AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour, DisplayName: "Acme"}
	if o.mutRealm != nil {
		o.mutRealm(&rl)
	}
	must(e.st.CreateRealm(c, rl))
	mk := func(id, name string, mut func(*core.Client)) {
		x := core.Client{Realm: "r", ClientID: id, Name: name, Enabled: true, SecretHash: HashSecret("s3cret")}
		if mut != nil {
			mut(&x)
		}
		must(e.st.CreateClient(c, x))
		got, err := e.st.GetClientByClientID(c, "r", id)
		must(err)
		must(e.st.SetCIBAClient(c, "r", got.ID, id != "plain"))
	}
	mk("agent", "Shopping agent", nil)
	mk("agent2", "Other agent", nil)
	mk("plain", "Not opted in", nil)
	mk("pub", "Public one", func(x *core.Client) { x.Public, x.SecretHash = true, "" })
	mk("xss", "<script>alert(1)</script>\r\nBcc: evil@x", nil)
	for _, u := range []core.User{
		{ID: "u1", Realm: "r", Username: "alice", Email: "alice@x.example", Enabled: true, EmailVerified: true, PasswordHash: "H:pw"},
		{ID: "u2", Realm: "r", Username: "bob", Enabled: true, EmailVerified: true, PasswordHash: "H:pw"}, // no email
		{ID: "u3", Realm: "r", Username: "carol", Email: "carol@x.example", Enabled: false, EmailVerified: true, PasswordHash: "H:pw"},
		{ID: "u4", Realm: "r", Username: "dave", Email: "dave@x.example", Enabled: true, EmailVerified: true, PasswordHash: "H:pw"},
	} {
		must(e.st.CreateUser(c, u))
	}
	var st core.Store = e.st
	if o.wrap != nil {
		st = o.wrap(st)
	}
	clock := func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
	cfg := Config{Store: st, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{}, BaseURL: idpBase, Clock: clock,
		CSRFKey: []byte("0123456789abcdef0123456789abcdef")}
	if !o.noMail {
		cfg.Actions = &actions.Service{Store: e.st, Mailer: e.box, BaseURL: idpBase, Clock: clock}
	}
	e.h = New(cfg)
	return e
}

func (e *cenv) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

func (e *cenv) do(method, target string, form url.Values, client, secret, ip string) (*httptest.ResponseRecorder, map[string]any) {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	if client != "" {
		req.SetBasicAuth(client, secret)
	}
	if ip == "" {
		ip = "203.0.113.50"
	}
	req.RemoteAddr = ip + ":1"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

// start posts a backchannel authentication request as the confidential client.
func (e *cenv) start(hint string, extra url.Values) (int, map[string]any) {
	return e.startAs("agent", hint, extra)
}

func (e *cenv) startAs(client, hint string, extra url.Values) (int, map[string]any) {
	f := url.Values{"scope": {"openid profile"}, "login_hint": {hint}}
	for k, v := range extra {
		f[k] = v
	}
	w, out := e.do("POST", cibaAuthPath, f, client, "s3cret", "")
	return w.Code, out
}

func (e *cenv) mustStart(hint string, extra url.Values) string {
	e.t.Helper()
	c, out := e.start(hint, extra)
	if c != 200 {
		e.t.Fatalf("ciba start: %d %v", c, out)
	}
	return out["auth_req_id"].(string)
}

func (e *cenv) poll(client, id string) (int, map[string]any) {
	w, out := e.do("POST", base+"token", url.Values{"grant_type": {cibaGrant}, "auth_req_id": {id}}, client, "s3cret", "")
	return w.Code, out
}

var cibaLinkRe = regexp.MustCompile(`https://idp\.example/realms/r/ciba/approve\?req=[A-Za-z0-9_%-]+`)

// link returns the approval link mailed to addr (after in-flight mail is done).
func (e *cenv) link(addr string) string {
	e.t.Helper()
	e.h.Drain()
	m, ok := e.box.Last(addr)
	if !ok {
		e.t.Fatalf("no mail to %s", addr)
	}
	l := cibaLinkRe.FindString(m.Text)
	if l == "" {
		e.t.Fatalf("no approval link in %q", m.Text)
	}
	return l
}

func tokenOf(link string) string {
	u, _ := url.Parse(link)
	return u.Query().Get("req")
}

type cbrowser struct {
	e       *cenv
	cookies map[string]*http.Cookie
}

func (e *cenv) browser() *cbrowser { return &cbrowser{e: e, cookies: map[string]*http.Cookie{}} }

func (b *cbrowser) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	b.e.t.Helper()
	target = strings.TrimPrefix(target, idpBase)
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.RemoteAddr = "198.51.100.7:4444"
	for _, c := range b.cookies {
		if strings.HasPrefix(req.URL.Path, c.Path) {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	w := httptest.NewRecorder()
	b.e.h.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		k := c.Name + "|" + c.Path
		if c.MaxAge < 0 {
			delete(b.cookies, k)
		} else {
			b.cookies[k] = c
		}
	}
	return w
}

func (b *cbrowser) cookie(name string) string {
	for _, c := range b.cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// open follows an approval link into the login, signs in and lands on the
// approval page.
func (b *cbrowser) open(link, user, pw string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	w := b.do("GET", link, nil)
	if w.Code != http.StatusSeeOther {
		b.e.t.Fatalf("expected redirect into login, got %d: %s", w.Code, w.Body)
	}
	return b.loginAt(w.Header().Get("Location"), user, pw)
}

func (b *cbrowser) loginAt(loc, user, pw string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	if !strings.HasPrefix(loc, idpBase+base+"auth?") || !strings.Contains(loc, "client_id=haven-ciba") || !strings.Contains(loc, "prompt=login") {
		b.e.t.Fatalf("login redirect: %s", loc)
	}
	w := b.do("GET", loc, nil)
	if w.Code != 200 {
		b.e.t.Fatalf("login page: %d %s", w.Code, w.Body)
	}
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		b.e.t.Fatalf("no login form: %s", w.Body)
	}
	w = b.do("POST", loc, url.Values{"username": {user}, "password": {pw}, "csrf": {m[1]}})
	if w.Code != http.StatusFound {
		return w
	}
	next := w.Header().Get("Location")
	if !strings.HasPrefix(next, idpBase+"/realms/r/ciba/continue?") {
		b.e.t.Fatalf("post-login redirect: %s", next)
	}
	return b.do("GET", next, nil)
}

func (b *cbrowser) decide(token, decision string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	return b.do("POST", "/realms/r/ciba/approve", url.Values{"csrf": {b.cookie(cibaCSRFCookie)}, "req": {token}, "decision": {decision}})
}

func cerr(out map[string]any) string { s, _ := out["error"].(string); return s }

// ---- tests ----

func TestCIBAFullFlow(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	id := e.mustStart("alice", url.Values{"binding_message": {"Buy 3 books for 42 EUR"},
		"resource": {"https://shop.example/api", "https://pay.example/v1", "https://shop.example/api"}})
	if c, out := e.poll("agent", id); c != 400 || cerr(out) != "authorization_pending" {
		t.Fatalf("first poll: %d %v", c, out)
	}
	e.h.Drain()
	m, ok := e.box.Last("alice@x.example")
	if !ok || !strings.Contains(m.Text, "Shopping agent") || !strings.Contains(m.Text, "Buy 3 books for 42 EUR") ||
		!strings.Contains(m.Text, "https://pay.example/v1") || strings.Contains(m.Subject, "\n") {
		t.Fatalf("mail: %+v", m)
	}
	if strings.Contains(m.Text, id) {
		t.Fatal("the mail must not contain the auth_req_id")
	}
	link := e.link("alice@x.example")

	b := e.browser()
	page := b.open(link, "alice", "pw")
	body := page.Body.String()
	if page.Code != 200 {
		t.Fatalf("approval page: %d %s", page.Code, body)
	}
	for _, want := range []string{"Shopping agent", "Buy 3 books for 42 EUR", "https://shop.example/api", "https://pay.example/v1",
		"See your name and profile", "Confirm who you are", "alice", "203.0.113.50", "UTC", "Approve", "Deny", "Only approve if"} {
		if !strings.Contains(body, want) {
			t.Errorf("approval page lacks %q", want)
		}
	}
	if strings.Count(body, "https://shop.example/api") != 1 {
		t.Error("duplicate resources must be shown once")
	}
	if c, out := e.poll("agent", id); c != 400 || (cerr(out) != "authorization_pending" && cerr(out) != "slow_down") {
		t.Fatalf("poll before decision: %d %v", c, out)
	}
	done := b.decide(tokenOf(link), "approve")
	if done.Code != 200 || !strings.Contains(done.Body.String(), "You approved") {
		t.Fatalf("decision: %d %s", done.Code, done.Body)
	}
	e.advance(30 * time.Second)
	c, out := e.poll("agent", id)
	if c != 200 {
		t.Fatalf("token poll: %d %v", c, out)
	}
	if _, has := out["refresh_token"]; has {
		t.Error("a refresh token was issued")
	}
	sess, err := e.st.ListSessions(context.Background(), "r", "u1", 10)
	if err != nil || len(sess) != 1 {
		t.Fatalf("sessions: %v %v", sess, err)
	}
	at, idc := claimsOf(t, out["access_token"].(string)), claimsOf(t, out["id_token"].(string))
	if at["sub"] != "u1" || at["aud"] != "agent" || at["sid"] != sess[0].ID || idc["sub"] != "u1" || idc["azp"] != "agent" ||
		int64(idc["auth_time"].(float64)) != sess[0].AuthTime.Unix() {
		t.Fatalf("claims: at=%v id=%v", at, idc)
	}
	if out["scope"] != "openid profile" {
		t.Errorf("scope %v", out["scope"])
	}
	// Single use.
	if c, out := e.poll("agent", id); c != 400 || cerr(out) != "invalid_grant" {
		t.Fatalf("replay: %d %v", c, out)
	}
	// Audit: the right events, no secrets.
	evs, _ := e.st.ListEvents(context.Background(), "r", 100)
	seen := map[string]bool{}
	for _, ev := range evs {
		seen[ev.Type] = true
		blob := ev.Detail + ev.IP + ev.ClientID + ev.UserID
		if strings.Contains(blob, id) || strings.Contains(blob, tokenOf(link)) || strings.Contains(blob, "Buy 3 books") {
			t.Errorf("event %s leaks: %+v", ev.Type, ev)
		}
	}
	for _, typ := range []string{"CIBA_AUTH_REQUEST", "CIBA_APPROVE", "CIBA_TOKEN"} {
		if !seen[typ] {
			t.Errorf("no %s event (have %v)", typ, seen)
		}
	}
}

func TestCIBADeny(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	id := e.mustStart("alice", nil)
	link := e.link("alice@x.example")
	b := e.browser()
	b.open(link, "alice", "pw")
	if w := b.decide(tokenOf(link), "deny"); w.Code != 200 || !strings.Contains(w.Body.String(), "You denied") {
		t.Fatalf("deny: %d %s", w.Code, w.Body)
	}
	e.advance(10 * time.Second)
	if c, out := e.poll("agent", id); c != 400 || cerr(out) != "access_denied" {
		t.Fatalf("poll: %d %v", c, out)
	}
	// A denial cannot be flipped, and a second decision is "not valid".
	if w := b.decide(tokenOf(link), "approve"); w.Code != 400 || !strings.Contains(w.Body.String(), "not valid") {
		t.Fatalf("re-decide: %d %s", w.Code, w.Body)
	}
	e.advance(10 * time.Second)
	if _, out := e.poll("agent", id); cerr(out) != "access_denied" {
		t.Fatalf("approved after denial: %v", out)
	}
}

func TestCIBASlowDownAndExpiry(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	c, out := e.start("alice", url.Values{"requested_expiry": {"30"}})
	if c != 200 || out["expires_in"] != float64(30) || out["interval"] != float64(5) {
		t.Fatalf("start: %d %v", c, out)
	}
	id := out["auth_req_id"].(string)
	if c, out := e.poll("agent", id); cerr(out) != "authorization_pending" {
		t.Fatalf("%d %v", c, out)
	}
	e.advance(time.Second)
	c, out = e.poll("agent", id)
	if c != 400 || cerr(out) != "slow_down" {
		t.Fatalf("fast poll: %d %v", c, out)
	}
	e.advance(7 * time.Second) // interval is now 10, last poll 7s ago
	if _, out = e.poll("agent", id); cerr(out) != "slow_down" || !strings.Contains(out["error_description"].(string), "15 seconds") {
		t.Fatalf("interval did not grow: %v", out)
	}
	e.advance(16 * time.Second) // interval is now 15
	if _, out = e.poll("agent", id); cerr(out) != "authorization_pending" {
		t.Fatalf("%v", out)
	}
	// Expired: poll says expired_token and the approval link is dead.
	link := e.link("alice@x.example")
	e.advance(time.Minute)
	if _, out = e.poll("agent", id); cerr(out) != "expired_token" {
		t.Fatalf("after expiry: %v", out)
	}
	b := e.browser()
	if w := b.do("GET", link, nil); w.Code != 400 || !strings.Contains(w.Body.String(), "not valid") {
		t.Fatalf("expired link: %d %s", w.Code, w.Body)
	}
}

func TestCIBANoUserEnumeration(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	type res struct {
		code int
		out  map[string]any
	}
	got := map[string]res{}
	for _, h := range []string{"alice", "nobody", "bob" /* no email */, "carol" /* disabled */, "ghost@x.example"} {
		c, out := e.start(h, nil)
		got[h] = res{c, out}
	}
	shape := func(r res) string {
		keys := ""
		for _, k := range []string{"auth_req_id", "expires_in", "interval"} {
			if _, ok := r.out[k]; ok {
				keys += k + ","
			}
		}
		return keys + "|" + formatNum(r.out["expires_in"]) + "|" + formatNum(r.out["interval"]) + "|" + strings.Repeat("x", len(r.out["auth_req_id"].(string)))
	}
	want := shape(got["alice"])
	for h, r := range got {
		if r.code != 200 || shape(r) != want {
			t.Errorf("hint %q answers differently: %d %v", h, r.code, r.out)
		}
	}
	e.h.Drain()
	if n := len(e.box.Messages()); n != 1 {
		t.Fatalf("expected exactly one mail (alice), got %d", n)
	}
	// Every request polls as pending, resolved or not.
	for h, r := range got {
		e.advance(6 * time.Second)
		if c, out := e.poll("agent", r.out["auth_req_id"].(string)); c != 400 || cerr(out) != "authorization_pending" {
			t.Errorf("hint %q polls %d %v", h, c, out)
		}
	}
	// The per-hint limit trips alike for a real and an unknown user (and is
	// case-insensitive on the hint).
	for _, h := range []string{"alice", "nobody"} {
		var last int
		for i := 0; i < 6; i++ {
			last, _ = e.start(strings.ToUpper(h[:1])+h[1:], nil)
		}
		if last != 429 {
			t.Errorf("hint %q: sixth request answered %d, want 429", h, last)
		}
	}
	// An email hint resolves to the same user.
	e2 := newCEnv(t, cibaOpts{})
	e2.mustStart("Alice@X.example", nil)
	e2.h.Drain()
	if _, ok := e2.box.Last("alice@x.example"); !ok {
		t.Error("email login_hint did not reach alice")
	}
}

func formatNum(v any) string { f, _ := v.(float64); return strings.Repeat("n", int(f)) }

func TestCIBAMailRateLimitPerUser(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	// Different hints for the same user dodge the per-hint limit; the per-user
	// email cap still holds, and the answers stay identical.
	hints := []string{"alice", "ALICE", "alice@x.example", "Alice@x.example", "alice ", " alice", "aLiCe", "alice@X.example"}
	for _, h := range hints {
		if c, out := e.start(h, nil); c != 200 && c != 429 {
			t.Fatalf("%q: %d %v", h, c, out)
		}
	}
	e.h.Drain()
	if n := len(e.box.Messages()); n > cibaMailPerUser || n == 0 {
		t.Fatalf("mails sent: %d (cap %d)", n, cibaMailPerUser)
	}
}

func TestCIBAClientRules(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	// Wrong secret: authentication fails before anything else is said.
	w, out := e.do("POST", cibaAuthPath, url.Values{"scope": {"openid"}, "login_hint": {"alice"}}, "agent", "nope", "")
	if w.Code != 401 || cerr(out) != "invalid_client" {
		t.Fatalf("bad secret: %d %v", w.Code, out)
	}
	w, out = e.do("POST", cibaAuthPath, url.Values{"scope": {"openid"}, "login_hint": {"alice"}}, "", "", "")
	if w.Code != 401 {
		t.Fatalf("no auth: %d %v", w.Code, out)
	}
	// Not opted in, and public clients, are unauthorized even when valid.
	if c, out := e.startAs("plain", "alice", nil); c != 400 || cerr(out) != "unauthorized_client" {
		t.Errorf("plain: %d %v", c, out)
	}
	w, out = e.do("POST", cibaAuthPath, url.Values{"scope": {"openid"}, "login_hint": {"alice"}, "client_id": {"pub"}}, "", "", "")
	if w.Code != 400 || cerr(out) != "unauthorized_client" {
		t.Errorf("public: %d %v", w.Code, out)
	}
	e.h.Drain()
	if len(e.box.Messages()) != 0 {
		t.Fatal("mail sent for an unauthorized client")
	}
	// An auth_req_id belongs to its client.
	id := e.mustStart("alice", nil)
	e.advance(6 * time.Second)
	if c, out := e.poll("agent2", id); c != 400 || cerr(out) != "invalid_grant" {
		t.Fatalf("other client polls: %d %v", c, out)
	}
	if c, out := e.poll("agent", "garbage"); c != 400 || cerr(out) != "invalid_grant" {
		t.Fatalf("unknown id: %d %v", c, out)
	}
	// The grant needs the opt-in as well: switching it off ends polling and
	// kills the approval link.
	link := e.link("alice@x.example")
	cl, _ := e.st.GetClientByClientID(context.Background(), "r", "agent")
	if err := e.st.SetCIBAClient(context.Background(), "r", cl.ID, false); err != nil {
		t.Fatal(err)
	}
	e.advance(6 * time.Second)
	if c, out := e.poll("agent", id); c != 400 || cerr(out) != "unauthorized_client" {
		t.Fatalf("poll after opt-out: %d %v", c, out)
	}
	if w := e.browser().do("GET", link, nil); w.Code != 400 {
		t.Fatalf("link after opt-out: %d", w.Code)
	}
	// A public client cannot use the token grant either.
	w, out = e.do("POST", base+"token", url.Values{"grant_type": {cibaGrant}, "auth_req_id": {id}, "client_id": {"pub"}}, "", "", "")
	if w.Code != 400 || cerr(out) != "unauthorized_client" {
		t.Fatalf("public grant: %d %v", w.Code, out)
	}
}

func TestCIBARequestValidation(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	long := strings.Repeat("a", cibaMaxBinding+1)
	cases := []struct {
		name  string
		extra url.Values
		hint  string
		want  string
	}{
		{"no hint", nil, "", "invalid_request"},
		{"hint too long", nil, strings.Repeat("a", cibaMaxHint+1), "invalid_request"},
		{"login_hint_token", url.Values{"login_hint_token": {"x"}}, "alice", "invalid_request"},
		{"id_token_hint", url.Values{"id_token_hint": {"x"}}, "alice", "invalid_request"},
		{"user_code", url.Values{"user_code": {"1234"}}, "alice", "invalid_request"},
		{"request object", url.Values{"request": {"x"}}, "alice", "invalid_request"},
		{"no openid", url.Values{"scope": {"profile"}}, "alice", "invalid_scope"},
		{"unknown scope", url.Values{"scope": {"openid admin"}}, "alice", "invalid_scope"},
		{"offline_access", url.Values{"scope": {"openid offline_access"}}, "alice", "invalid_scope"},
		{"binding newline", url.Values{"binding_message": {"hi\nBcc: x"}}, "alice", "invalid_binding_message"},
		{"binding bidi override", url.Values{"binding_message": {"pay \u202eBob"}}, "alice", "invalid_binding_message"},
		{"binding too long", url.Values{"binding_message": {long}}, "alice", "invalid_binding_message"},
		{"resource javascript", url.Values{"resource": {"javascript:alert(1)"}}, "alice", "invalid_target"},
		{"resource relative", url.Values{"resource": {"/api"}}, "alice", "invalid_target"},
		{"resource fragment", url.Values{"resource": {"https://a.example/x#f"}}, "alice", "invalid_target"},
		{"resource userinfo", url.Values{"resource": {"https://u:p@a.example/x"}}, "alice", "invalid_target"},
		{"resource newline", url.Values{"resource": {"https://a.example/x\nBcc: y"}}, "alice", "invalid_target"},
		{"too many resources", url.Values{"resource": {"https://a/1", "https://a/2", "https://a/3", "https://a/4", "https://a/5", "https://a/6"}}, "alice", "invalid_target"},
		{"expiry zero", url.Values{"requested_expiry": {"0"}}, "alice", "invalid_request"},
		{"expiry too big", url.Values{"requested_expiry": {"601"}}, "alice", "invalid_request"},
		{"expiry text", url.Values{"requested_expiry": {"soon"}}, "alice", "invalid_request"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.advance(time.Duration(i+1) * 11 * time.Minute) // fresh rate-limit windows
			c, out := e.start(tc.hint, tc.extra)
			if tc.hint == "" {
				c, out = e.start("", tc.extra)
			}
			if c != 400 || cerr(out) != tc.want {
				t.Fatalf("%d %v, want %s", c, out, tc.want)
			}
		})
	}
	e.h.Drain()
	if len(e.box.Messages()) != 0 {
		t.Fatal("a rejected request sent mail")
	}
	// Boundary cases that must pass.
	e.advance(time.Hour)
	if c, out := e.start("alice", url.Values{"binding_message": {strings.Repeat("é", cibaMaxBinding)}, "requested_expiry": {"600"}}); c != 200 {
		t.Fatalf("boundary: %d %v", c, out)
	}
}

func TestCIBAApproverMustBeAddressee(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	id := e.mustStart("alice", nil)
	link := e.link("alice@x.example")
	tok := tokenOf(link)

	// Not signed in: redirected into login.
	anon := e.browser()
	if w := anon.do("GET", link, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("anonymous GET: %d", w.Code)
	}
	// Dave signs in with Alice's link: no approval page, no decision possible.
	dave := e.browser()
	w := dave.open(link, "dave", "pw")
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "Approve") {
		t.Fatalf("wrong user got the approval page: %d %s", w.Code, w.Body)
	}
	// Dave hand-crafts the POST with a CSRF token he legitimately has.
	e.mustStart("dave", nil)
	dlink := e.link("dave@x.example")
	if p := dave.do("GET", dlink, nil); p.Code != 200 {
		t.Fatalf("dave's own page: %d", p.Code)
	}
	w = dave.do("POST", "/realms/r/ciba/approve", url.Values{"csrf": {dave.cookie(cibaCSRFCookie)}, "req": {tok}, "decision": {"approve"}})
	if w.Code != http.StatusForbidden {
		t.Fatalf("dave decided alice's request: %d %s", w.Code, w.Body)
	}
	e.advance(10 * time.Second)
	if c, out := e.poll("agent", id); cerr(out) != "authorization_pending" {
		t.Fatalf("request moved: %d %v", c, out)
	}
	// Alice herself can.
	a := e.browser()
	if p := a.open(link, "alice", "pw"); p.Code != 200 {
		t.Fatalf("alice page: %d", p.Code)
	}
	if w := a.decide(tok, "approve"); w.Code != 200 {
		t.Fatalf("alice decision: %d %s", w.Code, w.Body)
	}
}

func TestCIBAStaleSessionForcesLogin(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	e.mustStart("alice", url.Values{"requested_expiry": {"600"}})
	link := e.link("alice@x.example")
	b := e.browser()
	if p := b.open(link, "alice", "pw"); p.Code != 200 {
		t.Fatalf("page: %d", p.Code)
	}
	e.advance(cibaAuthFresh + time.Minute) // SSO session alive (idle 30 min default), authentication stale
	w := b.do("GET", link, nil)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "prompt=login") {
		t.Fatalf("stale session must re-login: %d %s", w.Code, w.Header().Get("Location"))
	}
	// A decision posted from the old page is bounced to login, not applied.
	w = b.decide(tokenOf(link), "approve")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("stale decision: %d %s", w.Code, w.Body)
	}
	cs, _ := core.StoreAs[core.CIBAStore](e.st)
	row, err := cs.GetCIBAByApproval(context.Background(), "r", HashSecret(tokenOf(link)))
	if err != nil || row.Status != core.CIBAPending {
		t.Fatalf("row after stale decision: %+v %v", row, err)
	}
	// Re-login works.
	if p := b.loginAt(w.Header().Get("Location"), "alice", "pw"); p.Code != 200 {
		t.Fatalf("after re-login: %d %s", p.Code, p.Body)
	}
}

func TestCIBAApprovalPageSecurity(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	e.mustStartAs(t, "xss", "alice", url.Values{"binding_message": {`<img src=x onerror=alert(1)>"'`}})
	e.h.Drain()
	m, _ := e.box.Last("alice@x.example")
	if strings.ContainsAny(m.Subject, "\r\n") || strings.Contains(m.Subject+m.Text, "\nBcc:") || strings.Contains(m.Subject, "Bcc") && strings.Contains(m.Subject, "\n") {
		t.Fatalf("header injection through the client name: %q", m.Subject)
	}
	link := e.link("alice@x.example")
	b := e.browser()
	w := b.open(link, "alice", "pw")
	body := w.Body.String()
	if strings.Contains(body, "<script>") || strings.Contains(body, "<img src=x") {
		t.Fatalf("unescaped markup on the approval page: %s", body)
	}
	if !strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Errorf("binding message not shown escaped")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "nonce-") || w.Header().Get("Cache-Control") != "no-store" ||
		w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("headers: %v", w.Header())
	}
	nonce := regexp.MustCompile(`<style nonce="([^"]+)"`).FindStringSubmatch(body)
	if nonce == nil || !strings.Contains(csp, "nonce-"+nonce[1]) {
		t.Error("CSP nonce does not match the page")
	}
}

func (e *cenv) mustStartAs(t *testing.T, client, hint string, extra url.Values) string {
	t.Helper()
	c, out := e.startAs(client, hint, extra)
	if c != 200 {
		t.Fatalf("start: %d %v", c, out)
	}
	return out["auth_req_id"].(string)
}

func TestCIBACSRFAndDecisionValidation(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	e.mustStart("alice", nil)
	link := e.link("alice@x.example")
	tok := tokenOf(link)
	b := e.browser()
	b.open(link, "alice", "pw")
	csrf := b.cookie(cibaCSRFCookie)
	post := func(f url.Values, cookie bool) int {
		req := httptest.NewRequest("POST", "/realms/r/ciba/approve", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "198.51.100.7:1"
		for _, c := range b.cookies {
			if c.Name == cibaCSRFCookie && !cookie {
				continue
			}
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		return w.Code
	}
	// No/forged/mismatched CSRF never decides anything.
	if c := post(url.Values{"req": {tok}, "decision": {"approve"}}, true); c != 403 {
		t.Errorf("no csrf field: %d", c)
	}
	if c := post(url.Values{"csrf": {csrf}, "req": {tok}, "decision": {"approve"}}, false); c != 403 {
		t.Errorf("no csrf cookie: %d", c)
	}
	if c := post(url.Values{"csrf": {"forged"}, "req": {tok}, "decision": {"approve"}}, true); c != 403 {
		t.Errorf("forged csrf: %d", c)
	}
	other := e.newCSRFFor()
	if c := post(url.Values{"csrf": {other}, "req": {tok}, "decision": {"approve"}}, true); c != 403 {
		t.Errorf("valid-but-mismatched csrf: %d", c)
	}
	if c := post(url.Values{"csrf": {csrf}, "req": {tok}, "decision": {"maybe"}}, true); c != 400 {
		t.Errorf("bad decision: %d", c)
	}
	if c := post(url.Values{"csrf": {csrf}, "req": {"wrong"}, "decision": {"approve"}}, true); c != 400 {
		t.Errorf("wrong token: %d", c)
	}
	cs, _ := core.StoreAs[core.CIBAStore](e.st)
	row, _ := cs.GetCIBAByApproval(context.Background(), "r", HashSecret(tok))
	if row.Status != core.CIBAPending {
		t.Fatalf("a rejected request changed the row: %+v", row)
	}
	// The correct one works, exactly once.
	if c := post(url.Values{"csrf": {csrf}, "req": {tok}, "decision": {"approve"}}, true); c != 200 {
		t.Errorf("good decision: %d", c)
	}
	if c := post(url.Values{"csrf": {csrf}, "req": {tok}, "decision": {"deny"}}, true); c != 400 {
		t.Errorf("second decision: %d", c)
	}
}

func (e *cenv) newCSRFFor() string { return e.h.newCSRF("r") }

func TestCIBAApprovalLookupRateLimit(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	b := e.browser()
	var last int
	for i := 0; i < cibaLookupPerIP+1; i++ {
		last = b.do("GET", "/realms/r/ciba/approve?req=guess"+strings.Repeat("a", i%5), nil).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("guessing the approval token is not rate limited: %d", last)
	}
}

func TestCIBASessionEndedBeforePoll(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	id := e.mustStart("alice", nil)
	link := e.link("alice@x.example")
	b := e.browser()
	b.open(link, "alice", "pw")
	b.decide(tokenOf(link), "approve")
	sess, _ := e.st.ListSessions(context.Background(), "r", "u1", 10)
	if _, err := e.h.sessions().End(context.Background(), "r", sess[0].ID); err != nil {
		t.Fatal(err)
	}
	e.advance(10 * time.Second)
	if c, out := e.poll("agent", id); c != 400 || cerr(out) != "invalid_grant" {
		t.Fatalf("tokens issued for an ended session: %d %v", c, out)
	}
}

func TestCIBAUserDisabledAfterApproval(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	id := e.mustStart("alice", nil)
	link := e.link("alice@x.example")
	b := e.browser()
	b.open(link, "alice", "pw")
	b.decide(tokenOf(link), "approve")
	u, _ := e.st.GetUser(context.Background(), "r", "u1")
	u.Enabled = false
	if err := e.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	e.advance(10 * time.Second)
	if c, out := e.poll("agent", id); c != 400 || cerr(out) != "invalid_grant" {
		t.Fatalf("tokens for a disabled user: %d %v", c, out)
	}
}

func TestCIBAForgedLoginState(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	e.mustStart("alice", nil)
	link := e.link("alice@x.example")
	b := e.browser()
	b.open(link, "alice", "pw")
	for _, st := range []string{"", "garbage", "a.b", e.h.signPending("r", "", "device-login", tokenOf(link), time.Minute)} {
		w := b.do("GET", "/realms/r/ciba/continue?state="+url.QueryEscape(st), nil)
		if w.Code != 400 || strings.Contains(w.Body.String(), "Approve") {
			t.Errorf("state %q: %d", st, w.Code)
		}
	}
	// A state signed for another realm is rejected too.
	w := b.do("GET", "/realms/r/ciba/continue?error=access_denied&state="+url.QueryEscape(e.h.signPending("r", "", cibaStatePurpose, tokenOf(link), time.Minute)), nil)
	if w.Code != 400 {
		t.Errorf("error return: %d", w.Code)
	}
}

func TestCIBAFailsClosed(t *testing.T) {
	t.Run("no mail transport", func(t *testing.T) {
		e := newCEnv(t, cibaOpts{noMail: true})
		c, out := e.start("alice", nil)
		if c != 501 || cerr(out) != "feature_unavailable" {
			t.Fatalf("%d %v", c, out)
		}
		if c, out := e.poll("agent", "x"); c != 501 {
			t.Fatalf("grant: %d %v", c, out)
		}
		if w := e.browser().do("GET", "/realms/r/ciba/approve?req=x", nil); w.Code != 501 {
			t.Fatalf("approve page: %d", w.Code)
		}
		w, _ := e.do("GET", "/realms/r/.well-known/openid-configuration", nil, "", "", "")
		if strings.Contains(w.Body.String(), "backchannel_authentication_endpoint") || strings.Contains(w.Body.String(), "ciba") {
			t.Error("discovery advertises CIBA without mail")
		}
		// The built-in login client is not available either.
		w, _ = e.do("GET", "/realms/r/protocol/openid-connect/auth?client_id=haven-ciba&response_type=code&redirect_uri="+
			url.QueryEscape(idpBase+"/realms/r/ciba/continue")+"&state=x&code_challenge="+strings.Repeat("A", 43)+"&code_challenge_method=S256", nil, "", "", "")
		if w.Code != 400 {
			t.Fatalf("pseudo client without CIBA: %d", w.Code)
		}
	})
	t.Run("store without CIBA", func(t *testing.T) {
		e := newCEnv(t, cibaOpts{wrap: func(s core.Store) core.Store { return struct{ core.Store }{s} }})
		if c, out := e.start("alice", nil); c != 501 {
			t.Fatalf("%d %v", c, out)
		}
	})
	t.Run("discovery when on", func(t *testing.T) {
		e := newCEnv(t, cibaOpts{})
		w, _ := e.do("GET", "/realms/r/.well-known/openid-configuration", nil, "", "", "")
		var doc map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &doc)
		if doc["backchannel_authentication_endpoint"] != idpBase+"/realms/r"+oidcPath+"/ext/ciba/auth" ||
			doc["backchannel_user_code_parameter_supported"] != false {
			t.Fatalf("discovery: %v", doc)
		}
		modes, _ := doc["backchannel_token_delivery_modes_supported"].([]any)
		if len(modes) != 1 || modes[0] != "poll" {
			t.Fatalf("modes: %v", modes)
		}
		found := false
		for _, g := range doc["grant_types_supported"].([]any) {
			found = found || g == cibaGrant
		}
		if !found {
			t.Fatal("grant type missing from discovery")
		}
	})
}

func TestCIBAUnknownRealmAndMethod(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	w, _ := e.do("POST", "/realms/nope/protocol/openid-connect/ext/ciba/auth", url.Values{"login_hint": {"a"}}, "agent", "s3cret", "")
	if w.Code != 404 {
		t.Fatalf("unknown realm: %d", w.Code)
	}
	w, _ = e.do("GET", cibaAuthPath, nil, "agent", "s3cret", "")
	if w.Code != 405 {
		t.Fatalf("GET: %d", w.Code)
	}
}

func TestCIBAStartRateLimitPerIP(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	var last int
	for i := 0; i < cibaStartPerIP+1; i++ {
		w, _ := e.do("POST", cibaAuthPath, url.Values{"scope": {"openid"}, "login_hint": {"u" + strings.Repeat("x", i)}}, "agent", "s3cret", "198.51.100.99")
		last = w.Code
	}
	if last != 429 {
		t.Fatalf("per-IP limit: %d", last)
	}
}
