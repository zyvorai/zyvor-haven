// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

const idpBase = "https://idp.example"

type denv struct {
	t   *testing.T
	st  *memstore.Store
	h   *Provider
	now time.Time
	mu  sync.Mutex
}

type devOpts struct {
	realm func(*core.Realm)
	store func(core.Store) core.Store // wrap the store handed to the provider
}

func newDEnv(t *testing.T, o devOpts) *denv {
	t.Helper()
	e := &denv{t: t, st: memstore.New(), now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	c := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	rl := core.Realm{Name: "r", Enabled: true, BruteForceProtection: true, RefreshTokenRotation: true,
		AuthEventsLogged: true, AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour}
	if o.realm != nil {
		o.realm(&rl)
	}
	must(e.st.CreateRealm(c, rl))
	must(e.st.CreateRealm(c, core.Realm{Name: "other", Enabled: true, AuthEventsLogged: true}))
	cl := func(id, name string, mut func(*core.Client)) {
		x := core.Client{Realm: "r", ClientID: id, Name: name, Enabled: true, Public: true, DeviceFlow: true}
		if mut != nil {
			mut(&x)
		}
		must(e.st.CreateClient(c, x))
	}
	cl("cli", "Haven CLI", nil)
	cl("conf", "Build agent", func(x *core.Client) { x.Public, x.SecretHash = false, HashSecret("s3cret") })
	cl("plain", "No device flow", func(x *core.Client) { x.DeviceFlow = false })
	cl("xss", `<script>alert(1)</script>"><img src=x onerror=alert(2)>`, nil)
	must(e.st.CreateClient(c, core.Client{Realm: "r", ClientID: "app", Enabled: true, Public: true, AuthCodeFlow: true,
		RedirectURIs: []string{cb}}))
	must(e.st.CreateUser(c, core.User{ID: "u1", Realm: "r", Username: "alice", Email: "a@x", Enabled: true,
		EmailVerified: true, PasswordHash: "H:pw", Roles: []string{"admin"}}))
	must(e.st.CreateUser(c, core.User{ID: "u9", Realm: "other", Username: "bob", Enabled: true, PasswordHash: "H:pw"}))
	clock := func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
	var st core.Store = e.st
	if o.store != nil {
		st = o.store(st)
	}
	e.h = New(Config{Store: st, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{}, BaseURL: idpBase, Clock: clock,
		CSRFKey: []byte("0123456789abcdef0123456789abcdef")})
	return e
}

func (e *denv) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

// browser is a minimal cookie-keeping client that talks straight to the handler.
type browser struct {
	e       *denv
	ip, ua  string
	cookies map[string]*http.Cookie // name|path
}

func (e *denv) browser() *browser {
	return &browser{e: e, ip: "198.51.100.7", ua: "Mozilla/5.0 test", cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	b.e.t.Helper()
	target = strings.TrimPrefix(target, idpBase)
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.RemoteAddr = b.ip + ":4444"
	req.Header.Set("User-Agent", b.ua)
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

func (b *browser) cookie(name string) *http.Cookie {
	for _, c := range b.cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ---- device client (the "CLI") ----

type devGrant struct {
	DeviceCode, UserCode, VerificationURI, VerificationURIComplete string
	ExpiresIn, Interval                                            int
}

const devPath = "/realms/r/protocol/openid-connect/auth/device"

func (e *denv) post(path string, form url.Values, ip, user, pass string, ua ...string) (int, map[string]any, http.Header) {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(ua) > 0 {
		req.Header.Set("User-Agent", ua[0])
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	if ip == "" {
		ip = "203.0.113.50"
	}
	req.RemoteAddr = ip + ":1"
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Header()
}

func (e *denv) start(client, scope string) devGrant {
	e.t.Helper()
	code, out, _ := e.post(devPath, url.Values{"client_id": {client}, "scope": {scope}}, "", "", "")
	if code != 200 {
		e.t.Fatalf("device authorization: %d %v", code, out)
	}
	g := devGrant{DeviceCode: out["device_code"].(string), UserCode: out["user_code"].(string),
		VerificationURI: out["verification_uri"].(string), VerificationURIComplete: out["verification_uri_complete"].(string),
		ExpiresIn: int(out["expires_in"].(float64)), Interval: int(out["interval"].(float64))}
	return g
}

func (e *denv) poll(client, deviceCode string) (int, map[string]any) {
	c, out, _ := e.post(base+"token", url.Values{"grant_type": {deviceGrant}, "device_code": {deviceCode}, "client_id": {client}}, "", "", "")
	return c, out
}

func errOf(out map[string]any) string { s, _ := out["error"].(string); return s }

// approveThroughLogin drives the browser: open the verification URL, sign in
// through the normal login, land on the approval page. It returns that page.
func (b *browser) openAndLogin(g devGrant, user, pw string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	w := b.do("GET", g.VerificationURIComplete, nil)
	if w.Code != http.StatusSeeOther {
		b.e.t.Fatalf("expected redirect into login, got %d: %s", w.Code, w.Body)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, idpBase+base+"auth?") || !strings.Contains(loc, "client_id=haven-device") {
		b.e.t.Fatalf("login redirect: %s", loc)
	}
	return b.loginAt(loc, user, pw)
}

// loginAt completes the standard login form at an /auth URL and follows the
// redirect back to the device page.
func (b *browser) loginAt(authURL, user, pw string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	w := b.do("GET", authURL, nil)
	if w.Code != 200 {
		b.e.t.Fatalf("login page: %d %s", w.Code, w.Body)
	}
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		b.e.t.Fatalf("no login form: %s", w.Body)
	}
	w = b.do("POST", authURL, url.Values{"username": {user}, "password": {pw}, "csrf": {m[1]}})
	if w.Code != http.StatusFound {
		return w // login failed or an extra step was shown
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, idpBase+"/realms/r/device/continue?") {
		b.e.t.Fatalf("post-login redirect: %s", loc)
	}
	return b.do("GET", loc, nil)
}

var devCSRFRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (b *browser) decide(userCode, decision string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	ck := b.cookie(deviceCSRFCookie)
	if ck == nil {
		b.e.t.Fatal("no device csrf cookie")
	}
	return b.do("POST", "/realms/r/device", url.Values{"csrf": {ck.Value}, "user_code": {userCode}, "decision": {decision}})
}

const notValidText = "not valid, has expired, or was already used"

// ---- tests ----

func TestDeviceFullFlow(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid profile email")
	if g.ExpiresIn != 600 || g.Interval != 5 || g.VerificationURI != idpBase+"/realms/r/device" ||
		g.VerificationURIComplete != g.VerificationURI+"?user_code="+g.UserCode {
		t.Fatalf("grant: %+v", g)
	}
	if !regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`).MatchString(g.UserCode) {
		t.Fatalf("user code %q", g.UserCode)
	}
	if c, out := e.poll("cli", g.DeviceCode); c != 400 || errOf(out) != "authorization_pending" {
		t.Fatalf("first poll: %d %v", c, out)
	}

	b := e.browser()
	page := b.openAndLogin(g, "alice", "pw")
	body := page.Body.String()
	if page.Code != 200 {
		t.Fatalf("approval page: %d %s", page.Code, body)
	}
	for _, want := range []string{"Haven CLI", g.UserCode, "203.0.113.50" /* the CLI's IP, not the browser's */, "Only approve if you started this on your own device",
		"Confirm who you are", "See your name and profile", "See your email address", "UTC", "alice", "Approve", "Deny"} {
		if !strings.Contains(body, want) {
			t.Errorf("approval page lacks %q", want)
		}
	}
	if strings.Contains(body, "long-lived") {
		t.Error("offline_access shown although not requested")
	}
	if c, out := e.poll("cli", g.DeviceCode); c != 400 || (errOf(out) != "authorization_pending" && errOf(out) != "slow_down") {
		t.Fatalf("poll before decision: %d %v", c, out)
	}
	done := b.decide(g.UserCode, "approve")
	if done.Code != 200 || !strings.Contains(done.Body.String(), "You approved the sign-in") || done.Header().Get("Location") != "" {
		t.Fatalf("final page: %d %s", done.Code, done.Body)
	}

	e.advance(30 * time.Second)
	c, out := e.poll("cli", g.DeviceCode)
	if c != 200 {
		t.Fatalf("token poll: %d %v", c, out)
	}
	sess, err := e.st.ListSessions(context.Background(), "r", "u1", 10)
	if err != nil || len(sess) != 1 {
		t.Fatalf("sessions: %v %v", sess, err)
	}
	for _, k := range []string{"access_token", "id_token", "refresh_token"} {
		if s, _ := out[k].(string); s == "" {
			t.Errorf("no %s", k)
		}
	}
	idc := claimsOf(t, out["id_token"].(string))
	atc := claimsOf(t, out["access_token"].(string))
	if idc["sid"] != sess[0].ID || atc["sid"] != sess[0].ID {
		t.Errorf("sid: id=%v at=%v want %s", idc["sid"], atc["sid"], sess[0].ID)
	}
	if int64(idc["auth_time"].(float64)) != sess[0].AuthTime.Unix() {
		t.Errorf("auth_time %v want %v", idc["auth_time"], sess[0].AuthTime.Unix())
	}
	if idc["sub"] != "u1" || idc["aud"] != "cli" || idc["azp"] != "cli" || idc["email"] != "a@x" || idc["iss"] != idpBase+"/realms/r" {
		t.Errorf("id token claims: %v", idc)
	}
	if out["scope"] != "openid profile email" {
		t.Errorf("scope %v", out["scope"])
	}
	// The session knows the device client (back-channel logout / revocation).
	found := false
	for _, cl := range sess[0].Clients {
		found = found || cl == "cli"
	}
	if !found {
		t.Errorf("session clients %v lack cli", sess[0].Clients)
	}

	// Single use: replay is invalid_grant, and so is a second poll.
	if c, out := e.poll("cli", g.DeviceCode); c != 400 || errOf(out) != "invalid_grant" {
		t.Fatalf("replay: %d %v", c, out)
	}
	// The issued refresh token works for the device client (it has no code flow).
	rc, rout, _ := e.post(base+"token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {out["refresh_token"].(string)}, "client_id": {"cli"}}, "", "", "")
	if rc != 200 || rout["access_token"] == nil {
		t.Fatalf("refresh: %d %v", rc, rout)
	}
	// Events, none with secrets.
	evs, _ := e.st.ListEvents(context.Background(), "r", 100)
	seen := map[string]bool{}
	for _, ev := range evs {
		seen[ev.Type] = true
		blob := ev.Detail + ev.IP + ev.ClientID + ev.UserID
		if strings.Contains(blob, g.DeviceCode) || strings.Contains(blob, g.UserCode) || strings.Contains(blob, strings.ReplaceAll(g.UserCode, "-", "")) {
			t.Errorf("event %s leaks a code: %+v", ev.Type, ev)
		}
	}
	for _, typ := range []string{"DEVICE_AUTH_REQUEST", "DEVICE_APPROVE", "DEVICE_TOKEN"} {
		if !seen[typ] {
			t.Errorf("no %s event (have %v)", typ, seen)
		}
	}
}

func TestDeviceOfflineAccessAndSessionEnd(t *testing.T) {
	for _, offline := range []bool{false, true} {
		t.Run(fmt.Sprintf("offline=%v", offline), func(t *testing.T) {
			e := newDEnv(t, devOpts{})
			scope := "openid"
			if offline {
				scope = "openid offline_access"
			}
			g := e.start("cli", scope)
			b := e.browser()
			page := b.openAndLogin(g, "alice", "pw")
			if offline != strings.Contains(page.Body.String(), "long-lived") {
				t.Errorf("offline_access wording shown=%v", !offline)
			}
			b.decide(g.UserCode, "approve")
			e.advance(10 * time.Second)
			c, out := e.poll("cli", g.DeviceCode)
			if c != 200 {
				t.Fatalf("%d %v", c, out)
			}
			rt := out["refresh_token"].(string)
			sess, _ := e.st.ListSessions(context.Background(), "r", "u1", 10)
			if _, err := e.h.sessions().End(context.Background(), "r", sess[0].ID); err != nil {
				t.Fatal(err)
			}
			rc, rout, _ := e.post(base+"token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"cli"}}, "", "", "")
			if offline && rc != 200 { // same rule as the code flow: offline tokens outlive the session
				t.Fatalf("offline refresh after session end: %d %v", rc, rout)
			}
			if !offline && (rc != 400 || errOf(rout) != "invalid_grant") {
				t.Fatalf("online refresh token survived the session: %d %v", rc, rout)
			}
		})
	}
}

func TestDeviceSessionEndedBeforePoll(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(g, "alice", "pw")
	b.decide(g.UserCode, "approve")
	sess, _ := e.st.ListSessions(context.Background(), "r", "u1", 10)
	if _, err := e.h.sessions().End(context.Background(), "r", sess[0].ID); err != nil {
		t.Fatal(err)
	}
	e.advance(10 * time.Second)
	if c, out := e.poll("cli", g.DeviceCode); c != 400 || errOf(out) != "invalid_grant" {
		t.Fatalf("tokens issued for an ended session: %d %v", c, out)
	}
}

func TestDeviceDeny(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(g, "alice", "pw")
	w := b.decide(g.UserCode, "deny")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "You denied") {
		t.Fatalf("deny page: %d %s", w.Code, w.Body)
	}
	e.advance(10 * time.Second)
	for i := 0; i < 2; i++ {
		if c, out := e.poll("cli", g.DeviceCode); c != 400 || errOf(out) != "access_denied" {
			t.Fatalf("poll %d: %d %v", i, c, out)
		}
		e.advance(10 * time.Second)
	}
	// A denied code cannot be flipped to approved.
	w = b.decide(g.UserCode, "approve")
	if w.Code != 400 || !strings.Contains(w.Body.String(), notValidText) {
		t.Fatalf("re-decide: %d %s", w.Code, w.Body)
	}
	if c, out := e.poll("cli", g.DeviceCode); errOf(out) != "access_denied" {
		t.Fatalf("approved after deny: %d %v", c, out)
	}
}

func TestDeviceApprovedCannotBeDenied(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(g, "alice", "pw")
	b.decide(g.UserCode, "approve")
	if w := b.decide(g.UserCode, "deny"); w.Code != 400 {
		t.Fatalf("re-decide: %d", w.Code)
	}
	e.advance(10 * time.Second)
	if c, out := e.poll("cli", g.DeviceCode); c != 200 {
		t.Fatalf("approval lost: %d %v", c, out)
	}
}

func TestDeviceExpiry(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(g, "alice", "pw") // sign in so we can try to decide later
	e.advance(10*time.Minute + time.Second)
	if c, out := e.poll("cli", g.DeviceCode); c != 400 || errOf(out) != "expired_token" {
		t.Fatalf("poll after expiry: %d %v", c, out)
	}
	if w := b.decide(g.UserCode, "approve"); w.Code != 400 || !strings.Contains(w.Body.String(), notValidText) {
		t.Fatalf("approve after expiry: %d %s", w.Code, w.Body)
	}
	if w := b.do("GET", g.VerificationURIComplete, nil); w.Code != 400 {
		t.Fatalf("verification page after expiry: %d", w.Code)
	}
	// Approved but never collected, then expired: expired_token, not tokens.
	g2 := e.start("cli", "openid")
	b.do("GET", g2.VerificationURIComplete, nil)
	b2 := e.browser()
	b2.openAndLogin(g2, "alice", "pw")
	b2.decide(g2.UserCode, "approve")
	e.advance(11 * time.Minute)
	if c, out := e.poll("cli", g2.DeviceCode); c != 400 || errOf(out) != "expired_token" {
		t.Fatalf("approved-then-expired: %d %v", c, out)
	}
	ds, _ := core.StoreAs[core.DeviceStore](e.st)
	if n, err := ds.PurgeExpiredDeviceCodes(context.Background(), e.h.now()); err != nil || n != 2 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if c, out := e.poll("cli", g.DeviceCode); errOf(out) != "invalid_grant" {
		t.Fatalf("after purge: %d %v", c, out)
	}
}

func TestDeviceSlowDown(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	if _, out := e.poll("cli", g.DeviceCode); errOf(out) != "authorization_pending" {
		t.Fatalf("first: %v", out)
	}
	e.advance(2 * time.Second)
	c, out := e.poll("cli", g.DeviceCode)
	if c != 400 || errOf(out) != "slow_down" {
		t.Fatalf("fast poll: %d %v", c, out)
	}
	ds, _ := core.StoreAs[core.DeviceStore](e.st)
	d, err := ds.GetDeviceCodeByUserCode(context.Background(), "r", userCodeHash(strings.ReplaceAll(g.UserCode, "-", "")))
	if err != nil || d.Interval != 10 {
		t.Fatalf("interval after slow_down: %+v %v", d, err)
	}
	// Respecting the old 5s interval is no longer enough; the new 10s is.
	e.advance(6 * time.Second)
	if _, out := e.poll("cli", g.DeviceCode); errOf(out) != "slow_down" {
		t.Fatalf("5s-interval poll after slow_down: %v", out)
	}
	e.advance(16 * time.Second) // the interval is 15s by now
	if _, out := e.poll("cli", g.DeviceCode); errOf(out) != "authorization_pending" {
		t.Fatalf("after waiting: %v", out)
	}
}

func TestDeviceWrongClientAndUnknownCode(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(g, "alice", "pw")
	b.decide(g.UserCode, "approve")
	e.advance(10 * time.Second)

	// Another (valid, device-enabled) client presents cli's device code: must be
	// indistinguishable from an unknown code, and must not consume it.
	c1, other, _ := e.post(base+"token", url.Values{"grant_type": {deviceGrant}, "device_code": {g.DeviceCode}}, "", "conf", "s3cret")
	c2, unknown, _ := e.post(base+"token", url.Values{"grant_type": {deviceGrant}, "device_code": {"definitely-not-a-real-device-code-0123456789"}}, "", "conf", "s3cret")
	if c1 != 400 || c2 != 400 || errOf(other) != "invalid_grant" || fmt.Sprint(other) != fmt.Sprint(unknown) {
		t.Fatalf("wrong client %d %v vs unknown %d %v", c1, other, c2, unknown)
	}
	// Same through the public-client route (client_id in the form).
	e.advance(time.Minute)
	if c, out := e.poll("app", g.DeviceCode); c != 400 || errOf(out) != "unauthorized_client" { // app has no device flow
		t.Fatalf("app: %d %v", c, out)
	}
	// The owner still gets its tokens.
	if c, out := e.poll("cli", g.DeviceCode); c != 200 {
		t.Fatalf("owner poll after foreign attempts: %d %v", c, out)
	}
	// A foreign poll must not have moved the owner's poll bookkeeping.
	g2 := e.start("cli", "openid")
	e.post(base+"token", url.Values{"grant_type": {deviceGrant}, "device_code": {g2.DeviceCode}}, "", "conf", "s3cret")
	if _, out := e.poll("cli", g2.DeviceCode); errOf(out) != "authorization_pending" {
		t.Fatalf("foreign poll triggered slow_down for the owner: %v", out)
	}
	// Missing device_code.
	if c, out := e.poll("cli", ""); c != 400 || errOf(out) != "invalid_request" {
		t.Fatalf("empty: %d %v", c, out)
	}
}

func TestDeviceFlagOff(t *testing.T) {
	e := newDEnv(t, devOpts{})
	code, out, _ := e.post(devPath, url.Values{"client_id": {"plain"}}, "", "", "")
	if code != 400 || errOf(out) != "unauthorized_client" {
		t.Fatalf("start with flag off: %d %v", code, out)
	}
	code, out, _ = e.post(base+"token", url.Values{"grant_type": {deviceGrant}, "device_code": {"x"}, "client_id": {"plain"}}, "", "", "")
	if code != 400 || errOf(out) != "unauthorized_client" {
		t.Fatalf("grant with flag off: %d %v", code, out)
	}
	// Switching the flag off after the request was made kills it everywhere.
	g := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(g, "alice", "pw")
	cl, _ := e.st.GetClientByClientID(context.Background(), "r", "cli")
	cl.DeviceFlow = false
	if err := e.st.UpdateClient(context.Background(), cl); err != nil {
		t.Fatal(err)
	}
	if w := b.decide(g.UserCode, "approve"); w.Code != 400 {
		t.Fatalf("approve for a client that lost the flag: %d", w.Code)
	}
	e.advance(10 * time.Second)
	if c, out := e.poll("cli", g.DeviceCode); c != 400 || errOf(out) != "unauthorized_client" {
		t.Fatalf("poll after flag off: %d %v", c, out)
	}
	// Disabled client: invalid_client at the device endpoint.
	cl.DeviceFlow, cl.Enabled = true, false
	_ = e.st.UpdateClient(context.Background(), cl)
	if code, out, _ := e.post(devPath, url.Values{"client_id": {"cli"}}, "", "", ""); code != 401 || errOf(out) != "invalid_client" {
		t.Fatalf("disabled client: %d %v", code, out)
	}
}

func TestDeviceAuthorizeErrors(t *testing.T) {
	e := newDEnv(t, devOpts{})
	cases := []struct {
		name         string
		form         url.Values
		user, pass   string
		status       int
		errCode      string
		wantAuthHdr  bool
		unknownRealm bool
	}{
		{"unknown client", url.Values{"client_id": {"nope"}}, "", "", 401, "invalid_client", false, false},
		{"no client", url.Values{}, "", "", 401, "invalid_client", false, false},
		{"bad scope", url.Values{"client_id": {"cli"}, "scope": {"openid admin"}}, "", "", 400, "invalid_scope", false, false},
		{"confidential without secret", url.Values{"client_id": {"conf"}}, "", "", 401, "invalid_client", false, false},
		{"confidential wrong secret", url.Values{"client_id": {"conf"}, "client_secret": {"x"}}, "", "", 401, "invalid_client", false, false},
		{"confidential wrong basic", url.Values{}, "conf", "x", 401, "invalid_client", true, false},
		{"public client with a secret", url.Values{"client_id": {"cli"}, "client_secret": {"x"}}, "", "", 401, "invalid_client", false, false},
	}
	for _, c := range cases {
		code, out, h := e.post(devPath, c.form, "", c.user, c.pass)
		if code != c.status || errOf(out) != c.errCode || (c.wantAuthHdr && h.Get("WWW-Authenticate") == "") {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
		if h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", c.name, h.Get("Cache-Control"))
		}
	}
	// Confidential client: Basic and form secret both work; default scope is openid.
	for name, f := range map[string]func() (int, map[string]any){
		"basic": func() (int, map[string]any) {
			c, o, _ := e.post(devPath, url.Values{}, "", "conf", "s3cret")
			return c, o
		},
		"post": func() (int, map[string]any) {
			c, o, _ := e.post(devPath, url.Values{"client_id": {"conf"}, "client_secret": {"s3cret"}}, "", "", "")
			return c, o
		},
	} {
		if c, o := f(); c != 200 || o["device_code"] == nil {
			t.Errorf("%s: %d %v", name, c, o)
		}
	}
	// Unknown realm.
	req := httptest.NewRequest("POST", "/realms/nope/protocol/openid-connect/auth/device", strings.NewReader("client_id=cli"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("unknown realm: %d", w.Code)
	}
}

func TestDeviceConfidentialClientFlow(t *testing.T) {
	e := newDEnv(t, devOpts{})
	code, out, _ := e.post(devPath, url.Values{"scope": {"openid"}}, "", "conf", "s3cret")
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	dc, uc := out["device_code"].(string), out["user_code"].(string)
	b := e.browser()
	b.openAndLogin(devGrant{VerificationURIComplete: out["verification_uri_complete"].(string)}, "alice", "pw")
	b.decide(uc, "approve")
	e.advance(10 * time.Second)
	form := url.Values{"grant_type": {deviceGrant}, "device_code": {dc}}
	// No / wrong credentials: invalid_client and nothing consumed.
	if c, o, _ := e.post(base+"token", form, "", "", ""); c != 401 || errOf(o) != "invalid_client" {
		t.Fatalf("no creds: %d %v", c, o)
	}
	if c, o, _ := e.post(base+"token", form, "", "conf", "wrong"); c != 401 || errOf(o) != "invalid_client" {
		t.Fatalf("bad creds: %d %v", c, o)
	}
	if c, o, _ := e.post(base+"token", form, "", "conf", "s3cret"); c != 200 || o["access_token"] == nil {
		t.Fatalf("good creds: %d %v", c, o)
	}
}

func TestDeviceUserCodeBruteForceLimited(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	b := e.browser()
	var last *httptest.ResponseRecorder
	for i := 0; i < deviceLookupPerIP; i++ {
		last = b.do("GET", "/realms/r/device?user_code=BCDF-GHJK", nil)
		if last.Code != 400 {
			t.Fatalf("guess %d: %d", i, last.Code)
		}
	}
	// Over the limit: even the correct code is refused, from this IP.
	w := b.do("GET", g.VerificationURIComplete, nil)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("limiter did not trip: %d", w.Code)
	}
	if w := b.do("POST", "/realms/r/device", url.Values{"csrf": {"x"}, "user_code": {g.UserCode}}); w.Code == 303 || w.Code == 200 {
		t.Fatalf("POST path bypasses the limiter: %d", w.Code)
	}
	// Another IP is unaffected until the realm-wide budget is spent.
	b2 := e.browser()
	b2.ip = "198.51.100.99"
	if w := b2.do("GET", g.VerificationURIComplete, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("other IP: %d", w.Code)
	}
	// The window ends.
	e.advance(deviceLookupWindow + time.Second)
	g = e.start("cli", "openid") // the first code has expired by now
	if w := b.do("GET", g.VerificationURIComplete, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("after window: %d", w.Code)
	}
}

func TestDeviceUserCodeRealmWideLimit(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	for i := 0; i < deviceLookupPerRealm; i++ {
		b := e.browser()
		b.ip = fmt.Sprintf("10.%d.%d.1", i/250, i%250) // a botnet: every IP stays under its own limit
		if w := b.do("GET", "/realms/r/device?user_code=BCDF-GHJK", nil); w.Code != 400 {
			t.Fatalf("guess %d: %d", i, w.Code)
		}
	}
	b := e.browser()
	b.ip = "192.0.2.77"
	if w := b.do("GET", g.VerificationURIComplete, nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("realm-wide limit did not trip: %d", w.Code)
	}
}

type failLimiter struct{ core.Store }

func (f failLimiter) Unwrap() core.Store { return f.Store }
func (failLimiter) HitRateLimit(context.Context, string, time.Time, time.Duration, int) (bool, error) {
	return false, fmt.Errorf("limiter down")
}

func TestDeviceFailsClosedWhenLimiterDown(t *testing.T) {
	e := newDEnv(t, devOpts{store: func(s core.Store) core.Store { return failLimiter{s} }})
	if code, out, _ := e.post(devPath, url.Values{"client_id": {"cli"}}, "", "", ""); code != 503 {
		t.Fatalf("start with limiter down: %d %v", code, out)
	}
	b := e.browser()
	if w := b.do("GET", "/realms/r/device?user_code=BCDF-GHJK", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("lookup with limiter down: %d", w.Code)
	}
}

func TestDeviceUniformInvalidResponses(t *testing.T) {
	e := newDEnv(t, devOpts{})
	denied := e.start("cli", "openid")
	approved := e.start("cli", "openid")
	expired := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(denied, "alice", "pw")
	b.decide(denied.UserCode, "deny")
	b.do("GET", approved.VerificationURIComplete, nil)
	b.decide(approved.UserCode, "approve")
	e.advance(11 * time.Minute)
	live := e.start("cli", "openid") // created after the clock jump so "expired" is truly expired
	_ = live
	body := func(code string) (int, string) {
		w := b.do("GET", "/realms/r/device?user_code="+url.QueryEscape(code), nil)
		// The CSRF token differs per response; normalise it.
		bd := devCSRFRe.ReplaceAllString(w.Body.String(), `name="csrf" value="-"`)
		return w.Code, regexp.MustCompile(`nonce="[^"]+"`).ReplaceAllString(bd, `nonce="-"`)
	}
	refCode, refBody := body("BCDF-GHJK") // unknown
	for name, code := range map[string]string{"denied": denied.UserCode, "approved": approved.UserCode, "expired": expired.UserCode,
		"malformed": "hello", "empty-ish": "----", "wrong alphabet": "AEIO-0123", "too long": strings.Repeat("B", 200)} {
		c, bd := body(code)
		if c != refCode || bd != refBody {
			t.Errorf("%s answers differently from an unknown code (%d vs %d)", name, c, refCode)
		}
	}
	if refCode != 400 || !strings.Contains(refBody, notValidText) {
		t.Fatalf("invalid page: %d", refCode)
	}
	// Same for decisions.
	for _, code := range []string{"BCDF-GHJK", denied.UserCode, approved.UserCode, expired.UserCode} {
		if w := b.decide(code, "approve"); w.Code != 400 || !strings.Contains(w.Body.String(), notValidText) {
			t.Errorf("decide %s: %d", code, w.Code)
		}
	}
}

func TestDeviceCSRF(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(g, "alice", "pw")
	ck := b.cookie(deviceCSRFCookie)
	form := func(csrf string) url.Values {
		return url.Values{"csrf": {csrf}, "user_code": {g.UserCode}, "decision": {"approve"}}
	}
	// No token, no cookie, mismatched, forged: all 403 and nothing decided.
	if w := b.do("POST", "/realms/r/device", url.Values{"user_code": {g.UserCode}, "decision": {"approve"}}); w.Code != 403 {
		t.Errorf("no csrf: %d", w.Code)
	}
	if w := b.do("POST", "/realms/r/device", form("forged.token")); w.Code != 403 {
		t.Errorf("forged: %d", w.Code)
	}
	stripped := e.browser()
	stripped.cookies = map[string]*http.Cookie{}
	for k, c := range b.cookies {
		if c.Name != deviceCSRFCookie {
			stripped.cookies[k] = c
		}
	}
	if w := stripped.do("POST", "/realms/r/device", form(ck.Value)); w.Code != 403 {
		t.Errorf("token without cookie (cross-site form post): %d", w.Code)
	}
	other := e.browser()
	other.cookies = b.cookies
	if w := other.do("POST", "/realms/r/device", form(e.h.newCSRF("r"))); w.Code != 403 { // valid token, different cookie
		t.Errorf("token not bound to cookie: %d", w.Code)
	}
	// Expired token.
	e.advance(csrfTTL + time.Second)
	if w := b.do("POST", "/realms/r/device", form(ck.Value)); w.Code != 403 {
		t.Errorf("expired csrf: %d", w.Code)
	}
	if _, out := e.poll("cli", g.DeviceCode); errOf(out) == "access_denied" || out["access_token"] != nil {
		t.Fatalf("decision applied despite CSRF failure: %v", out)
	}
	ds, _ := core.StoreAs[core.DeviceStore](e.st)
	d, _ := ds.GetDeviceCodeByUserCode(context.Background(), "r", userCodeHash(strings.ReplaceAll(g.UserCode, "-", "")))
	if d.Status != core.DevicePending {
		t.Fatalf("status %s", d.Status)
	}
}

func TestDeviceXSSEscaped(t *testing.T) {
	e := newDEnv(t, devOpts{})
	code, out, _ := e.post(devPath, url.Values{"client_id": {"xss"}, "scope": {"openid"}}, "", "", "", `<b onmouseover=alert(3)>"UA`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	b := e.browser()
	w := b.openAndLogin(devGrant{VerificationURIComplete: out["verification_uri_complete"].(string)}, "alice", "pw")
	body := w.Body.String()
	for _, bad := range []string{"<script>alert(1)", "<img src=x", "<b onmouseover"} {
		if strings.Contains(body, bad) {
			t.Errorf("unescaped %q in page", bad)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("client name not shown escaped: %s", body)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") || strings.Contains(csp, "unsafe") {
		t.Errorf("CSP %q", csp)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("headers %v", w.Header())
	}
}

func TestDeviceLoginRulesApply(t *testing.T) {
	t.Run("lockout", func(t *testing.T) {
		e := newDEnv(t, devOpts{})
		g := e.start("cli", "openid")
		b := e.browser()
		w := b.do("GET", g.VerificationURIComplete, nil)
		authURL := w.Header().Get("Location")
		for i := 0; i < lockThreshold; i++ {
			r := b.loginAt(authURL, "alice", "WRONG")
			if r.Code != 200 || !strings.Contains(r.Body.String(), badCreds) {
				t.Fatalf("attempt %d: %d", i, r.Code)
			}
		}
		// Now locked: the right password is refused and no SSO session appears.
		r := b.loginAt(authURL, "alice", "pw")
		if r.Code != 200 || !strings.Contains(r.Body.String(), badCreds) || b.cookie(ssoCookie) != nil {
			t.Fatalf("locked account got through: %d", r.Code)
		}
		if _, out := e.poll("cli", g.DeviceCode); errOf(out) != "authorization_pending" {
			t.Fatalf("%v", out)
		}
	})
	t.Run("email verification", func(t *testing.T) {
		e := newDEnv(t, devOpts{realm: func(r *core.Realm) { r.EmailVerificationRequired = true }})
		u, _ := e.st.GetUser(context.Background(), "r", "u1")
		u.EmailVerified = false
		_ = e.st.UpdateUser(context.Background(), u)
		g := e.start("cli", "openid")
		b := e.browser()
		authURL := b.do("GET", g.VerificationURIComplete, nil).Header().Get("Location")
		r := b.loginAt(authURL, "alice", "pw")
		if r.Code != 200 || !strings.Contains(r.Body.String(), "not been verified") || b.cookie(ssoCookie) != nil {
			t.Fatalf("unverified user got through: %d %s", r.Code, r.Body)
		}
	})
	t.Run("extra auth step", func(t *testing.T) {
		savedS, savedC := authStepHooks, authContinueHooks
		defer func() { authStepHooks, authContinueHooks = savedS, savedC }()
		registerAuthStep(func(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) bool {
			p.stepPage(w, r, ar, http.StatusOK, "Second factor", "", `<p>enter your code</p>`, nil)
			return true
		}, nil)
		e := newDEnv(t, devOpts{})
		g := e.start("cli", "openid")
		b := e.browser()
		authURL := b.do("GET", g.VerificationURIComplete, nil).Header().Get("Location")
		r := b.loginAt(authURL, "alice", "pw")
		if r.Code != 200 || !strings.Contains(r.Body.String(), "Second factor") || b.cookie(ssoCookie) != nil {
			t.Fatalf("MFA step skipped by the device flow: %d %s", r.Code, r.Body)
		}
		// The approval page is not reachable without the session.
		if w := b.do("GET", g.VerificationURIComplete, nil); w.Code != http.StatusSeeOther {
			t.Fatalf("approval page without session: %d", w.Code)
		}
	})
	t.Run("disabled user session", func(t *testing.T) {
		e := newDEnv(t, devOpts{})
		g := e.start("cli", "openid")
		b := e.browser()
		b.openAndLogin(g, "alice", "pw")
		u, _ := e.st.GetUser(context.Background(), "r", "u1")
		u.Enabled = false
		_ = e.st.UpdateUser(context.Background(), u)
		if w := b.decide(g.UserCode, "approve"); w.Code != http.StatusSeeOther {
			t.Fatalf("disabled user could approve: %d", w.Code)
		}
	})
	t.Run("user disabled after approval", func(t *testing.T) {
		e := newDEnv(t, devOpts{})
		g := e.start("cli", "openid")
		b := e.browser()
		b.openAndLogin(g, "alice", "pw")
		b.decide(g.UserCode, "approve")
		u, _ := e.st.GetUser(context.Background(), "r", "u1")
		u.Enabled = false
		_ = e.st.UpdateUser(context.Background(), u)
		e.advance(10 * time.Second)
		if c, out := e.poll("cli", g.DeviceCode); c != 400 || out["access_token"] != nil {
			t.Fatalf("tokens for a disabled user: %d %v", c, out)
		}
	})
}

func TestDeviceAlreadySignedIn(t *testing.T) {
	e := newDEnv(t, devOpts{})
	b := e.browser()
	// Ordinary code-flow login first.
	q := authQuery(nil)
	authURL := base + "auth?" + q.Encode()
	w := b.do("GET", authURL, nil)
	m := csrfRe.FindStringSubmatch(w.Body.String())
	w = b.do("POST", authURL, url.Values{"username": {"alice"}, "password": {"pw"}, "csrf": {m[1]}})
	if w.Code != 302 || b.cookie(ssoCookie) == nil {
		t.Fatalf("setup login: %d", w.Code)
	}
	g := e.start("cli", "openid")
	page := b.do("GET", g.VerificationURIComplete, nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Only approve if you started this on your own device") {
		t.Fatalf("signed-in user should land on the approval page directly: %d %s", page.Code, page.Body)
	}
	// Typing the code into the entry form works too (and is case/dash/space insensitive).
	b2 := e.browser()
	b2.cookies = b.cookies
	w = b2.do("GET", "/realms/r/device", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="user_code"`) {
		t.Fatalf("entry page: %d", w.Code)
	}
	typed := strings.ToLower(g.UserCode[:4]) + " " + g.UserCode[5:]
	w = b2.do("POST", "/realms/r/device", url.Values{"csrf": {b2.cookie(deviceCSRFCookie).Value}, "user_code": {typed}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), g.UserCode) {
		t.Fatalf("typed code: %d %s", w.Code, w.Body)
	}
	if w := b2.decide(g.UserCode, "approve"); w.Code != 200 {
		t.Fatalf("approve: %d", w.Code)
	}
	e.advance(10 * time.Second)
	if c, out := e.poll("cli", g.DeviceCode); c != 200 || out["access_token"] == nil {
		t.Fatalf("%d %v", c, out)
	}
}

func TestDeviceApproveRequiresSameRealm(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	// bob is signed in to realm "other".
	raw := "bob-cookie"
	s := core.Session{ID: "sb", CookieHash: actions.Hash(raw), Realm: "other", UserID: "u9", AuthTime: e.now, LastSeen: e.now,
		IdleExpires: e.now.Add(time.Hour), ExpiresAt: e.now.Add(5 * time.Hour)}
	if err := e.st.PutSession(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	b := e.browser()
	b.cookies["haven_sso|/realms/other"] = &http.Cookie{Name: ssoCookie, Value: raw, Path: "/realms/other"}
	w := b.do("GET", "/realms/other/device", nil)
	m := devCSRFRe.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || m == nil {
		t.Fatalf("other realm entry page: %d", w.Code)
	}
	for _, path := range []string{"/realms/other/device"} {
		w = b.do("POST", path, url.Values{"csrf": {m[1]}, "user_code": {g.UserCode}, "decision": {"approve"}})
		if w.Code != 400 || !strings.Contains(w.Body.String(), notValidText) {
			t.Fatalf("cross-realm approve: %d %s", w.Code, w.Body)
		}
	}
	// The other realm's session is not honoured in realm r either (cookie path).
	if w := b.do("GET", g.VerificationURIComplete, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("realm r accepted realm other's session: %d", w.Code)
	}
	if _, out := e.poll("cli", g.DeviceCode); errOf(out) != "authorization_pending" {
		t.Fatalf("%v", out)
	}
}

func TestDeviceContinueRejectsForgedState(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	b := e.browser()
	b.openAndLogin(g, "alice", "pw") // has an SSO session now
	for name, target := range map[string]string{
		"no state":      "/realms/r/device/continue",
		"garbage state": "/realms/r/device/continue?state=abc.def",
		"error":         "/realms/r/device/continue?error=access_denied&state=" + url.QueryEscape(e.h.signPending("r", "", deviceStatePurpose, "BCDFGHJK", time.Minute)),
		"wrong purpose": "/realms/r/device/continue?state=" + url.QueryEscape(e.h.signPending("r", "", "other", strings.ReplaceAll(g.UserCode, "-", ""), time.Minute)),
		"other realm":   "/realms/r/device/continue?state=" + url.QueryEscape(e.h.signPending("other", "", deviceStatePurpose, strings.ReplaceAll(g.UserCode, "-", ""), time.Minute)),
	} {
		w := b.do("GET", target, nil)
		if w.Code != 400 || strings.Contains(w.Body.String(), "Approve") {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	// A browser without a session cannot use even a valid state.
	nb := e.browser()
	st := url.QueryEscape(e.h.signPending("r", "", deviceStatePurpose, strings.ReplaceAll(g.UserCode, "-", ""), time.Minute))
	if w := nb.do("GET", "/realms/r/device/continue?code=x&state="+st, nil); w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "Approve") {
		t.Errorf("no session: %d", w.Code)
	}
}

func TestDevicePseudoClientIsolation(t *testing.T) {
	e := newDEnv(t, devOpts{})
	b := e.browser()
	q := url.Values{"client_id": {deviceClientID}, "response_type": {"code"}, "state": {"s"}, "scope": {"openid"},
		"redirect_uri": {"https://evil.example/cb"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	if w := b.do("GET", base+"auth?"+q.Encode(), nil); w.Code != 400 {
		t.Errorf("pseudo client with a foreign redirect: %d", w.Code)
	}
	// It is not a real client: the token endpoint knows nothing about it, and it
	// has no secret to guess.
	for _, f := range []url.Values{
		{"grant_type": {"authorization_code"}, "client_id": {deviceClientID}, "code": {"x"}},
		{"grant_type": {deviceGrant}, "client_id": {deviceClientID}, "device_code": {"x"}},
	} {
		if c, out, _ := e.post(base+"token", f, "", "", ""); c != 401 || errOf(out) != "invalid_client" {
			t.Errorf("token endpoint accepted the pseudo client: %d %v", c, out)
		}
	}
	// A realm-defined client with the same id is shadowed in /auth, never used.
	_ = e.st.CreateClient(context.Background(), core.Client{Realm: "r", ClientID: deviceClientID, Enabled: true, Public: true,
		AuthCodeFlow: true, RedirectURIs: []string{"https://evil.example/cb"}})
	if w := b.do("GET", base+"auth?"+q.Encode(), nil); w.Code != 400 {
		t.Errorf("store client hijacked the pseudo client id: %d", w.Code)
	}
}

// A store without core.DeviceStore means the feature is off everywhere.
type noDevice struct{ core.Store }

func TestDeviceOffWithoutStoreSupport(t *testing.T) {
	e := newDEnv(t, devOpts{store: func(s core.Store) core.Store { return noDevice{s} }})
	if code, out, _ := e.post(devPath, url.Values{"client_id": {"cli"}}, "", "", ""); code != 501 || errOf(out) != "feature_unavailable" {
		t.Fatalf("start: %d %v", code, out)
	}
	if code, out, _ := e.post(base+"token", url.Values{"grant_type": {deviceGrant}, "device_code": {"x"}, "client_id": {"cli"}}, "", "", ""); code != 501 || errOf(out) != "feature_unavailable" {
		t.Fatalf("grant: %d %v", code, out)
	}
	b := e.browser()
	if w := b.do("GET", "/realms/r/device", nil); w.Code != 501 {
		t.Errorf("GET /device: %d", w.Code)
	}
	if w := b.do("POST", "/realms/r/device", url.Values{}); w.Code != 501 {
		t.Errorf("POST /device: %d", w.Code)
	}
	if w := b.do("GET", "/realms/r/device/continue", nil); w.Code != 501 {
		t.Errorf("continue: %d", w.Code)
	}
	q := url.Values{"client_id": {deviceClientID}, "response_type": {"code"}, "state": {"s"}, "redirect_uri": {idpBase + "/realms/r/device/continue"},
		"code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	if w := b.do("GET", base+"auth?"+q.Encode(), nil); w.Code != 400 {
		t.Errorf("pseudo client exists without the feature: %d", w.Code)
	}
	w := b.do("GET", "/realms/r/.well-known/openid-configuration", nil)
	if strings.Contains(w.Body.String(), "device_authorization_endpoint") || strings.Contains(w.Body.String(), "device_code") {
		t.Errorf("discovery advertises the device flow: %s", w.Body)
	}
}

func TestDeviceDiscovery(t *testing.T) {
	e := newDEnv(t, devOpts{})
	w := e.browser().do("GET", "/realms/r/.well-known/openid-configuration", nil)
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["device_authorization_endpoint"] != idpBase+"/realms/r/protocol/openid-connect/auth/device" {
		t.Errorf("endpoint: %v", doc["device_authorization_endpoint"])
	}
	gts := fmt.Sprint(doc["grant_types_supported"])
	for _, g := range []string{"authorization_code", "refresh_token", "client_credentials", deviceGrant} {
		if !strings.Contains(gts, g) {
			t.Errorf("grant_types_supported lacks %s: %s", g, gts)
		}
	}
}

func TestDeviceCodesStoredHashed(t *testing.T) {
	e := newDEnv(t, devOpts{})
	g := e.start("cli", "openid")
	ds, _ := core.StoreAs[core.DeviceStore](e.st)
	norm := strings.ReplaceAll(g.UserCode, "-", "")
	d, err := ds.GetDeviceCodeByUserCode(context.Background(), "r", HashSecret(norm))
	if err != nil {
		t.Fatal(err)
	}
	if d.DeviceCodeHash != HashSecret(g.DeviceCode) || d.UserCodeHash != HashSecret(norm) {
		t.Fatalf("hashes: %+v", d)
	}
	for _, v := range []string{d.DeviceCodeHash, d.UserCodeHash, d.RequestUA, d.Scope, d.ClientID} {
		if v == g.DeviceCode || v == norm || v == g.UserCode {
			t.Fatalf("plaintext code stored: %+v", d)
		}
	}
	if d.RequestIP != "203.0.113.50" || d.ExpiresAt.Sub(d.CreatedAt) != 10*time.Minute || d.Interval != 5 {
		t.Fatalf("row: %+v", d)
	}
}

func TestUserCodeNormalisationAndAlphabet(t *testing.T) {
	good := map[string]string{"bcdf-ghjk": "BCDFGHJK", "BCDF GHJK": "BCDFGHJK", " b-c d f g-h j k ": "BCDFGHJK", "BCDFGHJK": "BCDFGHJK"}
	for in, want := range good {
		if got, ok := normalizeUserCode(in); !ok || got != want {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-GHJ0", "BCDF-GHJ1", "BCDF-GHJI", "BCDF-GHJ_", strings.Repeat("B", 100), "BCDF\x00GHJK", "BCDF-GHJÉ"} {
		if got, ok := normalizeUserCode(bad); ok {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
	seen := map[string]bool{}
	counts := map[byte]int{}
	for i := 0; i < 4000; i++ {
		c := newUserCode()
		if len(c) != 8 {
			t.Fatalf("len %d", len(c))
		}
		if n, ok := normalizeUserCode(c); !ok || n != c {
			t.Fatalf("generated code %q does not normalise to itself", c)
		}
		seen[c] = true
		for j := 0; j < len(c); j++ {
			counts[c[j]]++
		}
	}
	if len(seen) < 3990 {
		t.Errorf("only %d distinct of 4000 codes", len(seen))
	}
	if len(counts) != len(userCodeAlphabet) {
		t.Errorf("alphabet coverage %d/%d", len(counts), len(userCodeAlphabet))
	}
	for ch, n := range counts { // 32000 draws over 20 symbols: expect 1600 each
		if n < 1300 || n > 1900 {
			t.Errorf("symbol %c drawn %d times (biased?)", ch, n)
		}
	}
	if displayUserCode("BCDFGHJK") != "BCDF-GHJK" {
		t.Error("display form")
	}
}

func TestDeviceStartRateLimited(t *testing.T) {
	e := newDEnv(t, devOpts{})
	for i := 0; i < deviceStartPerIP; i++ {
		if code, out, _ := e.post(devPath, url.Values{"client_id": {"cli"}}, "192.0.2.200", "", ""); code != 200 {
			t.Fatalf("request %d: %d %v", i, code, out)
		}
	}
	if code, out, _ := e.post(devPath, url.Values{"client_id": {"cli"}}, "192.0.2.200", "", ""); code != 429 {
		t.Fatalf("limiter: %d %v", code, out)
	}
	if code, _, _ := e.post(devPath, url.Values{"client_id": {"cli"}}, "192.0.2.201", "", ""); code != 200 {
		t.Fatalf("other IP: %d", code)
	}
}

func TestDeviceDisabledRealm(t *testing.T) {
	e := newDEnv(t, devOpts{realm: func(r *core.Realm) { r.Enabled = false }})
	if code, _, _ := e.post(devPath, url.Values{"client_id": {"cli"}}, "", "", ""); code != 404 {
		t.Fatalf("%d", code)
	}
	if w := e.browser().do("GET", "/realms/r/device", nil); w.Code != 404 {
		t.Fatalf("%d", w.Code)
	}
}
