// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/totp"
)

// ---- harness: real memstore, real secretbox, controllable clock ----

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type mfaEnv struct {
	t    *testing.T
	st   *memstore.Store
	h    *Provider
	box  *secretbox.Box
	now  time.Time
	logs *logBuf
	// bodies collects every response body seen through b.do, for leak checks.
	bodies []string
	alice  core.User
	bob    core.User
}

// startTime is a multiple of 30 plus 5 seconds: well inside a TOTP step.
var startTime = time.Unix(1_780_315_200+5, 0).UTC()

type mfaOpt func(*Config)

func newMFA(t *testing.T, withKey bool, opts ...mfaOpt) *mfaEnv {
	t.Helper()
	e := &mfaEnv{t: t, now: startTime, st: memstore.New(), logs: &logBuf{}}
	ctx := context.Background()
	if err := e.st.CreateRealm(ctx, core.Realm{Name: "r", Enabled: true, BruteForceProtection: true,
		AuthEventsLogged: true, RefreshTokenRotation: true, AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateRealm(ctx, core.Realm{Name: "other", Enabled: true, AuthEventsLogged: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateClient(ctx, core.Client{Realm: "r", ClientID: "app", Enabled: true, Public: true,
		AuthCodeFlow: true, RedirectURIs: []string{cb}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		u := core.User{ID: "id-" + name, Realm: "r", Username: name, Email: name + "@x", Enabled: true,
			EmailVerified: true, PasswordHash: "H:pw", CreatedAt: e.now}
		if err := e.st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		if name == "alice" {
			e.alice = u
		} else {
			e.bob = u
		}
	}
	cfg := Config{Store: e.st, Signer: fakeSigner{now: func() time.Time { return e.now }}, Hasher: fakeHasher{},
		BaseURL: "https://idp.example", Clock: func() time.Time { return e.now },
		CSRFKey: []byte("0123456789abcdef0123456789abcdef"),
		Logger:  slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	if withKey {
		k, _ := secretbox.ParseKey(secretbox.GenerateKey())
		e.box, _ = secretbox.New(k)
		cfg.SecretBox = e.box
	}
	for _, o := range opts {
		o(&cfg)
	}
	e.h = New(cfg)
	return e
}

// mfaBrowser keeps cookies (by name+path) like a real client.
type mfaBrowser struct {
	e       *mfaEnv
	cookies map[string]*http.Cookie
	ip      string
	csrf    string // csrf token of the latest page that carried one (matches the latest csrf cookie)
	// expectCSRFFail allows a 403 "request was invalid" response. Otherwise one
	// fails the test: a negative test must fail for the reason it claims, not
	// because its form token went stale.
	expectCSRFFail bool
}

func (e *mfaEnv) mfaBrowser() *mfaBrowser {
	return &mfaBrowser{e: e, cookies: map[string]*http.Cookie{}, ip: "192.0.2.1:1234"}
}

func (b *mfaBrowser) do(req *http.Request) *httptest.ResponseRecorder {
	req.RemoteAddr = b.ip
	for _, c := range b.cookies {
		if strings.HasPrefix(req.URL.Path, c.Path) {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	w := httptest.NewRecorder()
	b.e.h.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		k := c.Name + "|" + c.Path
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, k)
		} else {
			b.cookies[k] = c
		}
	}
	body := w.Body.String()
	b.e.bodies = append(b.e.bodies, body)
	if m := csrfRe.FindStringSubmatch(body); m != nil {
		b.csrf = m[1]
	}
	if w.Code == http.StatusForbidden && strings.Contains(body, "request was invalid") && !b.expectCSRFFail {
		b.e.t.Fatalf("unexpected CSRF rejection of %s %s (test bug: stale form token)", req.Method, req.URL.Path)
	}
	return w
}

func (b *mfaBrowser) get(path string) *httptest.ResponseRecorder {
	return b.do(httptest.NewRequest("GET", path, nil))
}

func (b *mfaBrowser) post(path string, f url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req)
}

func (b *mfaBrowser) hasSSO() bool {
	for _, c := range b.cookies {
		if c.Name == ssoCookie {
			return true
		}
	}
	return false
}

var (
	tokenRe   = regexp.MustCompile(`name="mfa_token" value="([^"]+)"`)
	secretRe  = regexp.MustCompile(`Secret key: <code>([A-Z2-7]+)</code>`)
	recCodeRe = regexp.MustCompile(`[A-Z2-9]{5}-[A-Z2-9]{5}`)
)

// authURL is the /auth URL used by all login tests.
func authURL() string { return base + "auth?" + authQuery(nil).Encode() }

// password runs GET /auth + POST with the password and returns the response.
func (b *mfaBrowser) password(user, pw string) *httptest.ResponseRecorder {
	b.t().Helper()
	w := b.get(authURL())
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || m == nil {
		b.t().Fatalf("login page: %d %s", w.Code, w.Body)
	}
	return b.post(authURL(), url.Values{"username": {user}, "password": {pw}, "csrf": {m[1]}})
}

func (b *mfaBrowser) t() *testing.T { return b.e.t }

// step posts to the step page shown in prev (csrf + mfa_token taken from it)
// with extra fields.
func (b *mfaBrowser) step(prev *httptest.ResponseRecorder, extra url.Values) *httptest.ResponseRecorder {
	b.t().Helper()
	body := prev.Body.String()
	tk := tokenRe.FindStringSubmatch(body)
	if tk == nil {
		b.t().Fatalf("not a step page (%d): %s", prev.Code, body)
	}
	f := url.Values{"csrf": {b.csrf}, "mfa_token": {tk[1]}}
	for k, v := range extra {
		f[k] = v
	}
	return b.post(authURL(), f)
}

func isRedirectWithCode(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusFound && strings.Contains(w.Header().Get("Location"), "code=")
}

func (e *mfaEnv) store() core.MFAStore { return e.st }

// seedOf returns the plaintext seed of a user's credential (test-only access).
func (e *mfaEnv) seedOf(userID string) []byte {
	e.t.Helper()
	c, err := e.st.GetTOTP(context.Background(), "r", userID)
	if err != nil {
		e.t.Fatal(err)
	}
	s, err := e.box.Open(c.SealedSeed, "totp|r|"+userID)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *mfaEnv) code(userID string, delta int64) string {
	return totp.CodeAt(e.seedOf(userID), totp.StepAt(e.now)+delta)
}

// enrollDirect enrolls a user through the store (no HTTP) and returns the
// plaintext recovery codes. The credential's last used step is the current one.
func (e *mfaEnv) enrollDirect(u core.User) (recovery []string) {
	e.t.Helper()
	ctx := context.Background()
	seed := totp.NewSeed()
	if err := e.st.PutTOTP(ctx, core.TOTPCredential{Realm: "r", UserID: u.ID, CreatedAt: e.now,
		SealedSeed: e.box.Seal(seed, "totp|r|"+u.ID)}); err != nil {
		e.t.Fatal(err)
	}
	if ok, err := e.st.ConfirmTOTP(ctx, "r", u.ID, totp.StepAt(e.now)-5); err != nil || !ok {
		e.t.Fatal(err, ok)
	}
	recovery = totp.NewRecoveryCodes(totp.RecoveryCount)
	var hs []string
	for _, c := range recovery {
		h, _ := totp.HashRecovery(c)
		hs = append(hs, h)
	}
	if err := e.st.ReplaceRecoveryCodes(ctx, "r", u.ID, hs); err != nil {
		e.t.Fatal(err)
	}
	return recovery
}

func (e *mfaEnv) events(typ string) []core.Event {
	evs, _ := e.st.ListEvents(context.Background(), "r", 1000)
	var out []core.Event
	for _, ev := range evs {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

func (e *mfaEnv) setPolicy(on bool) {
	e.t.Helper()
	if err := e.st.PutMFAPolicy(context.Background(), "r", core.MFAPolicy{RequireMFA: on}); err != nil {
		e.t.Fatal(err)
	}
}

// ---- tests ----

func TestMFAOffWithoutKey(t *testing.T) {
	e := newMFA(t, false)
	// Even a stored requireMfa policy and a credential row must not affect login.
	_ = e.st.PutMFAPolicy(context.Background(), "r", core.MFAPolicy{RequireMFA: true})
	b := e.mfaBrowser()
	w := b.password("alice", "pw")
	if !isRedirectWithCode(w) {
		t.Fatalf("login must be unaffected without a key: %d %s", w.Code, w.Body)
	}
	if w := b.get("/realms/r/account/totp"); w.Code != http.StatusNotFound {
		t.Errorf("account page without key: %d", w.Code)
	}
	if w := b.post("/realms/r/account/totp", url.Values{"action": {"start"}}); w.Code != http.StatusNotFound {
		t.Errorf("account POST without key: %d", w.Code)
	}
}

func TestMFAOffWithoutStoreSupport(t *testing.T) {
	type plainStore struct{ core.Store } // hides MFAStore
	e := newMFA(t, true, func(c *Config) { c.Store = plainStore{c.Store} })
	b := e.mfaBrowser()
	if w := b.password("alice", "pw"); !isRedirectWithCode(w) {
		t.Fatalf("login affected by a store without MFA support: %d", w.Code)
	}
	if w := b.get("/realms/r/account/totp"); w.Code != http.StatusNotFound {
		t.Errorf("account page: %d", w.Code)
	}
}

// Full journey through the real pages: SSO login, enroll on the account page,
// wrong confirm code, confirm, recovery codes shown once, later login needs the code.
func TestMFAEnrollOnAccountPageAndLogin(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()

	if w := b.get("/realms/r/account/totp"); w.Code != http.StatusUnauthorized {
		t.Fatalf("account page without SSO session: %d", w.Code)
	}
	if w := b.password("alice", "pw"); !isRedirectWithCode(w) || !b.hasSSO() {
		t.Fatalf("initial login: %d", w.Code)
	}

	w := b.get("/realms/r/account/totp")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "is <strong>off</strong>") {
		t.Fatalf("status page: %d %s", w.Code, w.Body)
	}
	assertNoStore(t, w)
	if strings.Contains(w.Body.String(), "Secret key") {
		t.Error("status page shows a secret")
	}

	// POST without CSRF: rejected.
	b.expectCSRFFail = true
	if w := b.post("/realms/r/account/totp", url.Values{"action": {"start"}}); w.Code != http.StatusForbidden {
		t.Errorf("POST without csrf: %d", w.Code)
	}
	b.expectCSRFFail = false
	csrf := csrfRe.FindStringSubmatch(w.Body.String())[1]
	// POST with a forged cookie-less token.
	forged := httptest.NewRequest("POST", "/realms/r/account/totp", strings.NewReader(url.Values{"action": {"start"}, "csrf": {csrf}}.Encode()))
	forged.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	forged.RemoteAddr = "192.0.2.1:1"
	for _, c := range b.cookies {
		if c.Name == ssoCookie {
			forged.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	fw := httptest.NewRecorder()
	e.h.ServeHTTP(fw, forged)
	if fw.Code != http.StatusForbidden {
		t.Errorf("csrf token without matching cookie accepted: %d", fw.Code)
	}

	// Start.
	w = b.post("/realms/r/account/totp", url.Values{"action": {"start"}, "csrf": {csrf}})
	m := secretRe.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || m == nil || !strings.Contains(w.Body.String(), "otpauth://totp/r:alice?") {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	secret := m[1]
	seed, err := totp.DecodeSeed(secret)
	if err != nil || len(seed) != totp.SeedSize {
		t.Fatalf("displayed secret does not decode to a 20 byte seed: %v", err)
	}
	// The stored seed is sealed, not the plaintext.
	cred, _ := e.st.GetTOTP(context.Background(), "r", "id-alice")
	if cred.Confirmed || strings.Contains(cred.SealedSeed, secret) || !strings.HasPrefix(cred.SealedSeed, "v1.") {
		t.Fatalf("stored credential: %+v", cred)
	}

	// Wrong code: still not enrolled.
	csrf = csrfRe.FindStringSubmatch(w.Body.String())[1]
	w = b.post("/realms/r/account/totp", url.Values{"action": {"confirm"}, "csrf": {csrf}, "code": {"000000"}})
	if !strings.Contains(w.Body.String(), mfaGeneric) {
		t.Fatalf("wrong confirm code: %d %s", w.Code, w.Body)
	}
	if c, _ := e.st.GetTOTP(context.Background(), "r", "id-alice"); c.Confirmed {
		t.Fatal("confirmed with a wrong code")
	}

	// Right code.
	csrf = csrfRe.FindStringSubmatch(w.Body.String())[1]
	w = b.post("/realms/r/account/totp", url.Values{"action": {"confirm"}, "csrf": {csrf}, "code": {totp.Code(seed, e.now)}})
	codes := recCodeRe.FindAllString(w.Body.String(), -1)
	if w.Code != 200 || len(codes) != 10 || !strings.Contains(w.Body.String(), "Save these recovery codes now") {
		t.Fatalf("confirm: %d codes=%d %s", w.Code, len(codes), w.Body)
	}
	if n, _ := e.st.CountRecoveryCodes(context.Background(), "r", "id-alice"); n != 10 {
		t.Errorf("stored recovery codes: %d", n)
	}
	if len(e.events("TOTP_ENROLLED")) != 1 {
		t.Error("TOTP_ENROLLED event missing")
	}

	// Status afterwards: on, count shown, no secret, no codes, no seed in any later page.
	w = b.get("/realms/r/account/totp")
	if !strings.Contains(w.Body.String(), "is <strong>on</strong>") || !strings.Contains(w.Body.String(), "<strong>10</strong>") ||
		secretRe.MatchString(w.Body.String()) || recCodeRe.MatchString(w.Body.String()) {
		t.Fatalf("status after enrollment: %s", w.Body)
	}

	// New login: password alone no longer finishes the login.
	e.now = e.now.Add(35 * time.Second) // next step
	b2 := e.mfaBrowser()
	w = b2.password("alice", "pw")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Two-step verification") || isRedirectWithCode(w) {
		t.Fatalf("code page not shown: %d %s", w.Code, w.Body)
	}
	if b2.hasSSO() {
		t.Fatal("SSO cookie issued before the second factor")
	}
	assertStepHeaders(t, w)
	wrong := b2.step(w, url.Values{"code": {"123456"}})
	if wrong.Code != 200 || !strings.Contains(wrong.Body.String(), mfaGeneric) || b2.hasSSO() || isRedirectWithCode(wrong) {
		t.Fatalf("wrong code: %d %s", wrong.Code, wrong.Body)
	}
	good := b2.step(wrong, url.Values{"code": {totp.Code(seed, e.now)}})
	if !isRedirectWithCode(good) || !b2.hasSSO() {
		t.Fatalf("right code: %d %s", good.Code, good.Body)
	}
	var sawTOTP bool
	for _, ev := range e.events("LOGIN") {
		if ev.UserID == "id-alice" && ev.Detail == "totp" {
			sawTOTP = true
		}
	}
	if !sawTOTP {
		t.Error("LOGIN event with detail totp missing")
	}
	if len(e.events("MFA_FAILED")) < 2 {
		t.Errorf("MFA_FAILED events: %d", len(e.events("MFA_FAILED")))
	}
	for _, ev := range e.events("MFA_FAILED") {
		if strings.ContainsAny(ev.Detail, "0123456789") {
			t.Errorf("event detail may carry a code: %q", ev.Detail)
		}
	}

	// SSO re-login is unaffected: a silent GET /auth with the session issues a code.
	if w := b2.get(authURL()); !isRedirectWithCode(w) {
		t.Errorf("SSO reuse broken: %d", w.Code)
	}
	assertNoLeak(t, e, secret, hexOf(seed), codes)
}

func hexOf(b []byte) string { return fmt.Sprintf("%x", b) }

func assertNoStore(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
}

func assertStepHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assertNoStore(t, w)
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "nonce-") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP: %s", csp)
	}
}

// The seed (base32 or hex) must not appear in any response after enrollment
// finished, nor in the logs; recovery codes only on the one page that shows them.
func assertNoLeak(t *testing.T, e *mfaEnv, secret, seedHex string, codes []string) {
	t.Helper()
	logs := e.logs.String()
	for _, needle := range append([]string{secret, seedHex}, codes...) {
		if strings.Contains(logs, needle) {
			t.Errorf("secret material %q... found in logs", needle[:4])
		}
	}
	for _, ev := range func() []core.Event { x, _ := e.st.ListEvents(context.Background(), "r", 1000); return x }() {
		for _, needle := range append([]string{secret}, codes...) {
			if strings.Contains(ev.Detail, needle) {
				t.Errorf("audit event %s carries secret material", ev.Type)
			}
		}
	}
	// Bodies: the secret may appear only on the pages of the enrollment itself
	// (start and the wrong-code re-render); recovery codes only on the confirm page.
	secretPages, codePages := 0, 0
	for _, b := range e.bodies {
		if strings.Contains(b, secret) {
			secretPages++
		}
		if strings.Contains(b, codes[0]) {
			codePages++
		}
	}
	if secretPages != 2 { // start page + wrong-code re-render
		t.Errorf("the seed appeared in %d responses, want exactly 2 (start and wrong-code re-render)", secretPages)
	}
	if codePages != 1 {
		t.Errorf("recovery codes appeared in %d responses, want exactly 1", codePages)
	}
}

// loginUntilCodePage returns a mfaBrowser and the code page response of alice.
func (e *mfaEnv) codePage(user string) (*mfaBrowser, *httptest.ResponseRecorder) {
	b := e.mfaBrowser()
	w := b.password(user, "pw")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Two-step verification") {
		e.t.Fatalf("expected the code page for %s: %d %s", user, w.Code, w.Body)
	}
	return b, w
}

func TestMFAReplayedCodeRejected(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	code := e.code("id-alice", 0)

	b, w := e.codePage("alice")
	if got := b.step(w, url.Values{"code": {code}}); !isRedirectWithCode(got) {
		t.Fatalf("first use rejected: %d %s", got.Code, got.Body)
	}
	// Same code again, same time, fresh login: replay.
	b2, w2 := e.codePage("alice")
	if got := b2.step(w2, url.Values{"code": {code}}); isRedirectWithCode(got) || !strings.Contains(got.Body.String(), mfaGeneric) {
		t.Fatalf("replayed code accepted: %d", got.Code)
	}
	// An OLDER step's code (still inside the skew window) is rejected too.
	if got := b2.step(w2, url.Values{"code": {e.code("id-alice", -1)}}); isRedirectWithCode(got) {
		t.Fatal("code of an older step accepted after a newer one was used")
	}
	// The next step's code works.
	if got := b2.step(w2, url.Values{"code": {e.code("id-alice", 1)}}); !isRedirectWithCode(got) {
		t.Fatalf("next step rejected: %d %s", got.Code, got.Body)
	}
}

// Two parallel submissions of ONE valid code: exactly one logs in.
func TestMFAParallelDoubleSubmit(t *testing.T) {
	// Without help the first request usually finishes before the others read
	// the credential, so the replay check in Verify would hide a broken store
	// compare-and-set. The barrier holds every request after it has read the
	// credential (with the OLD last used step) until all of them have: the
	// store's UseTOTPStep is then the only thing that can stop the extras.
	const n = 5 // = the per-user attempt limit: the limiter must not be what stops the others
	bar := &barrierStore{need: n, release: make(chan struct{})}
	e := newMFA(t, true, func(c *Config) { bar.Store = c.Store.(*memstore.Store); c.Store = bar })
	e.enrollDirect(e.alice)
	code := e.code("id-alice", 0)
	b, w := e.codePage("alice")
	body := w.Body.String()
	cs, tk := csrfRe.FindStringSubmatch(body)[1], tokenRe.FindStringSubmatch(body)[1]

	bar.arm()
	results := make([]*httptest.ResponseRecorder, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			f := url.Values{"csrf": {cs}, "mfa_token": {tk}, "code": {code}}
			req := httptest.NewRequest("POST", authURL(), strings.NewReader(f.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "192.0.2.1:1234"
			for _, c := range b.cookies {
				if strings.HasPrefix(req.URL.Path, c.Path) {
					req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
				}
			}
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			results[i] = rec
		}(i)
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, r := range results {
		if isRedirectWithCode(r) {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d of %d parallel submissions of one code logged in, want exactly 1", wins, n)
	}
}

func TestMFASkewWindowAtLogin(t *testing.T) {
	cases := []struct {
		delta int64
		ok    bool
	}{{-2, false}, {-1, true}, {0, true}, {1, true}, {2, false}}
	for _, c := range cases {
		t.Run(fmt.Sprintf("step%+d", c.delta), func(t *testing.T) {
			e := newMFA(t, true)
			e.enrollDirect(e.alice)
			b, w := e.codePage("alice")
			got := b.step(w, url.Values{"code": {e.code("id-alice", c.delta)}})
			if isRedirectWithCode(got) != c.ok {
				t.Fatalf("delta %d: login=%v, want %v", c.delta, isRedirectWithCode(got), c.ok)
			}
		})
	}
}

func TestMFAWrongCodesLockoutAndRecovery(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	b, w := e.codePage("alice")
	for i := 0; i < 5; i++ {
		w = b.step(w, url.Values{"code": {"000000"}})
		if w.Code != 200 || !strings.Contains(w.Body.String(), mfaGeneric) {
			t.Fatalf("wrong code %d: %d", i, w.Code)
		}
	}
	// The limit is reached: even the correct code is refused...
	good := e.code("id-alice", 0)
	w = b.step(w, url.Values{"code": {good}})
	if w.Code != http.StatusTooManyRequests || isRedirectWithCode(w) || !strings.Contains(w.Body.String(), mfaLimited) {
		t.Fatalf("correct code during lockout: %d %s", w.Code, w.Body)
	}
	// ...from another mfaBrowser and another IP too (it is per user)...
	b2 := e.mfaBrowser()
	b2.ip = "198.51.100.9:4444"
	w2 := b2.password("alice", "pw")
	if got := b2.step(w2, url.Values{"code": {good}}); got.Code != http.StatusTooManyRequests {
		t.Fatalf("lockout is not per user: %d", got.Code)
	}
	// ...and a recovery code does not bypass it.
	if n, _ := e.st.CountRecoveryCodes(context.Background(), "r", "id-alice"); n != 10 {
		t.Fatal(n)
	}
	// Failures were audited.
	if len(e.events("MFA_FAILED")) != 5 {
		t.Errorf("MFA_FAILED events = %d, want 5", len(e.events("MFA_FAILED")))
	}
	// After the window the correct code works again.
	e.now = e.now.Add(11 * time.Minute)
	b3, w3 := e.codePage("alice")
	if got := b3.step(w3, url.Values{"code": {e.code("id-alice", 0)}}); !isRedirectWithCode(got) {
		t.Fatalf("not recovered after the window: %d %s", got.Code, got.Body)
	}
}

// A user's failures do not lock another user; IP limit applies across users.
func TestMFALockoutIsolationAndIPLimit(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	e.enrollDirect(e.bob)
	b, w := e.codePage("alice")
	for i := 0; i < 5; i++ {
		w = b.step(w, url.Values{"code": {"000000"}})
	}
	bb, bw := e.codePage("bob")
	if got := bb.step(bw, url.Values{"code": {e.code("id-bob", 0)}}); !isRedirectWithCode(got) {
		t.Fatalf("bob locked by alice's failures: %d", got.Code)
	}
	// IP limit: 30 attempts per window across users (alice's 5 + bob's 1 so far).
	e2 := newMFA(t, true)
	e2.enrollDirect(e2.alice)
	e2.enrollDirect(e2.bob)
	var denied bool
	for i := 0; i < 20 && !denied; i++ {
		for _, u := range []string{"alice", "bob"} {
			e2.now = e2.now.Add(0)
			bx, wx := e2.codePage(u)
			got := bx.step(wx, url.Values{"code": {"000000"}})
			if got.Code == http.StatusTooManyRequests && i >= 3 {
				denied = true
			}
		}
	}
	if !denied {
		t.Error("per-IP attempt limit never triggered")
	}
}

func TestMFARateLimitStoreErrorFailsClosed(t *testing.T) {
	var failing bool
	e := newMFA(t, true, func(c *Config) { c.Store = &flakyRL{Store: c.Store.(*memstore.Store), fail: &failing} })
	e.enrollDirect(e.alice)
	b, w := e.codePage("alice")
	failing = true
	got := b.step(w, url.Values{"code": {e.code("id-alice", 0)}})
	if isRedirectWithCode(got) || got.Code < 500 {
		t.Fatalf("limiter error did not fail closed: %d %s", got.Code, got.Body)
	}
	failing = false
	if got := b.step(w, url.Values{"code": {e.code("id-alice", 0)}}); !isRedirectWithCode(got) {
		t.Fatalf("login does not recover when the store does: %d", got.Code)
	}
}

type flakyRL struct {
	*memstore.Store
	fail *bool
}

func (f *flakyRL) HitRateLimit(ctx context.Context, key string, now time.Time, w time.Duration, max int) (bool, error) {
	if *f.fail {
		return false, errors.New("boom")
	}
	return f.Store.HitRateLimit(ctx, key, now, w, max)
}

func TestMFARecoveryCodeSingleUse(t *testing.T) {
	e := newMFA(t, true)
	codes := e.enrollDirect(e.alice)

	b, w := e.codePage("alice")
	got := b.step(w, url.Values{"code": {strings.ToLower(codes[0])}}) // case-insensitive
	if !isRedirectWithCode(got) {
		t.Fatalf("recovery code rejected: %d %s", got.Code, got.Body)
	}
	if n, _ := e.st.CountRecoveryCodes(context.Background(), "r", "id-alice"); n != 9 {
		t.Errorf("remaining %d", n)
	}
	if len(e.events("RECOVERY_USED")) != 1 {
		t.Error("RECOVERY_USED event missing")
	}
	var sawRecovery bool
	for _, ev := range e.events("LOGIN") {
		if ev.Detail == "recovery" {
			sawRecovery = true
		}
	}
	if !sawRecovery {
		t.Error("LOGIN detail recovery missing")
	}
	// Reuse fails, another code works.
	b2, w2 := e.codePage("alice")
	if got := b2.step(w2, url.Values{"code": {codes[0]}}); isRedirectWithCode(got) || !strings.Contains(got.Body.String(), mfaGeneric) {
		t.Fatalf("used recovery code accepted again: %d", got.Code)
	}
	if got := b2.step(w2, url.Values{"code": {codes[1]}}); !isRedirectWithCode(got) {
		t.Fatalf("second recovery code rejected: %d %s", got.Code, got.Body)
	}
	// Another user's codes are not valid for alice.
	bobCodes := e.enrollDirect(e.bob)
	b3, w3 := e.codePage("alice")
	if got := b3.step(w3, url.Values{"code": {bobCodes[0]}}); isRedirectWithCode(got) {
		t.Fatal("a recovery code of another user was accepted")
	}
}

// A wrong code looks the same whether or not the user has recovery codes, and
// whether the guess has the shape of a TOTP code or of a recovery code.
func TestMFAWrongCodeRevealsNothing(t *testing.T) {
	strip := regexp.MustCompile(`(value|nonce)="[^"]*"`) // csrf, proof and CSP nonce differ per render
	render := func(e *mfaEnv, guess string) string {
		b, w := e.codePage("alice")
		got := b.step(w, url.Values{"code": {guess}})
		return fmt.Sprintf("%d|%s", got.Code, strip.ReplaceAllString(got.Body.String(), `value=""`))
	}
	withCodes := newMFA(t, true)
	withCodes.enrollDirect(withCodes.alice)
	noCodes := newMFA(t, true)
	noCodes.enrollDirect(noCodes.alice)
	_ = noCodes.st.ReplaceRecoveryCodes(context.Background(), "r", "id-alice", nil)

	ref := render(withCodes, "000000")
	for name, got := range map[string]string{
		"totp-shaped, no recovery codes":     render(noCodes, "000000"),
		"recovery-shaped, with codes":        render(withCodes, "ABCDE-FGHJK"),
		"recovery-shaped, no recovery codes": render(noCodes, "ABCDE-FGHJK"),
		"garbage":                            render(withCodes, "hello world!"),
	} {
		if got != ref {
			t.Errorf("%s: response differs from the reference wrong-code page", name)
		}
	}
	if strings.Contains(strings.ToLower(ref), "recovery") && strings.Contains(strings.ToLower(ref), "remaining") {
		t.Error("wrong-code page mentions recovery code counts")
	}
}

func TestMFABareCodeWithoutProofRejected(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	b := e.mfaBrowser()
	b.get(authURL())
	code := e.code("id-alice", 0)
	for name, f := range map[string]url.Values{
		"code only":              {"code": {code}},
		"code + user id":         {"code": {code}, "username": {"alice"}},
		"empty proof":            {"code": {code}, "mfa_token": {""}},
		"recovery only":          {"code": {"ABCDE-FGHJK"}},
		"proof is the csrf":      {"code": {code}, "mfa_token": {"csrf-placeholder"}},
		"username, no password":  {"code": {code}, "username": {"alice"}, "password": {""}},
		"garbage proof":          {"code": {code}, "mfa_token": {"abc.def"}},
		"proof as the user name": {"code": {code}, "username": {"id-alice"}, "password": {code}},
	} {
		f.Set("csrf", b.csrf)
		if f.Get("mfa_token") == "csrf-placeholder" {
			f.Set("mfa_token", b.csrf)
		}
		got := b.post(authURL(), f)
		if isRedirectWithCode(got) || b.hasSSO() {
			t.Errorf("%s: login completed without a proof", name)
		}
		if got.Code != 200 {
			t.Errorf("%s: status %d, want the login page", name, got.Code)
		}
	}
	if n := len(e.events("LOGIN")); n != 0 {
		t.Errorf("%d LOGIN events: a code was issued", n)
	}
}

func TestMFAProofValidation(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	e.enrollDirect(e.bob)
	good := e.code("id-alice", 0)

	b, w := e.codePage("alice")
	realTok := tokenRe.FindStringSubmatch(w.Body.String())[1]
	rawURL := authURL()
	otherQuery := base + "auth?" + authQuery(map[string]string{"state": "other-state"}).Encode()

	mint := func(realm, user, purpose, payload string, ttl time.Duration) string {
		return e.h.signPending(realm, user, purpose, payload, ttl)
	}
	bind := mfaBind(httptest.NewRequest("POST", rawURL, nil))
	valid := "verify|" + bind

	post := func(tok, to string) *httptest.ResponseRecorder {
		return b.post(to, url.Values{"csrf": {b.csrf}, "mfa_token": {tok}, "code": {good}})
	}

	cases := map[string]string{
		"other realm":                mint("other", "id-alice", mfaPurpose, valid, time.Minute),
		"other purpose":              mint("r", "id-alice", "test-step", valid, time.Minute),
		"expired":                    mint("r", "id-alice", mfaPurpose, valid, -time.Second),
		"other user (bob)":           mint("r", "id-bob", mfaPurpose, valid, time.Minute), // alice's code, bob's credential
		"unknown user":               mint("r", "id-nobody", mfaPurpose, valid, time.Minute),
		"unknown mode":               mint("r", "id-alice", mfaPurpose, "root|"+bind, time.Minute),
		"no mode":                    mint("r", "id-alice", mfaPurpose, "", time.Minute),
		"enroll mode, enrolled user": mint("r", "id-alice", mfaPurpose, "enroll|"+bind, time.Minute),
		"done mode, no extra":        mint("r", "id-alice", mfaPurpose, "done|"+bind, time.Minute),
		"wrong binding":              mint("r", "id-alice", mfaPurpose, "verify|0000000000000000", time.Minute),
		"tampered":                   realTok[:len(realTok)-3] + "AAA",
	}
	for name, tok := range cases {
		if got := post(tok, rawURL); isRedirectWithCode(got) {
			t.Errorf("%s: proof accepted", name)
		}
	}
	// A proof minted for one authorization request cannot be replayed on another.
	if got := post(realTok, otherQuery); isRedirectWithCode(got) {
		t.Error("proof accepted on a different authorization request")
	}
	// The valid combination does work.
	if got := post(realTok, rawURL); !isRedirectWithCode(got) {
		t.Fatalf("valid proof + valid code rejected: %d %s", got.Code, got.Body)
	}
}

// requireMfa: a user without a credential must enroll inside the login flow and
// cannot skip it.
func TestMFARequiredForcesEnrollment(t *testing.T) {
	e := newMFA(t, true)
	e.setPolicy(true)
	b := e.mfaBrowser()
	w := b.password("alice", "pw")
	if w.Code != 200 || isRedirectWithCode(w) || !strings.Contains(w.Body.String(), "requires a second factor") || b.hasSSO() {
		t.Fatalf("enrollment page not shown: %d %s", w.Code, w.Body)
	}
	assertStepHeaders(t, w)
	m := secretRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatal("no secret on the enrollment page")
	}
	seed, _ := totp.DecodeSeed(m[1])

	// Skipping attempts. None may produce a code or an SSO session.
	enrollTok := tokenRe.FindStringSubmatch(w.Body.String())[1]
	bind := mfaBind(httptest.NewRequest("POST", authURL(), nil))
	skip := map[string]url.Values{
		"no proof":                    {},
		"continue as done, no proof":  {"mfa_token": {e.h.signPending("r", "id-alice", mfaPurpose, "done|"+bind+"|123", time.Minute)}},
		"verify proof, no credential": {"mfa_token": {e.h.signPending("r", "id-alice", mfaPurpose, "verify|"+bind, time.Minute)}, "code": {totp.Code(seed, e.now)}},
		"enroll proof, wrong code":    {"mfa_token": {enrollTok}, "code": {"000000"}},
		"enroll proof, empty code":    {"mfa_token": {enrollTok}},
	}
	for name, f := range skip {
		f.Set("csrf", b.csrf)
		got := b.post(authURL(), f)
		if isRedirectWithCode(got) || b.hasSSO() {
			t.Errorf("%s: login completed without enrolling", name)
		}
	}
	// Navigating straight to /auth (no prompt) or the account page with this
	// mfaBrowser (half-finished login) gets neither a code nor a session.
	if got := b.get(authURL()); isRedirectWithCode(got) {
		t.Error("GET /auth issued a code for a half-finished login")
	}
	if got := b.get("/realms/r/account/totp"); got.Code != http.StatusUnauthorized {
		t.Errorf("account page reachable by a half-finished login: %d", got.Code)
	}
	if c, _ := e.st.GetTOTP(context.Background(), "r", "id-alice"); c.Confirmed {
		t.Fatal("credential confirmed by a skipping attempt")
	}

	// Enroll for real.
	good := b.step(w, url.Values{"code": {totp.Code(seed, e.now)}})
	if good.Code != 200 || isRedirectWithCode(good) || b.hasSSO() {
		t.Fatalf("enrollment confirm: %d %s", good.Code, good.Body)
	}
	codes := recCodeRe.FindAllString(good.Body.String(), -1)
	if len(codes) != 10 || !strings.Contains(good.Body.String(), "Save these recovery codes now") {
		t.Fatalf("recovery codes page: %d codes\n%s", len(codes), good.Body)
	}
	// Still no login until the user continues.
	if b.hasSSO() {
		t.Fatal("SSO session before the codes were acknowledged")
	}
	fin := b.step(good, nil)
	if !isRedirectWithCode(fin) || !b.hasSSO() {
		t.Fatalf("continue after codes: %d %s", fin.Code, fin.Body)
	}
	// Next login asks for the code, as for any enrolled user.
	e.now = e.now.Add(35 * time.Second)
	b3 := e.mfaBrowser()
	w3 := b3.password("alice", "pw")
	if !strings.Contains(w3.Body.String(), "Two-step verification") {
		t.Fatalf("enrolled user not asked for a code: %d", w3.Code)
	}
	if got := b3.step(w3, url.Values{"code": {totp.Code(seed, e.now)}}); !isRedirectWithCode(got) {
		t.Fatalf("login with code: %d %s", got.Code, got.Body)
	}
	// SSO re-login stays silent for users with a session even if policy applies.
	if got := b3.get(authURL()); !isRedirectWithCode(got) {
		t.Errorf("SSO re-login affected by the policy: %d", got.Code)
	}
	if len(e.events("TOTP_ENROLLED")) != 1 {
		t.Error("TOTP_ENROLLED missing")
	}
}

// Re-using the enrollment page's CSRF / proof after the credential exists, and
// replaying a done proof after the credential was removed, must not work.
func TestMFADoneProofDiesWithCredential(t *testing.T) {
	e := newMFA(t, true)
	e.setPolicy(true)
	b := e.mfaBrowser()
	w := b.password("alice", "pw")
	seed, _ := totp.DecodeSeed(secretRe.FindStringSubmatch(w.Body.String())[1])
	done := b.step(w, url.Values{"code": {totp.Code(seed, e.now)}})
	_ = e.st.DeleteUserMFA(context.Background(), "r", "id-alice") // admin reset
	if got := b.step(done, nil); isRedirectWithCode(got) || b.hasSSO() {
		t.Fatalf("done proof outlived the credential: %d", got.Code)
	}
	// ...and not even when the user enrolls AGAIN afterwards: the proof names
	// the credential it was minted for.
	e.enrollDirect(e.alice)
	if got := b.step(done, nil); isRedirectWithCode(got) || b.hasSSO() {
		t.Fatalf("done proof of an old credential accepted for a new one: %d", got.Code)
	}
}

// enrollViaLogin enrolls a user through the real enrollment pages (so the seed
// is sealed by the handler itself) and returns the plaintext seed.
func (e *mfaEnv) enrollViaLogin(user string) []byte {
	e.t.Helper()
	e.setPolicy(true)
	defer e.setPolicy(false)
	b := e.mfaBrowser()
	w := b.password(user, "pw")
	m := secretRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		e.t.Fatalf("no enrollment page: %d %s", w.Code, w.Body)
	}
	seed, _ := totp.DecodeSeed(m[1])
	done := b.step(w, url.Values{"code": {totp.Code(seed, e.now)}})
	if fin := b.step(done, nil); !isRedirectWithCode(fin) {
		e.t.Fatalf("enrollment did not complete: %d", fin.Code)
	}
	return seed
}

func TestMFAPolicyOffDoesNotForceEnrollment(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()
	if w := b.password("alice", "pw"); !isRedirectWithCode(w) {
		t.Fatalf("login without policy and credential: %d", w.Code)
	}
	// A pending (never confirmed) credential does not trigger the code page.
	e2 := newMFA(t, true)
	st := e2.st
	_ = st.PutTOTP(context.Background(), core.TOTPCredential{Realm: "r", UserID: "id-alice", CreatedAt: e2.now,
		SealedSeed: e2.box.Seal(totp.NewSeed(), "totp|r|id-alice")})
	if w := e2.mfaBrowser().password("alice", "pw"); !isRedirectWithCode(w) {
		t.Fatalf("pending credential blocked login: %d", w.Code)
	}
}

func TestMFADisabledAndLockedUsersNeverReachStep(t *testing.T) {
	e := newMFA(t, true)
	e.enrollDirect(e.alice)
	u := e.alice
	u.Enabled = false
	if err := e.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	w := e.mfaBrowser().password("alice", "pw")
	if strings.Contains(w.Body.String(), "Two-step verification") || isRedirectWithCode(w) {
		t.Fatalf("disabled user reached the step: %d", w.Code)
	}
	// Disabled between the password step and the code.
	e2 := newMFA(t, true)
	e2.enrollDirect(e2.alice)
	b, pw := e2.codePage("alice")
	u2 := e2.alice
	u2.Enabled = false
	_ = e2.st.UpdateUser(context.Background(), u2)
	if got := b.step(pw, url.Values{"code": {e2.code("id-alice", 0)}}); isRedirectWithCode(got) {
		t.Fatal("user disabled after the password step still logged in")
	}
}

func TestMFASecretBoxContextBinding(t *testing.T) {
	e := newMFA(t, true)
	aliceSeed := e.enrollViaLogin("alice") // sealed by the handler, not by the test
	e.now = e.now.Add(35 * time.Second)
	ctx := context.Background()
	aliceCred, _ := e.st.GetTOTP(ctx, "r", "id-alice")

	// The sealed seed is bound to realm+user.
	for _, wrong := range []string{"totp|r|id-bob", "totp|other|id-alice", "totp|r|id-alice ", "device|r|id-alice"} {
		if _, err := e.box.Open(aliceCred.SealedSeed, wrong); err == nil {
			t.Errorf("seed opened with context %q", wrong)
		}
	}
	// Copy alice's sealed seed to bob's row: bob can never log in with alice's codes.
	if err := e.st.PutTOTP(ctx, core.TOTPCredential{Realm: "r", UserID: "id-bob", CreatedAt: e.now, SealedSeed: aliceCred.SealedSeed}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.st.ConfirmTOTP(ctx, "r", "id-bob", 1); !ok {
		t.Fatal("setup")
	}
	b, w := e.codePage("bob")
	got := b.step(w, url.Values{"code": {totp.Code(aliceSeed, e.now)}})
	if isRedirectWithCode(got) || b.hasSSO() {
		t.Fatal("alice's seed copied to bob's row logged bob in")
	}
	if got.Code < 500 {
		t.Errorf("an unopenable seed should fail closed with a server error, got %d", got.Code)
	}
	if strings.Contains(e.logs.String(), aliceCred.SealedSeed) || strings.Contains(e.logs.String(), totp.EncodeSeed(aliceSeed)) {
		t.Error("seed material in logs")
	}
}

func TestMFAAccountDisableRegenerateAndReauth(t *testing.T) {
	e := newMFA(t, true)
	codes := e.enrollDirect(e.alice)
	b := e.mfaBrowser()
	// Log in with a code to get an SSO session.
	w := b.password("alice", "pw")
	if got := b.step(w, url.Values{"code": {e.code("id-alice", 0)}}); !isRedirectWithCode(got) {
		t.Fatal("setup login failed")
	}
	acct := func() (*httptest.ResponseRecorder, string) {
		g := b.get("/realms/r/account/totp")
		return g, csrfRe.FindStringSubmatch(g.Body.String())[1]
	}
	postAcct := func(f url.Values) *httptest.ResponseRecorder {
		_, cs := acct()
		f.Set("csrf", cs)
		return b.post("/realms/r/account/totp", f)
	}

	// Fresh session: no password needed. A wrong code does nothing.
	if got := postAcct(url.Values{"action": {"regenerate"}, "code": {"111111"}}); !strings.Contains(got.Body.String(), mfaGeneric) || recCodeRe.MatchString(got.Body.String()) {
		t.Fatalf("regenerate with wrong code: %s", got.Body)
	}
	e.now = e.now.Add(35 * time.Second)
	got := postAcct(url.Values{"action": {"regenerate"}, "code": {e.code("id-alice", 0)}})
	newCodes := recCodeRe.FindAllString(got.Body.String(), -1)
	if len(newCodes) != 10 || len(e.events("RECOVERY_REGENERATED")) != 1 {
		t.Fatalf("regenerate: %d codes %s", len(newCodes), got.Body)
	}
	// Old set is dead, new set lives.
	e.now = e.now.Add(35 * time.Second)
	b2, w2 := e.codePage("alice")
	if r := b2.step(w2, url.Values{"code": {codes[0]}}); isRedirectWithCode(r) {
		t.Fatal("old recovery code survived regeneration")
	}
	if r := b2.step(w2, url.Values{"code": {newCodes[0]}}); !isRedirectWithCode(r) {
		t.Fatal("new recovery code rejected")
	}

	// Session older than 10 minutes: password required.
	e.now = e.now.Add(11 * time.Minute)
	pg, _ := acct()
	if !strings.Contains(pg.Body.String(), `name="password"`) {
		t.Fatal("stale session: password field missing")
	}
	// (the SSO idle time is 30 minutes by default, so the session is still live)
	code := e.code("id-alice", 0)
	if r := postAcct(url.Values{"action": {"disable"}, "code": {code}}); !strings.Contains(r.Body.String(), "Wrong password") {
		t.Fatalf("disable without password on a stale session: %s", r.Body)
	}
	if c, _ := e.st.GetTOTP(context.Background(), "r", "id-alice"); !c.Confirmed {
		t.Fatal("disabled without re-authentication")
	}
	if r := postAcct(url.Values{"action": {"disable"}, "code": {code}, "password": {"nope"}}); !strings.Contains(r.Body.String(), "Wrong password") {
		t.Fatal("wrong password accepted")
	}
	// Right password, wrong code.
	if r := postAcct(url.Values{"action": {"disable"}, "code": {"222222"}, "password": {"pw"}}); !strings.Contains(r.Body.String(), mfaGeneric) {
		t.Fatalf("disable with wrong code: %s", r.Body)
	}
	if c, _ := e.st.GetTOTP(context.Background(), "r", "id-alice"); !c.Confirmed {
		t.Fatal("disabled with a wrong code")
	}
	// Right password and a recovery code.
	r := postAcct(url.Values{"action": {"disable"}, "code": {newCodes[1]}, "password": {"pw"}})
	if !strings.Contains(r.Body.String(), "is <strong>off</strong>") {
		t.Fatalf("disable: %s", r.Body)
	}
	if _, err := e.st.GetTOTP(context.Background(), "r", "id-alice"); err == nil {
		t.Fatal("credential still present")
	}
	if n, _ := e.st.CountRecoveryCodes(context.Background(), "r", "id-alice"); n != 0 {
		t.Fatalf("recovery codes survived disable: %d", n)
	}
	if len(e.events("TOTP_DISABLED")) != 1 || len(e.events("RECOVERY_USED")) < 2 {
		t.Errorf("events: disabled=%d recovery_used=%d", len(e.events("TOTP_DISABLED")), len(e.events("RECOVERY_USED")))
	}
	// Login no longer needs a code.
	if w := e.mfaBrowser().password("alice", "pw"); !isRedirectWithCode(w) {
		t.Fatalf("login after disable: %d", w.Code)
	}
}

func TestMFAAccountStartRequiresFreshAuthAndRefusesWhenOn(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()
	if w := b.password("alice", "pw"); !isRedirectWithCode(w) {
		t.Fatal("setup")
	}
	e.now = e.now.Add(11 * time.Minute)
	g := b.get("/realms/r/account/totp")
	cs := csrfRe.FindStringSubmatch(g.Body.String())[1]
	got := b.post("/realms/r/account/totp", url.Values{"action": {"start"}, "csrf": {cs}})
	if secretRe.MatchString(got.Body.String()) {
		t.Fatal("enrollment started on a stale session without the password")
	}
	cs = csrfRe.FindStringSubmatch(got.Body.String())[1]
	got = b.post("/realms/r/account/totp", url.Values{"action": {"start"}, "csrf": {cs}, "password": {"pw"}})
	if !secretRe.MatchString(got.Body.String()) {
		t.Fatalf("start with password: %s", got.Body)
	}
	// Once confirmed, start is refused and never replaces the credential.
	seed, _ := totp.DecodeSeed(secretRe.FindStringSubmatch(got.Body.String())[1])
	cs = csrfRe.FindStringSubmatch(got.Body.String())[1]
	got = b.post("/realms/r/account/totp", url.Values{"action": {"confirm"}, "csrf": {cs}, "code": {totp.Code(seed, e.now)}})
	if !strings.Contains(got.Body.String(), "Save these recovery codes now") {
		t.Fatal("confirm failed")
	}
	before, _ := e.st.GetTOTP(context.Background(), "r", "id-alice")
	got = b.get("/realms/r/account/totp")
	cs = b.csrf
	got = b.post("/realms/r/account/totp", url.Values{"action": {"start"}, "csrf": {cs}, "password": {"pw"}})
	after, _ := e.st.GetTOTP(context.Background(), "r", "id-alice")
	if secretRe.MatchString(got.Body.String()) || before.SealedSeed != after.SealedSeed || !after.Confirmed {
		t.Fatal("an enrolled credential was replaced by a second start")
	}
}

func TestMFAAccountPageUnauthenticatedVariants(t *testing.T) {
	e := newMFA(t, true)
	b := e.mfaBrowser()
	if w := b.password("alice", "pw"); !isRedirectWithCode(w) {
		t.Fatal("setup")
	}
	// Disabled user with a live session.
	u := e.alice
	u.Enabled = false
	_ = e.st.UpdateUser(context.Background(), u)
	if w := b.get("/realms/r/account/totp"); w.Code != http.StatusForbidden {
		t.Errorf("disabled user: %d", w.Code)
	}
	// Unknown realm.
	if w := b.get("/realms/nope/account/totp"); w.Code != http.StatusNotFound {
		t.Errorf("unknown realm: %d", w.Code)
	}
	// A session of another realm does not open this realm's page.
	b2 := e.mfaBrowser()
	if w := b2.get("/realms/other/account/totp"); w.Code != http.StatusUnauthorized {
		t.Errorf("other realm without session: %d", w.Code)
	}
}

// barrierStore makes GetTOTP wait (once armed) until `need` callers are inside.
type barrierStore struct {
	*memstore.Store
	need    int
	mu      sync.Mutex
	armed   bool
	in      int
	release chan struct{}
}

func (b *barrierStore) arm() {
	b.mu.Lock()
	b.armed = true
	b.mu.Unlock()
}

func (b *barrierStore) GetTOTP(ctx context.Context, realm, userID string) (core.TOTPCredential, error) {
	c, err := b.Store.GetTOTP(ctx, realm, userID)
	b.mu.Lock()
	if b.armed {
		b.in++
		if b.in == b.need {
			close(b.release)
		}
	}
	armed := b.armed
	b.mu.Unlock()
	if armed {
		select {
		case <-b.release:
		case <-time.After(5 * time.Second):
		}
	}
	return c, err
}
