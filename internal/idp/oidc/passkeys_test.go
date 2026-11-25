// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/webauthn/webauthntest"
)

const (
	pkOrigin = "https://idp.example"
	pkRPID   = "idp.example"
	pkPW     = "S3cret-pass-1"
)

// pkEnv is a real memstore + signer + argon2 provider with a fake clock and a
// tiny cookie-keeping browser.
type pkEnv struct {
	t       *testing.T
	st      *memstore.Store
	h       *Provider
	now     time.Time
	cookies map[string]*http.Cookie
	user    core.User
}

func newPKEnv(t *testing.T, mut func(*core.Realm), wrap func(core.Store) core.Store, cfg func(*Config)) *pkEnv {
	t.Helper()
	ctx := context.Background()
	e := &pkEnv{t: t, st: memstore.New(), now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), cookies: map[string]*http.Cookie{}}
	rl := core.Realm{Name: "r", Enabled: true, BruteForceProtection: true, AuthEventsLogged: true,
		RefreshTokenRotation: true, AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour}
	if mut != nil {
		mut(&rl)
	}
	must(t, e.st.CreateRealm(ctx, rl))
	must(t, e.st.CreateClient(ctx, core.Client{Realm: "r", ClientID: "app", Enabled: true, Public: true, AuthCodeFlow: true, RedirectURIs: []string{cb}}))
	hasher := password.New(password.TestParams)
	hash, err := hasher.Hash(pkPW)
	must(t, err)
	e.user = core.User{ID: "u1", Realm: "r", Username: "alice", Email: "a@x", Enabled: true, EmailVerified: true, PasswordHash: hash}
	must(t, e.st.CreateUser(ctx, e.user))
	signer := keys.New(e.st, keys.Options{})
	must(t, signer.EnsureKey(ctx, "r"))
	var store core.Store = e.st
	if wrap != nil {
		store = wrap(store)
	}
	c := Config{Store: store, Signer: signer, Hasher: hasher, BaseURL: pkOrigin, Clock: func() time.Time { return e.now },
		CSRFKey: []byte("0123456789abcdef0123456789abcdef")}
	if cfg != nil {
		cfg(&c)
	}
	e.h = New(c)
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *pkEnv) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.RemoteAddr = "192.0.2.1:1234"
	for _, c := range e.cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(e.cookies, c.Name)
		} else {
			e.cookies[c.Name] = c
		}
	}
	return w
}

var (
	optsRe    = regexp.MustCompile(`data-opts="([^"]*)"`)
	pkTokenRe = regexp.MustCompile(`name="pk_token" value="([^"]+)"`)
	authPath  = base + "auth?"
)

type pkPage struct {
	opts      map[string]any
	token     string
	csrf      string
	body      string
	challenge []byte
}

func parsePKPage(t *testing.T, w *httptest.ResponseRecorder) pkPage {
	t.Helper()
	body := w.Body.String()
	m := optsRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no passkey options in page (status %d): %s", w.Code, body)
	}
	var pg pkPage
	must(t, json.Unmarshal([]byte(html.UnescapeString(m[1])), &pg.opts))
	pg.token = pkTokenRe.FindStringSubmatch(body)[1]
	pg.csrf = csrfRe.FindStringSubmatch(body)[1]
	pg.body = body
	ch, err := base64.RawURLEncoding.DecodeString(pg.opts["challenge"].(string))
	must(t, err)
	pg.challenge = ch
	return pg
}

func bu(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// loginPage returns the (passkey-enabled) login page.
func (e *pkEnv) loginPage() *httptest.ResponseRecorder {
	return e.do("GET", authPath+authQuery(nil).Encode(), nil)
}

// passwordLogin posts username/password through the login form.
func (e *pkEnv) passwordLogin(pw string) *httptest.ResponseRecorder {
	w := e.loginPage()
	csrf := csrfRe.FindStringSubmatch(w.Body.String())[1]
	return e.do("POST", authPath+authQuery(nil).Encode(), url.Values{"csrf": {csrf}, "username": {"alice"}, "password": {pw}})
}

func (e *pkEnv) accountPath() string { return "/realms/r/account/passkeys" }

// register performs a full passkey registration through the account page and
// returns the authenticator.
func (e *pkEnv) register(alg int) *webauthntest.Authenticator {
	e.t.Helper()
	w := e.passwordLogin(pkPW)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "code=") {
		e.t.Fatalf("password login failed: %d %s", w.Code, w.Body)
	}
	return e.addPasskey(alg)
}

func (e *pkEnv) addPasskey(alg int) *webauthntest.Authenticator {
	e.t.Helper()
	pg := parsePKPage(e.t, e.do("GET", e.accountPath(), nil))
	a := webauthntest.New(alg, pkRPID)
	user := pg.opts["user"].(map[string]any)
	uh, err := base64.RawURLEncoding.DecodeString(user["id"].(string))
	must(e.t, err)
	a.UserHandle = uh
	cd, obj := a.Create(pg.challenge, pkOrigin)
	w := e.do("POST", e.accountPath(), url.Values{"csrf": {pg.csrf}, "pk_action": {"add"}, "pk_token": {pg.token},
		"pk_cd": {bu(cd)}, "pk_att": {bu(obj)}, "pk_tr": {"internal,bogus"}, "name": {"My laptop"}})
	if w.Code != http.StatusSeeOther {
		e.t.Fatalf("registration failed: %d %s", w.Code, w.Body)
	}
	return a
}

// assertionForm builds the posted fields for a login page or step page.
func assertionForm(pg pkPage, mode string, a *webauthntest.Authenticator, origin string) url.Values {
	cd, ad, sig := a.Get(pg.challenge, origin)
	return url.Values{"csrf": {pg.csrf}, "pk_mode": {mode}, "pk_token": {pg.token}, "pk_cred": {bu(a.CredID)},
		"pk_cd": {bu(cd)}, "pk_ad": {bu(ad)}, "pk_sig": {bu(sig)}, "pk_uh": {bu(a.UserHandle)}}
}

func (e *pkEnv) events(typ string) int {
	evs, _ := e.st.ListEvents(context.Background(), "r", 1000)
	n := 0
	for _, ev := range evs {
		if ev.Type == typ {
			n++
		}
	}
	return n
}

func (e *pkEnv) forget() { e.cookies = map[string]*http.Cookie{} }

func isCode(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusFound && strings.Contains(w.Header().Get("Location"), "code=")
}

const genericFail = "Passkey sign-in failed"

// ---- tests ----

func TestPasskeyRegisterAndLoginBothWays(t *testing.T) {
	for _, alg := range []int{-7, -8, -257} {
		e := newPKEnv(t, nil, nil, nil)
		a := e.register(alg)
		pks, _ := e.st.ListPasskeys(context.Background(), "r", "u1")
		if len(pks) != 1 || pks[0].Name != "My laptop" || strings.Join(pks[0].Transports, ",") != "internal" || pks[0].CredentialID != bu(a.CredID) {
			t.Fatalf("stored credential: %+v", pks)
		}
		if e.events("PASSKEY_REGISTERED") != 1 {
			t.Error("no PASSKEY_REGISTERED event")
		}
		e.forget()

		// First factor: passkey button, discoverable credential, no password.
		lp := e.loginPage()
		csp := lp.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'nonce-") || strings.Contains(csp, "unsafe") || !strings.Contains(lp.Body.String(), "Sign in with a passkey") {
			t.Fatalf("login page lacks passkey support or CSP is wrong: %s", csp)
		}
		if strings.Contains(lp.Body.String(), "src=") {
			t.Error("login page loads external script")
		}
		pg := parsePKPage(t, lp)
		if pg.opts["userVerification"] != "required" {
			t.Errorf("first factor must require UV: %v", pg.opts)
		}
		if _, has := pg.opts["allowCredentials"]; has {
			t.Error("discoverable login must not list credentials (user enumeration)")
		}
		w := e.do("POST", authPath+authQuery(nil).Encode(), assertionForm(pg, "login", a, pkOrigin))
		if !isCode(w) {
			t.Fatalf("alg %d: passkey login failed: %d %s", alg, w.Code, w.Body)
		}
		if e.events("PASSKEY_LOGIN") != 1 {
			t.Error("no PASSKEY_LOGIN event")
		}
		if got, _ := e.st.GetPasskey(context.Background(), "r", bu(a.CredID)); got.SignCount != 1 || got.LastUsedAt.IsZero() {
			t.Errorf("use not recorded: %+v", got)
		}

		// Second factor after the password.
		e.forget()
		w = e.passwordLogin(pkPW)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Use your passkey") {
			t.Fatalf("no second factor step: %d %s", w.Code, w.Body)
		}
		if strings.Contains(w.Header().Get("Set-Cookie"), "haven_sso") {
			t.Fatal("session before second factor")
		}
		pg = parsePKPage(t, w)
		if pg.opts["userVerification"] != "preferred" || len(pg.opts["allowCredentials"].([]any)) != 1 {
			t.Errorf("2fa options: %v", pg.opts)
		}
		w = e.do("POST", authPath+authQuery(nil).Encode(), assertionForm(pg, "2fa", a, pkOrigin))
		if !isCode(w) {
			t.Fatalf("alg %d: passkey 2fa failed: %d %s", alg, w.Code, w.Body)
		}
	}
}

func TestPasskeyNegativeAssertions(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	e.forget()
	post := func(pg pkPage, f url.Values) *httptest.ResponseRecorder {
		return e.do("POST", authPath+authQuery(nil).Encode(), f)
	}
	fresh := func() pkPage { return parsePKPage(t, e.loginPage()) }

	t.Run("replay of a captured assertion", func(t *testing.T) {
		pg := fresh()
		f := assertionForm(pg, "login", a, pkOrigin)
		if !isCode(post(pg, f)) {
			t.Fatal("first use must succeed")
		}
		e.forget()
		pg2 := fresh() // fresh csrf cookie for the replay, SAME captured fields
		f.Set("csrf", pg2.csrf)
		w := post(pg2, f)
		if isCode(w) || !strings.Contains(w.Body.String(), genericFail) {
			t.Fatalf("replayed assertion accepted: %d", w.Code)
		}
		e.forget()
	})
	t.Run("wrong origin", func(t *testing.T) {
		pg := fresh()
		if w := post(pg, assertionForm(pg, "login", a, "https://evil.example")); isCode(w) {
			t.Fatal("accepted")
		}
	})
	t.Run("wrong rp id", func(t *testing.T) {
		pg := fresh()
		o := webauthntest.New(-7, "evil.example")
		o.CredID, o.UserHandle = a.CredID, a.UserHandle
		if w := post(pg, assertionForm(pg, "login", o, pkOrigin)); isCode(w) {
			t.Fatal("accepted")
		}
	})
	t.Run("missing UV on first factor", func(t *testing.T) {
		pg := fresh()
		a.UV = false
		defer func() { a.UV = true }()
		if w := post(pg, assertionForm(pg, "login", a, pkOrigin)); isCode(w) {
			t.Fatal("passkey login without user verification accepted")
		}
	})
	t.Run("challenge from another page", func(t *testing.T) {
		pg, other := fresh(), fresh()
		f := assertionForm(other, "login", a, pkOrigin) // signed over other's challenge
		f.Set("pk_token", pg.token)                     // but presented with this page's token
		if w := post(pg, f); isCode(w) {
			t.Fatal("accepted")
		}
	})
	t.Run("bad signature and unknown credential look identical", func(t *testing.T) {
		pg := fresh()
		f := assertionForm(pg, "login", a, pkOrigin)
		sig, _ := base64.RawURLEncoding.DecodeString(f.Get("pk_sig"))
		sig[len(sig)-1] ^= 1
		f.Set("pk_sig", bu(sig))
		w1 := post(pg, f)
		pg = fresh()
		ghost := webauthntest.New(-7, pkRPID)
		ghost.UserHandle = a.UserHandle
		w2 := post(pg, assertionForm(pg, "login", ghost, pkOrigin))
		strip := func(s string) string {
			s = regexp.MustCompile(`value="[^"]*"`).ReplaceAllString(s, "")
			s = regexp.MustCompile(`nonce="[^"]*"`).ReplaceAllString(s, "")
			s = regexp.MustCompile(`data-opts="[^"]*"`).ReplaceAllString(s, "")
			return regexp.MustCompile(`nonce-[A-Za-z0-9_-]+`).ReplaceAllString(s, "")
		}
		if isCode(w1) || isCode(w2) || w1.Code != w2.Code || strip(w1.Body.String()) != strip(w2.Body.String()) {
			t.Fatalf("responses differ (%d vs %d): unknown credentials are distinguishable", w1.Code, w2.Code)
		}
	})
	t.Run("user handle of someone else", func(t *testing.T) {
		pg := fresh()
		f := assertionForm(pg, "login", a, pkOrigin)
		f.Set("pk_uh", bu([]byte("not-the-users-handle-xxxxxxxxxxxx")))
		if isCode(post(pg, f)) {
			t.Fatal("accepted")
		}
		f2 := assertionForm(fresh(), "login", a, pkOrigin)
		f2.Del("pk_uh")
		if isCode(post(pg, f2)) {
			t.Fatal("accepted without a user handle")
		}
	})
	t.Run("valid handle of a different user", func(t *testing.T) {
		must(t, e.st.CreateUser(context.Background(), core.User{ID: "u9", Realm: "r", Username: "mallory", Enabled: true, EmailVerified: true}))
		h, err := e.st.UserHandle(context.Background(), "r", "u9", bu([]byte("mallorys-own-user-handle-0123456")))
		must(t, err)
		hb, _ := base64.RawURLEncoding.DecodeString(h)
		pg := fresh()
		f := assertionForm(pg, "login", a, pkOrigin) // alice's credential and signature...
		f.Set("pk_uh", bu(hb))                       // ...claimed by mallory's handle
		if isCode(post(pg, f)) {
			t.Fatal("credential accepted for a user whose handle it does not carry")
		}
	})
	t.Run("garbage and oversize fields", func(t *testing.T) {
		pg := fresh()
		f := assertionForm(pg, "login", a, pkOrigin)
		f.Set("pk_cd", strings.Repeat("A", 50000))
		if isCode(post(pg, f)) {
			t.Fatal("accepted")
		}
		pg = fresh()
		f = assertionForm(pg, "login", a, pkOrigin)
		f.Set("pk_ad", "!!!not base64")
		if isCode(post(pg, f)) {
			t.Fatal("accepted")
		}
	})
	t.Run("expired challenge", func(t *testing.T) {
		pg := fresh()
		e.now = e.now.Add(6 * time.Minute)
		defer func() { e.now = e.now.Add(-6 * time.Minute) }()
		if isCode(post(pg, assertionForm(pg, "login", a, pkOrigin))) {
			t.Fatal("expired challenge accepted")
		}
	})
	t.Run("csrf is enforced", func(t *testing.T) {
		pg := fresh()
		f := assertionForm(pg, "login", a, pkOrigin)
		f.Set("csrf", "bogus")
		if w := post(pg, f); w.Code != http.StatusForbidden {
			t.Fatalf("passkey post without csrf: %d", w.Code)
		}
	})
	t.Run("login-mode token cannot answer a second factor", func(t *testing.T) {
		pg := fresh()
		if isCode(post(pg, assertionForm(pg, "2fa", a, pkOrigin))) {
			t.Fatal("login token accepted as 2fa token")
		}
	})
	if e.events("PASSKEY_FAILED") == 0 {
		t.Error("failures are not audited")
	}
}

func TestPasskeyCounterRegressionFlagsClone(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	e.forget()
	for i := 0; i < 2; i++ { // counter 1, 2
		pg := parsePKPage(t, e.loginPage())
		if !isCode(e.do("POST", authPath+authQuery(nil).Encode(), assertionForm(pg, "login", a, pkOrigin))) {
			t.Fatal("login failed")
		}
		e.forget()
	}
	a.SignCount, a.Counting = 1, false // a clone replays an old counter value
	pg := parsePKPage(t, e.loginPage())
	w := e.do("POST", authPath+authQuery(nil).Encode(), assertionForm(pg, "login", a, pkOrigin))
	if isCode(w) || !strings.Contains(w.Body.String(), genericFail) {
		t.Fatal("regressed counter accepted")
	}
	if e.events("PASSKEY_CLONE_SUSPECTED") != 1 {
		t.Error("clone suspicion not audited")
	}
	if got, _ := e.st.GetPasskey(context.Background(), "r", bu(a.CredID)); got.SignCount != 2 {
		t.Errorf("stored counter moved to %d", got.SignCount)
	}
}

func TestPasskeyRespectsAccountState(t *testing.T) {
	for name, tc := range map[string]struct {
		mut func(e *pkEnv)
		rl  func(*core.Realm)
	}{
		"disabled": {mut: func(e *pkEnv) {
			u, _ := e.st.GetUser(context.Background(), "r", "u1")
			u.Enabled = false
			must(e.t, e.st.UpdateUser(context.Background(), u))
		}},
		"locked": {mut: func(e *pkEnv) {
			u, _ := e.st.GetUser(context.Background(), "r", "u1")
			u.LockedUntil = e.now.Add(time.Hour)
			must(e.t, e.st.UpdateUser(context.Background(), u))
		}},
		"unverified email": {rl: func(r *core.Realm) { r.EmailVerificationRequired = true }, mut: func(e *pkEnv) {
			u, _ := e.st.GetUser(context.Background(), "r", "u1")
			u.EmailVerified = false
			must(e.t, e.st.UpdateUser(context.Background(), u))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newPKEnv(t, tc.rl, nil, nil)
			// Registration needs a verified user; flip state afterwards.
			a := e.register(-7)
			e.forget()
			tc.mut(e)
			for _, mode := range []string{"login", "2fa"} {
				var pg pkPage
				if mode == "login" {
					pg = parsePKPage(t, e.loginPage())
				} else {
					// Craft a 2fa token as the password step would have.
					_, tok := e.h.pkChallenge("r", "u1", pk2FA)
					chal := mustDecodeTok(t, e.h, tok)
					w := e.loginPage()
					pg = pkPage{token: tok, csrf: csrfRe.FindStringSubmatch(w.Body.String())[1], challenge: chal}
				}
				w := e.do("POST", authPath+authQuery(nil).Encode(), assertionForm(pg, mode, a, pkOrigin))
				if isCode(w) {
					t.Fatalf("%s passkey %s accepted", name, mode)
				}
				e.forget()
			}
		})
	}
}

func mustDecodeTok(t *testing.T, p *Provider, tok string) []byte {
	t.Helper()
	_, payload, ok := p.checkPending("r", tok, pk2FA)
	if !ok {
		t.Fatal("bad token")
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	must(t, err)
	return b
}

func TestPasskeySecondFactorBindsUser(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	// Bob also exists; alice's credential must not satisfy bob's second factor.
	must(t, e.st.CreateUser(context.Background(), core.User{ID: "u2", Realm: "r", Username: "bob", Enabled: true, EmailVerified: true}))
	chal, tok := e.h.pkChallenge("r", "u2", pk2FA)
	e.forget()
	w := e.loginPage()
	pg := pkPage{token: tok, csrf: csrfRe.FindStringSubmatch(w.Body.String())[1], challenge: chal}
	if isCode(e.do("POST", authPath+authQuery(nil).Encode(), assertionForm(pg, "2fa", a, pkOrigin))) {
		t.Fatal("another user's passkey accepted as second factor")
	}
}

func TestPasskeyRateLimitFailsClosed(t *testing.T) {
	var ls *limitStore
	e := newPKEnv(t, nil, func(s core.Store) core.Store { ls = &limitStore{Store: s}; return ls }, nil)
	a := e.register(-7)
	e.forget()
	ls.deny = true
	pg := parsePKPage(t, e.loginPage())
	w := e.do("POST", authPath+authQuery(nil).Encode(), assertionForm(pg, "login", a, pkOrigin))
	if isCode(w) || !strings.Contains(w.Body.String(), genericFail) {
		t.Fatalf("login proceeded although the rate limiter refused: %d", w.Code)
	}
}

// limitStore denies (or errors) every rate-limit hit but passes everything else through.
type limitStore struct {
	core.Store
	deny bool
	err  error
}

func (l *limitStore) HitRateLimit(context.Context, string, time.Time, time.Duration, int) (bool, error) {
	return !l.deny, l.err
}
func (l *limitStore) Unwrap() core.Store { return l.Store }

func TestPasskeyRateLimitCountsPerIP(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	e.forget()
	ghost := webauthntest.New(-7, pkRPID)
	for i := 0; i < pkAssertPerIP+3; i++ {
		pg := parsePKPage(t, e.loginPage())
		e.do("POST", authPath+authQuery(nil).Encode(), assertionForm(pg, "login", ghost, pkOrigin))
		e.forget()
	}
	pg := parsePKPage(t, e.loginPage())
	w := e.do("POST", authPath+authQuery(nil).Encode(), assertionForm(pg, "login", a, pkOrigin))
	if isCode(w) {
		t.Fatal("a valid passkey still worked after the per-IP limit was exceeded")
	}
}

func TestPasskeyFeatureOffWithoutStoreSupport(t *testing.T) {
	e := newPKEnv(t, nil, func(s core.Store) core.Store { return struct{ core.Store }{s} }, nil)
	w := e.loginPage()
	if w.Code != 200 || strings.Contains(w.Body.String(), "passkey") || strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src") {
		t.Fatalf("passkey UI shown without store support: %s", w.Body)
	}
	if w := e.do("GET", e.accountPath(), nil); w.Code != http.StatusNotFound {
		t.Errorf("account page: %d", w.Code)
	}
	w = e.loginPage()
	c := csrfRe.FindStringSubmatch(w.Body.String())[1]
	w = e.do("POST", authPath+authQuery(nil).Encode(), url.Values{"csrf": {c}, "pk_mode": {"login"}})
	if w.Code != http.StatusNotFound {
		t.Errorf("passkey post with the feature off: %d", w.Code)
	}
	// Password login still works and no step is injected.
	if w := e.passwordLogin(pkPW); !isCode(w) {
		t.Errorf("password login broken: %d", w.Code)
	}
}

func TestPasskeyAccountPage(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	// No session: refused.
	if w := e.do("GET", e.accountPath(), nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", w.Code)
	}
	a := e.register(-7)
	w := e.do("GET", e.accountPath(), nil)
	body := w.Body.String()
	for _, want := range []string{"My laptop", "Added 2026-01-01", "last used never", "Remove", "Rename", "Add a passkey"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'nonce-") {
		t.Errorf("headers: %v", w.Header())
	}
	pg := parsePKPage(t, w)
	ex := pg.opts["excludeCredentials"].([]any)
	if len(ex) != 1 || ex[0].(map[string]any)["id"] != bu(a.CredID) {
		t.Errorf("registered credential not excluded: %v", ex)
	}
	sel := pg.opts["authenticatorSelection"].(map[string]any)
	if sel["residentKey"] != "preferred" || sel["userVerification"] != "required" {
		t.Errorf("selection: %v", sel)
	}

	post := func(f url.Values) *httptest.ResponseRecorder { return e.do("POST", e.accountPath(), f) }
	// CSRF missing / wrong.
	if w := post(url.Values{"pk_action": {"delete"}, "cred": {bu(a.CredID)}}); w.Code != http.StatusForbidden {
		t.Errorf("delete without csrf: %d", w.Code)
	}
	if w := post(url.Values{"csrf": {pg.csrf}, "pk_action": {"delete"}, "cred": {bu(a.CredID)}}); w.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if e.events("PASSKEY_REMOVED") != 1 {
		t.Error("no PASSKEY_REMOVED event")
	}
	if l, _ := e.st.ListPasskeys(context.Background(), "r", "u1"); len(l) != 0 {
		t.Fatal("not deleted")
	}
}

func TestPasskeyRenameAndOwnership(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	pg := parsePKPage(t, e.do("GET", e.accountPath(), nil))
	w := e.do("POST", e.accountPath(), url.Values{"csrf": {pg.csrf}, "pk_action": {"rename"}, "cred": {bu(a.CredID)}, "name": {"  Phone\x00<b>x</b>  "}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("rename: %d", w.Code)
	}
	got, _ := e.st.GetPasskey(context.Background(), "r", bu(a.CredID))
	if got.Name != "Phone<b>x</b>" {
		t.Errorf("name %q", got.Name)
	}
	// Rendered escaped.
	if body := e.do("GET", e.accountPath(), nil).Body.String(); strings.Contains(body, "<b>x</b>") {
		t.Error("credential name not escaped")
	}
	// Another user's credential cannot be touched through this session.
	must(t, e.st.CreateUser(context.Background(), core.User{ID: "u2", Realm: "r", Username: "bob", Enabled: true}))
	must(t, e.st.AddPasskey(context.Background(), core.Passkey{Realm: "r", UserID: "u2", CredentialID: "bobs-cred", PublicKey: []byte{1}, Name: "Bob"}))
	pg = parsePKPage(t, e.do("GET", e.accountPath(), nil))
	for _, act := range []string{"rename", "delete"} {
		w := e.do("POST", e.accountPath(), url.Values{"csrf": {pg.csrf}, "pk_action": {act}, "cred": {"bobs-cred"}, "name": {"hax"}})
		if w.Code != http.StatusNotFound {
			t.Errorf("%s of another user's credential: %d", act, w.Code)
		}
		pg.csrf = csrfRe.FindStringSubmatch(w.Body.String())[1] // every page render rotates the token
	}
	if c, _ := e.st.GetPasskey(context.Background(), "r", "bobs-cred"); c.Name != "Bob" {
		t.Error("another user's credential modified")
	}
}

func TestPasskeyRecentAuthRequired(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	e.now = e.now.Add(11 * time.Minute) // session is still alive (idle 30m) but the login is stale
	w := e.do("GET", e.accountPath(), nil)
	// The page offers only re-authentication: no registration form or options.
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Confirm your password") || strings.Contains(w.Body.String(), `data-pk="create"`) ||
		strings.Contains(w.Body.String(), `name="pk_action" value="add"`) {
		t.Fatalf("stale session must be asked to reauthenticate and get no registration options: %d", w.Code)
	}
	pg := pkPage{csrf: csrfRe.FindStringSubmatch(w.Body.String())[1]}
	del := url.Values{"csrf": {pg.csrf}, "pk_action": {"delete"}, "cred": {bu(a.CredID)}}
	w = e.do("POST", e.accountPath(), del)
	if w.Code != http.StatusForbidden {
		t.Fatalf("delete with a stale login: %d", w.Code)
	}
	if l, _ := e.st.ListPasskeys(context.Background(), "r", "u1"); len(l) != 1 {
		t.Fatal("deleted with a stale login")
	}
	// Wrong password does not unlock it.
	del.Set("csrf", csrfRe.FindStringSubmatch(w.Body.String())[1])
	w = e.do("POST", e.accountPath(), url.Values{"csrf": {del.Get("csrf")}, "pk_action": {"reauth"}, "password": {"nope"}})
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad reauth: %d", w.Code)
	}
	del.Set("csrf", csrfRe.FindStringSubmatch(w.Body.String())[1])
	w = e.do("POST", e.accountPath(), del)
	if w.Code != http.StatusForbidden {
		t.Fatal("bad password unlocked the page")
	}
	pg.csrf = csrfRe.FindStringSubmatch(w.Body.String())[1]
	// Right password does, for this session only.
	if w := e.do("POST", e.accountPath(), url.Values{"csrf": {pg.csrf}, "pk_action": {"reauth"}, "password": {pkPW}}); w.Code != http.StatusSeeOther {
		t.Fatalf("reauth: %d", w.Code)
	}
	del.Set("csrf", pg.csrf)
	if w := e.do("POST", e.accountPath(), del); w.Code != http.StatusSeeOther {
		t.Fatalf("delete after reauth: %d", w.Code)
	}
	// The confirmation lapses after 10 minutes.
	a2 := e.addPasskey(-7)
	_ = a2
	e.now = e.now.Add(11 * time.Minute)
	pg.csrf = csrfRe.FindStringSubmatch(e.do("GET", e.accountPath(), nil).Body.String())[1]
	if w := e.do("POST", e.accountPath(), url.Values{"csrf": {pg.csrf}, "pk_action": {"delete"}, "cred": {bu(a2.CredID)}}); w.Code != http.StatusForbidden {
		t.Fatalf("expired confirmation honoured: %d", w.Code)
	}
}

func TestPasskeyRegistrationRejections(t *testing.T) {
	cases := map[string]func(a *webauthntest.Authenticator, pg pkPage) (origin string, challenge []byte){
		"wrong origin": func(a *webauthntest.Authenticator, pg pkPage) (string, []byte) {
			return "https://evil.example", pg.challenge
		},
		"wrong challenge": func(a *webauthntest.Authenticator, pg pkPage) (string, []byte) {
			return pkOrigin, []byte("another challenge 0123456789abcdef")
		},
		"wrong rp id": func(a *webauthntest.Authenticator, pg pkPage) (string, []byte) {
			a.RPID = "evil.example"
			return pkOrigin, pg.challenge
		},
		"no user verification": func(a *webauthntest.Authenticator, pg pkPage) (string, []byte) {
			a.UV = false
			return pkOrigin, pg.challenge
		},
		"unsupported attestation format": func(a *webauthntest.Authenticator, pg pkPage) (string, []byte) {
			a.Fmt = "tpm"
			return pkOrigin, pg.challenge
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPKEnv(t, nil, nil, nil)
			if w := e.passwordLogin(pkPW); !isCode(w) {
				t.Fatal("login")
			}
			pg := parsePKPage(t, e.do("GET", e.accountPath(), nil))
			a := webauthntest.New(-7, pkRPID)
			origin, chal := mutate(a, pg)
			cd, obj := a.Create(chal, origin)
			w := e.do("POST", e.accountPath(), url.Values{"csrf": {pg.csrf}, "pk_action": {"add"}, "pk_token": {pg.token}, "pk_cd": {bu(cd)}, "pk_att": {bu(obj)}})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("accepted: %d", w.Code)
			}
			if l, _ := e.st.ListPasskeys(context.Background(), "r", "u1"); len(l) != 0 {
				t.Fatal("credential stored")
			}
		})
	}

	t.Run("registration replay and duplicate credential", func(t *testing.T) {
		e := newPKEnv(t, nil, nil, nil)
		a := e.register(-7)
		pg := parsePKPage(t, e.do("GET", e.accountPath(), nil))
		cd, obj := a.Create(pg.challenge, pkOrigin) // same credential id again
		f := url.Values{"csrf": {pg.csrf}, "pk_action": {"add"}, "pk_token": {pg.token}, "pk_cd": {bu(cd)}, "pk_att": {bu(obj)}}
		w := e.do("POST", e.accountPath(), f)
		if w.Code != http.StatusConflict {
			t.Fatalf("duplicate credential id: %d", w.Code)
		}
		// Same token again (challenge already consumed).
		f.Set("csrf", csrfRe.FindStringSubmatch(w.Body.String())[1])
		if w := e.do("POST", e.accountPath(), f); w.Code != http.StatusBadRequest {
			t.Fatalf("replayed registration: %d", w.Code)
		}
		// A registration challenge token cannot be used as a login challenge.
		e.forget()
		lp := parsePKPage(t, e.loginPage())
		f2 := assertionForm(lp, "login", a, pkOrigin)
		f2.Set("pk_token", pg.token)
		if isCode(e.do("POST", authPath+authQuery(nil).Encode(), f2)) {
			t.Fatal("registration token accepted for login")
		}
	})
}

func TestPasskeyRequiredPolicyKeepsLastCredential(t *testing.T) {
	e := newPKEnv(t, nil, nil, nil)
	a := e.register(-7)
	must(t, e.st.SetRealmRequiresPasskeys(context.Background(), "r", true))
	pg := parsePKPage(t, e.do("GET", e.accountPath(), nil))
	del := func(id []byte) *httptest.ResponseRecorder {
		return e.do("POST", e.accountPath(), url.Values{"csrf": {pg.csrf}, "pk_action": {"delete"}, "cred": {bu(id)}})
	}
	if w := del(a.CredID); w.Code != http.StatusConflict {
		t.Fatalf("last credential removed under a passkey-required realm: %d", w.Code)
	}
	a2 := e.addPasskey(-8)
	pg = parsePKPage(t, e.do("GET", e.accountPath(), nil))
	if w := del(a.CredID); w.Code != http.StatusSeeOther {
		t.Fatalf("not the last: %d", w.Code)
	}
	pg = parsePKPage(t, e.do("GET", e.accountPath(), nil))
	if w := del(a2.CredID); w.Code != http.StatusConflict {
		t.Fatalf("now the last: %d", w.Code)
	}
}

func TestPasskeyRPResolution(t *testing.T) {
	for _, tc := range []struct {
		base string
		cfg  WebAuthnConfig
		id   string
		orig []string
		ok   bool
	}{
		{"https://idp.example.com", WebAuthnConfig{}, "idp.example.com", []string{"https://idp.example.com"}, true},
		{"https://idp.example.com:8443", WebAuthnConfig{}, "idp.example.com", []string{"https://idp.example.com:8443"}, true},
		{"http://127.0.0.1:25000", WebAuthnConfig{}, "localhost", []string{"http://127.0.0.1:25000", "http://localhost:25000"}, true},
		{"https://192.0.2.9", WebAuthnConfig{}, "", nil, false},
		{"https://login.example.com", WebAuthnConfig{RPID: "Example.com", Origins: []string{"https://login.example.com/", "https://app.example.com"}}, "example.com", []string{"https://login.example.com", "https://app.example.com"}, true},
		{"https://login.example.com", WebAuthnConfig{Origins: []string{"javascript:alert(1)"}}, "", nil, false},
		{"https://login.example.com", WebAuthnConfig{Origins: []string{"https://x.example.com/path"}}, "", nil, false},
	} {
		p := &Provider{base: tc.base, cfg: Config{WebAuthn: tc.cfg}}
		rp, ok := p.webauthnRP()
		if ok != tc.ok || rp.ID != tc.id || strings.Join(rp.Origins, ",") != strings.Join(tc.orig, ",") {
			t.Errorf("%s %+v: got %+v ok=%v", tc.base, tc.cfg, rp, ok)
		}
	}
}
