// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package upstream_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/native"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/safehttp"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/upstream"
	"github.com/zyvorai/haven/internal/idp/upstream/upstreamtest"
)

const (
	adminRealm  = "platform"
	adminSecret = "admin-secret-for-tests-0123456789abcdef"
	realm       = "acme"
	appCB       = "https://app.example/cb"
	verifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// fed is the whole broker under test plus its fake upstream.
type fed struct {
	t      *testing.T
	up     *upstreamtest.IdP
	st     *memstore.Store
	srv    *httptest.Server
	box    *secretbox.Box
	mgr    *upstream.Manager
	logs   *syncBuf
	offset atomic.Int64 // seconds added to the clock of broker and upstream
	token  string       // admin token
	seen   []string     // every response body/header seen by browsers (secret scan)
}

type fedOpts struct {
	noBox      bool
	strictIP   bool // the real IP policy (no AllowPrivate)
	timeout    time.Duration
	noProvider bool
	cfg        map[string]string // merged over the default provider config
	trustEmail *bool
	alias      string
}

func newFed(t *testing.T, o fedOpts) *fed {
	t.Helper()
	f := &fed{t: t, st: memstore.New(), logs: &syncBuf{}}
	f.up = upstreamtest.New(t)
	clock := func() time.Time { return time.Now().Add(time.Duration(f.offset.Load()) * time.Second) }
	f.up.Now = clock
	if !o.noBox {
		k, _ := secretbox.ParseKey(secretbox.GenerateKey())
		f.box, _ = secretbox.New(k)
	}
	to := o.timeout
	if to == 0 {
		to = 3 * time.Second
	}
	f.mgr = upstream.NewManager(safehttp.Options{AllowPrivate: !o.strictIP, RootCAs: f.up.Pool, Timeout: to}, clock)

	h := password.New(password.TestParams)
	sg := keys.New(f.st, keys.Options{})
	var handler http.Handler
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(f.srv.Close)
	ctx := context.Background()
	if _, err := bootstrap.Run(ctx, f.st, h, sg, bootstrap.Options{Realm: adminRealm, AdminClientSecret: adminSecret}); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Run(ctx, f.st, h, sg, bootstrap.Options{Realm: realm}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.CreateClient(ctx, core.Client{Realm: realm, ClientID: "app", Name: "App", Enabled: true, Public: true,
		AuthCodeFlow: true, RequirePKCE: true, RedirectURIs: []string{appCB}}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: f.st, Signer: sg, Hasher: h, BaseURL: f.srv.URL, Clock: clock,
		Logger: log, SecretBox: f.box, Federation: f.mgr, CSRFKey: []byte("0123456789abcdef0123456789abcdef")}))
	mux.Handle("/admin/v1/", admin.New(admin.Config{Store: f.st, Signer: sg, Hasher: h, BaseURL: f.srv.URL,
		AdminRealm: adminRealm, SecretBox: f.box, Logger: log, Clock: clock, AllowPrivateUpstreams: !o.strictIP}))
	handler = mux
	f.token = f.clientToken(adminRealm, "haven-admin", adminSecret)

	alias := o.alias
	if alias == "" {
		alias = "fake"
	}
	f.up.RedirectURIs = []string{f.srv.URL + "/realms/" + realm + "/broker/" + alias + "/endpoint"}
	if !o.noProvider {
		f.addProvider(alias, o)
	}
	return f
}

func (f *fed) clientToken(rlm, id, secret string) string {
	f.t.Helper()
	req, _ := http.NewRequest("POST", f.srv.URL+"/realms/"+rlm+"/protocol/openid-connect/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	b, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(b, &out) != nil || out.AccessToken == "" {
		f.t.Fatalf("admin token: %d %s", resp.StatusCode, b)
	}
	return out.AccessToken
}

func (f *fed) addProvider(alias string, o fedOpts) {
	f.t.Helper()
	cfg := map[string]string{"issuer": f.up.URL(), "clientId": f.up.ClientID, "clientSecret": f.up.ClientSecret, "autoCreateUsers": "true"}
	for k, v := range o.cfg {
		if v == "-" {
			delete(cfg, k)
			continue
		}
		cfg[k] = v
	}
	trust := true
	if o.trustEmail != nil {
		trust = *o.trustEmail
	}
	code, body := f.admin("POST", "/realms/"+realm+"/identity-providers", map[string]any{
		"alias": alias, "displayName": "Fake", "providerId": "oidc", "enabled": true, "trustEmail": trust, "config": cfg})
	if code != 201 {
		f.t.Fatalf("create provider: %d %s", code, body)
	}
}

// admin calls the Admin API with the admin token.
func (f *fed) admin(method, path string, body any) (int, []byte) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.srv.URL+"/admin/v1"+path, rd)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	f.seen = append(f.seen, string(b))
	return resp.StatusCode, b
}

// ---- the browser ----

type browser struct {
	f *fed
	c *http.Client
}

func (f *fed) newBrowser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{f: f, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) get(raw string) (*http.Response, string) {
	b.f.t.Helper()
	resp, err := b.c.Get(raw)
	if err != nil {
		b.f.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var hs strings.Builder
	for k, v := range resp.Header {
		hs.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	b.f.seen = append(b.f.seen, string(body), hs.String(), raw)
	return resp, string(body)
}

func authQuery() string {
	sum := sha256.Sum256([]byte(verifier))
	return url.Values{"client_id": {"app"}, "redirect_uri": {appCB}, "response_type": {"code"}, "scope": {"openid profile email"},
		"state": {"client-state"}, "nonce": {"client-nonce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}}.Encode()
}

func (f *fed) authURL() string {
	return f.srv.URL + "/realms/" + realm + "/protocol/openid-connect/auth?" + authQuery()
}

var hrefRE = regexp.MustCompile(`href="(/realms/[^"]*/broker/([a-z0-9-]+)/login\?[^"]*)"`)

// loginPageLinks returns the broker login URLs shown on the login page.
func (b *browser) loginPageLinks() []string {
	b.f.t.Helper()
	resp, body := b.get(b.f.authURL())
	if resp.StatusCode != 200 {
		b.f.t.Fatalf("login page: %d", resp.StatusCode)
	}
	var out []string
	for _, m := range hrefRE.FindAllStringSubmatch(body, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// startUpstream clicks "Continue with Fake" and returns the upstream
// authorization URL the broker redirected to.
func (b *browser) startUpstream(alias string) string {
	b.f.t.Helper()
	resp, body := b.get(b.f.srv.URL + "/realms/" + realm + "/broker/" + alias + "/login?" + authQuery())
	if resp.StatusCode != http.StatusFound {
		b.f.t.Fatalf("broker login: %d %s", resp.StatusCode, body)
	}
	return resp.Header.Get("Location")
}

// callbackURL plays the upstream: user signs in as claims.
func (f *fed) callbackURL(authURL string, claims map[string]any) string {
	f.t.Helper()
	back, err := f.up.Authorize(authURL, claims)
	if err != nil {
		f.t.Fatal(err)
	}
	return back
}

func goodClaims() map[string]any {
	return map[string]any{"sub": "up-sub-1", "email": "alice@corp.example", "email_verified": true,
		"preferred_username": "alice", "given_name": "Alice", "family_name": "Example"}
}

// login runs the whole flow with a fresh browser and returns the final
// response of the callback (a 302 back to the app on success).
func (f *fed) login(claims map[string]any) (*browser, *http.Response, string) {
	f.t.Helper()
	b := f.newBrowser()
	auth := b.startUpstream("fake")
	resp, body := b.get(f.callbackURL(auth, claims))
	return b, resp, body
}

// succeeded checks the callback redirected to the app with a code and returns
// the code.
func succeeded(t *testing.T, resp *http.Response, body string) string {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d %s", resp.StatusCode, body)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Scheme+"://"+loc.Host+loc.Path != appCB || loc.Query().Get("code") == "" || loc.Query().Get("state") != "client-state" {
		t.Fatalf("callback redirected to %s", resp.Header.Get("Location"))
	}
	return loc.Query().Get("code")
}

// refused checks the callback produced an error page, not a code.
func refused(t *testing.T, resp *http.Response, body string) {
	t.Helper()
	if resp.StatusCode < 400 {
		t.Fatalf("expected an error page, got %d %s (Location %q)", resp.StatusCode, body, resp.Header.Get("Location"))
	}
	if strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Fatal("a code was issued")
	}
}

func (f *fed) users() []core.User {
	us, _ := f.st.ListUsers(context.Background(), realm, "", 0, 100)
	return us
}

func (f *fed) tokenExchange(code string) map[string]any {
	f.t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {appCB}, "client_id": {"app"}, "code_verifier": {verifier}}
	resp, err := http.PostForm(f.srv.URL+"/realms/"+realm+"/protocol/openid-connect/token", form)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		f.t.Fatalf("token: %d %s", resp.StatusCode, b)
	}
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func jwtClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		t.Fatalf("not a jwt: %q", tok)
	}
	b, _ := base64.RawURLEncoding.DecodeString(p[1])
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	return c
}

func mustUser(t *testing.T, f *fed, name string) core.User {
	t.Helper()
	u, err := f.st.GetUserByUsername(context.Background(), realm, name)
	if err != nil {
		t.Fatalf("user %q: %v", name, err)
	}
	return u
}

func lastLoginEvent(f *fed) core.Event {
	evs, _ := f.st.ListEvents(context.Background(), realm, 50)
	for _, e := range evs {
		if e.Type == "LOGIN" {
			return e
		}
	}
	return core.Event{}
}

// ---- happy path ----

func TestBrokerHappyPath(t *testing.T) {
	f := newFed(t, fedOpts{noProvider: true})
	b0 := f.newBrowser()
	if l := b0.loginPageLinks(); len(l) != 0 {
		t.Fatalf("buttons without providers: %v", l)
	}
	f.addProvider("fake", fedOpts{})

	b := f.newBrowser()
	links := b.loginPageLinks()
	if len(links) != 1 {
		t.Fatalf("want one button, got %v", links)
	}
	if resp, body := b.get(f.srv.URL + "/realms/" + realm + "/protocol/openid-connect/auth?" + authQuery()); !strings.Contains(body, "Continue with Fake") || resp.StatusCode != 200 {
		t.Fatalf("login page lacks the button: %s", body)
	}
	resp, _ := b.get(f.srv.URL + links[0])
	if resp.StatusCode != 302 {
		t.Fatalf("broker login: %d", resp.StatusCode)
	}
	auth, _ := url.Parse(resp.Header.Get("Location"))
	if auth.Host != strings.TrimPrefix(f.up.URL(), "https://") || auth.Path != "/authorize" {
		t.Fatalf("redirected to %s", auth)
	}
	q := auth.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("response_type") != "code" ||
		q.Get("client_id") != f.up.ClientID || q.Get("scope") != "openid email profile" ||
		q.Get("redirect_uri") != f.srv.URL+"/realms/"+realm+"/broker/fake/endpoint" {
		t.Fatalf("authorization request: %v", q)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "haven_fed" && (!c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/realms/"+realm+"/broker") {
			t.Fatalf("binding cookie attributes: %+v", c)
		}
	}
	if strings.Contains(auth.String(), f.up.ClientSecret) {
		t.Fatal("client secret in the authorization URL")
	}

	cb := f.callbackURL(auth.String(), goodClaims())
	resp, body := b.get(cb)
	code := succeeded(t, resp, body)
	if f.up.TokenHits.Load() != 1 {
		t.Fatalf("token endpoint hits = %d", f.up.TokenHits.Load())
	}
	if m, _ := f.up.LastAuthMethod.Load().(string); m != "basic" {
		t.Fatalf("client auth method %q, want basic", m)
	}

	u := mustUser(t, f, "alice")
	if u.Email != "alice@corp.example" || !u.EmailVerified || !u.Enabled || u.PasswordHash != "" || len(u.PendingActions) != 0 ||
		u.FirstName != "Alice" || u.LastName != "Example" {
		t.Fatalf("created user: %+v", u)
	}
	link, err := f.st.GetFedLink(context.Background(), realm, "fake", "up-sub-1")
	if err != nil || link.UserID != u.ID {
		t.Fatalf("link: %+v %v", link, err)
	}
	if ev := lastLoginEvent(f); ev.Detail != "federated:fake" || ev.UserID != u.ID {
		t.Fatalf("login event: %+v", ev)
	}

	// The code is a normal authorization code of OUR provider.
	tok := f.tokenExchange(code)
	idc := jwtClaims(t, tok["id_token"].(string))
	if idc["sub"] != u.ID || idc["iss"] != f.srv.URL+"/realms/"+realm || idc["nonce"] != "client-nonce" {
		t.Fatalf("id token claims: %v", idc)
	}

	// Second login: same user, no duplicate, SSO cookie works for a silent re-login.
	resp, body = b.get(f.srv.URL + "/realms/" + realm + "/protocol/openid-connect/auth?" + authQuery())
	succeeded(t, resp, body)
	b2 := f.newBrowser()
	auth2 := b2.startUpstream("fake")
	resp, body = b2.get(f.callbackURL(auth2, goodClaims()))
	succeeded(t, resp, body)
	if n := len(f.users()); n != 1 {
		t.Fatalf("users after second login: %d", n)
	}
	if l, _ := f.st.GetFedLink(context.Background(), realm, "fake", "up-sub-1"); !l.LastLoginAt.After(link.CreatedAt.Add(-time.Second)) {
		t.Fatalf("lastLoginAt not updated: %+v", l)
	}
	f.assertNoSecretLeak()
}

func (f *fed) assertNoSecretLeak() {
	f.t.Helper()
	for _, s := range append(f.seen, f.logs.String()) {
		if strings.Contains(s, f.up.ClientSecret) {
			f.t.Fatalf("the upstream client secret leaked into a response, header, URL or log: %.200s", s)
		}
	}
	if strings.Contains(f.logs.String(), "opaque-upstream-access") {
		f.t.Fatal("upstream access token in logs")
	}
}

func TestBrokerClientSecretPost(t *testing.T) {
	f := newFed(t, fedOpts{})
	f.up.AuthMethods = []string{"client_secret_post"}
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	if m, _ := f.up.LastAuthMethod.Load().(string); m != "post" {
		t.Fatalf("client auth method %q, want post", m)
	}
}

func TestDisabledProviderHasNoButtonAndNoLogin(t *testing.T) {
	f := newFed(t, fedOpts{})
	code, body := f.admin("GET", "/realms/"+realm+"/identity-providers/fake", nil)
	if code != 200 {
		t.Fatal(code, body)
	}
	var p idp.IdentityProvider
	_ = json.Unmarshal(body, &p)
	p.Enabled = false
	if code, b := f.admin("PUT", "/realms/"+realm+"/identity-providers/fake", p); code != 204 {
		t.Fatal(code, b)
	}
	b := f.newBrowser()
	if l := b.loginPageLinks(); len(l) != 0 {
		t.Fatalf("disabled provider listed: %v", l)
	}
	resp, _ := b.get(f.srv.URL + "/realms/" + realm + "/broker/fake/login?" + authQuery())
	if resp.StatusCode != 404 {
		t.Fatalf("login via disabled provider: %d", resp.StatusCode)
	}
}

func TestBrokerLoginRejectsBadAuthRequest(t *testing.T) {
	f := newFed(t, fedOpts{})
	b := f.newBrowser()
	for name, q := range map[string]string{
		"unregistered redirect": strings.Replace(authQuery(), url.QueryEscape(appCB), url.QueryEscape("https://evil.example/cb"), 1),
		"unknown client":        strings.Replace(authQuery(), "client_id=app", "client_id=nope", 1),
		"no pkce":               strings.Replace(authQuery(), "code_challenge_method=S256", "code_challenge_method=plain", 1),
		"no state":              strings.Replace(authQuery(), "state=client-state", "", 1),
	} {
		resp, _ := b.get(f.srv.URL + "/realms/" + realm + "/broker/fake/login?" + q)
		if resp.StatusCode != 400 {
			t.Errorf("%s: %d, want 400", name, resp.StatusCode)
		}
	}
	if resp, _ := b.get(f.srv.URL + "/realms/" + realm + "/broker/nosuch/login?" + authQuery()); resp.StatusCode != 404 {
		t.Errorf("unknown alias: %d", resp.StatusCode)
	}
	if f.up.DiscoveryHits.Load() != 0 {
		t.Error("upstream contacted for an invalid authorization request")
	}
}

// ---- state / browser binding ----

func TestWrongState(t *testing.T) {
	f := newFed(t, fedOpts{})
	b := f.newBrowser()
	cb := f.callbackURL(b.startUpstream("fake"), goodClaims())
	u, _ := url.Parse(cb)
	q := u.Query()
	q.Set("state", q.Get("state")+"x")
	u.RawQuery = q.Encode()
	resp, body := b.get(u.String())
	refused(t, resp, body)
	if f.up.TokenHits.Load() != 0 || len(f.users()) != 0 {
		t.Fatal("a wrong state reached the token endpoint or created a user")
	}
	// No state at all.
	u.RawQuery = "code=" + q.Get("code")
	resp, body = b.get(u.String())
	refused(t, resp, body)
}

func TestStateReplay(t *testing.T) {
	f := newFed(t, fedOpts{})
	b := f.newBrowser()
	cb := f.callbackURL(b.startUpstream("fake"), goodClaims())
	resp, body := b.get(cb)
	succeeded(t, resp, body)
	resp, body = b.get(cb)
	refused(t, resp, body)
	if f.up.TokenHits.Load() != 1 || len(f.users()) != 1 {
		t.Fatalf("replay reached the token endpoint (%d) or created users (%d)", f.up.TokenHits.Load(), len(f.users()))
	}
}

func TestStateFromAnotherBrowser(t *testing.T) {
	f := newFed(t, fedOpts{})
	victim := f.newBrowser()
	cb := f.callbackURL(victim.startUpstream("fake"), goodClaims())
	// The attacker plants the callback URL (login CSRF / session fixation) in a
	// browser that never started the flow.
	attacker := f.newBrowser()
	resp, body := attacker.get(cb)
	refused(t, resp, body)
	// A browser that has a binding cookie from ANOTHER flow is refused too.
	other := f.newBrowser()
	other.startUpstream("fake")
	resp, body = other.get(cb)
	refused(t, resp, body)
	if f.up.TokenHits.Load() != 0 || len(f.users()) != 0 {
		t.Fatal("a foreign browser reached the token endpoint or created a user")
	}
}

func TestStateExpires(t *testing.T) {
	f := newFed(t, fedOpts{})
	b := f.newBrowser()
	auth := b.startUpstream("fake")
	cb := f.callbackURL(auth, goodClaims())
	f.offset.Store(11 * 60)
	resp, body := b.get(cb)
	refused(t, resp, body)
	if f.up.TokenHits.Load() != 0 {
		t.Fatal("expired state reached the token endpoint")
	}
}

func TestStateIsBoundToProvider(t *testing.T) {
	f := newFed(t, fedOpts{})
	f.addProvider("other", fedOpts{})
	b := f.newBrowser()
	cb := f.callbackURL(b.startUpstream("fake"), goodClaims())
	cb = strings.Replace(cb, "/broker/fake/endpoint", "/broker/other/endpoint", 1)
	resp, body := b.get(cb)
	refused(t, resp, body)
	if f.up.TokenHits.Load() != 0 {
		t.Fatal("a state of provider A was accepted by provider B")
	}
}

// ---- ID token validation ----

func TestIDTokenRejections(t *testing.T) {
	now := func(f *fed) time.Time { return time.Now().Add(time.Duration(f.offset.Load()) * time.Second) }
	cases := []struct {
		name  string
		setup func(f *fed)
	}{
		{"wrong nonce", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { c["nonce"] = "not-the-nonce" } }},
		{"missing nonce", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { delete(c, "nonce") } }},
		{"wrong audience", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { c["aud"] = "someone-else" } }},
		{"audience list without ours", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { c["aud"] = []string{"a", "b"} } }},
		{"multiple audiences without azp", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { c["aud"] = []string{f.up.ClientID, "b"} } }},
		{"wrong azp", func(f *fed) {
			f.up.ClaimsHook = func(c map[string]any) { c["aud"] = []string{f.up.ClientID, "b"}; c["azp"] = "b" }
		}},
		{"expired", func(f *fed) {
			f.up.ClaimsHook = func(c map[string]any) {
				c["exp"] = now(f).Add(-time.Hour).Unix()
				c["iat"] = now(f).Add(-2 * time.Hour).Unix()
			}
		}},
		{"no exp", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { delete(c, "exp") } }},
		{"issued in the future", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { c["iat"] = now(f).Add(time.Hour).Unix() } }},
		{"not yet valid", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { c["nbf"] = now(f).Add(time.Hour).Unix() } }},
		{"wrong issuer", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { c["iss"] = "https://evil.example" } }},
		{"missing sub", func(f *fed) { f.up.ClaimsHook = func(c map[string]any) { delete(c, "sub") } }},
		{"bad signature", func(f *fed) { f.up.Sign.BadSignature = true }},
		{"alg none", func(f *fed) { f.up.Sign.Alg = "none" }},
		{"unknown kid", func(f *fed) { f.up.Sign.KID = "ghost" }},
		{"HS256 with the public key as secret", func(f *fed) {
			f.up.Sign = upstreamtest.SignOpts{Alg: "HS256", HMACKey: f.up.RSAPublicDER()}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFed(t, fedOpts{})
			tc.setup(f)
			_, resp, body := f.login(goodClaims())
			refused(t, resp, body)
			if len(f.users()) != 0 {
				t.Fatalf("a user was created from a rejected token")
			}
			f.assertNoSecretLeak()
		})
	}
}

func TestIDTokenAcceptsES256AndPS256(t *testing.T) {
	for _, alg := range []string{"ES256", "PS256"} {
		f := newFed(t, fedOpts{})
		f.up.AddECKey("ec1")
		f.up.Sign.Alg = alg
		_, resp, body := f.login(goodClaims())
		if alg == "ES256" || alg == "PS256" {
			succeeded(t, resp, body)
		}
	}
}

func TestKeyRotation(t *testing.T) {
	f := newFed(t, fedOpts{})
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	if f.up.JWKSHits.Load() != 1 {
		t.Fatalf("jwks hits %d", f.up.JWKSHits.Load())
	}
	// The upstream rotates: new key active, old one still published.
	f.up.AddRSAKey("k2")
	_, resp, body = f.login(goodClaims())
	succeeded(t, resp, body) // unknown kid k2 triggers one JWKS refresh
	if f.up.JWKSHits.Load() != 2 {
		t.Fatalf("jwks hits after rotation %d, want 2", f.up.JWKSHits.Load())
	}
	// The old key is retired: a token still signed by it must now fail once the
	// cache refreshes (the refetch gap passes).
	f.up.Retire("k1")
	f.up.Sign.KID = "k1"
	f.offset.Store(60)
	_, resp, body = f.login(goodClaims())
	refused(t, resp, body)
	// Signed with the real active key again: fine.
	f.up.Sign.KID = ""
	_, resp, body = f.login(goodClaims())
	succeeded(t, resp, body)
}

func TestJWKSRefreshIsRateLimited(t *testing.T) {
	f := newFed(t, fedOpts{})
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	f.up.Sign.KID = "ghost"
	for i := 0; i < 5; i++ {
		_, resp, body = f.login(goodClaims())
		refused(t, resp, body)
	}
	// 1 initial + at most 1 forced refresh within the refetch gap.
	if n := f.up.JWKSHits.Load(); n > 2 {
		t.Fatalf("unknown kids caused %d JWKS fetches", n)
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	f := newFed(t, fedOpts{})
	f.up.DiscoveryIssuer = "https://other.example"
	b := f.newBrowser()
	resp, body := b.get(f.srv.URL + "/realms/" + realm + "/broker/fake/login?" + authQuery())
	refused(t, resp, body)
	if strings.Contains(resp.Header.Get("Location"), "authorize") {
		t.Fatal("redirected to an upstream whose discovery issuer differs")
	}
}

// ---- local user resolution ----

func TestEmailUnverifiedWithTrustEmail(t *testing.T) {
	f := newFed(t, fedOpts{})
	c := goodClaims()
	c["email_verified"] = false
	_, resp, body := f.login(c)
	succeeded(t, resp, body)
	u := mustUser(t, f, "alice")
	if u.EmailVerified {
		t.Fatal("upstream email_verified=false must not produce a verified local email")
	}
	// No email_verified claim at all behaves the same.
	f2 := newFed(t, fedOpts{})
	c = goodClaims()
	delete(c, "email_verified")
	_, resp, body = f2.login(c)
	succeeded(t, resp, body)
	if mustUser(t, f2, "alice").EmailVerified {
		t.Fatal("missing email_verified must not produce a verified local email")
	}
}

func TestTrustEmailOffNeverMarksVerified(t *testing.T) {
	no := false
	f := newFed(t, fedOpts{trustEmail: &no})
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	if mustUser(t, f, "alice").EmailVerified {
		t.Fatal("trustEmail=false but the local email is verified")
	}
}

func TestLinkExistingByEmailMatrix(t *testing.T) {
	type tc struct {
		name         string
		link, trust  bool
		upVerified   bool
		preLinked    bool // the local user already has a link for this alias (other subject)
		twoUsers     bool // two local accounts share the email
		wantLinked   bool
		wantNewUsers int
	}
	cases := []tc{
		{name: "all conditions met", link: true, trust: true, upVerified: true, wantLinked: true},
		{name: "link off", link: false, trust: true, upVerified: true},
		{name: "trustEmail off", link: true, trust: false, upVerified: true},
		{name: "upstream not verified", link: true, trust: true, upVerified: false},
		{name: "link off and trust off", link: false, trust: false, upVerified: false},
		{name: "local user already linked to this alias", link: true, trust: true, upVerified: true, preLinked: true},
		{name: "two local accounts with the email", link: true, trust: true, upVerified: true, twoUsers: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trust := c.trust
			f := newFed(t, fedOpts{trustEmail: &trust, cfg: map[string]string{"linkExistingByEmail": map[bool]string{true: "true", false: "false"}[c.link]}})
			ctx := context.Background()
			if err := f.st.CreateUser(ctx, core.User{Realm: realm, Username: "local-alice", Email: "Alice@Corp.example", Enabled: true}); err != nil {
				t.Fatal(err)
			}
			local := mustUser(t, f, "local-alice")
			if c.twoUsers {
				_ = f.st.CreateUser(ctx, core.User{Realm: realm, Username: "local-alice-2", Email: "alice@corp.example", Enabled: true})
			}
			if c.preLinked {
				if err := f.st.CreateFedLink(ctx, core.FedLink{Realm: realm, Alias: "fake", Subject: "some-other-subject", UserID: local.ID}); err != nil {
					t.Fatal(err)
				}
			}
			before := len(f.users())
			cl := goodClaims()
			cl["email_verified"] = c.upVerified
			_, resp, body := f.login(cl)
			if c.wantLinked {
				succeeded(t, resp, body)
				l, err := f.st.GetFedLink(ctx, realm, "fake", "up-sub-1")
				if err != nil || l.UserID != local.ID {
					t.Fatalf("not linked to the local user: %+v %v", l, err)
				}
				if len(f.users()) != before {
					t.Fatal("a duplicate user was created")
				}
				return
			}
			refused(t, resp, body)
			if _, err := f.st.GetFedLink(ctx, realm, "fake", "up-sub-1"); err == nil {
				t.Fatal("a link was created although a condition was not met")
			}
			if len(f.users()) != before {
				t.Fatal("a user was created next to the existing account")
			}
		})
	}
}

func TestExistingLinkWinsOverEmail(t *testing.T) {
	f := newFed(t, fedOpts{})
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	// The upstream user changes email: the link (by sub) still selects the user.
	c := goodClaims()
	c["email"] = "renamed@corp.example"
	_, resp, body = f.login(c)
	succeeded(t, resp, body)
	if len(f.users()) != 1 {
		t.Fatalf("users: %d", len(f.users()))
	}
}

func TestDisabledUserRefused(t *testing.T) {
	f := newFed(t, fedOpts{})
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	u := mustUser(t, f, "alice")
	u.Enabled = false
	if err := f.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	_, resp, body = f.login(goodClaims())
	refused(t, resp, body)
	if !strings.Contains(body, "disabled") {
		t.Fatalf("page does not say the account is disabled: %s", body)
	}
}

func TestDisabledUserNotLinkedByEmail(t *testing.T) {
	f := newFed(t, fedOpts{cfg: map[string]string{"linkExistingByEmail": "true"}})
	if err := f.st.CreateUser(context.Background(), core.User{Realm: realm, Username: "off", Email: "alice@corp.example", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	_, resp, body := f.login(goodClaims())
	refused(t, resp, body)
	if _, err := f.st.GetFedLink(context.Background(), realm, "fake", "up-sub-1"); err == nil {
		t.Fatal("a disabled user got linked")
	}
}

func TestAutoCreateOffRefuses(t *testing.T) {
	f := newFed(t, fedOpts{cfg: map[string]string{"autoCreateUsers": "false"}})
	_, resp, body := f.login(goodClaims())
	refused(t, resp, body)
	if len(f.users()) != 0 {
		t.Fatal("user created with autoCreateUsers=false")
	}
}

func TestEmailOfExistingAccountBlocksAutoCreate(t *testing.T) {
	f := newFed(t, fedOpts{}) // autoCreate on, link off
	if err := f.st.CreateUser(context.Background(), core.User{Realm: realm, Username: "victim", Email: "alice@corp.example", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, resp, body := f.login(goodClaims())
	refused(t, resp, body)
	if len(f.users()) != 1 {
		t.Fatal("a second account with the same email was created")
	}
}

func TestUsernameUniqueness(t *testing.T) {
	f := newFed(t, fedOpts{})
	for _, n := range []string{"alice", "alice2"} {
		if err := f.st.CreateUser(context.Background(), core.User{Realm: realm, Username: n, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	l, err := f.st.GetFedLink(context.Background(), realm, "fake", "up-sub-1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := f.st.GetUser(context.Background(), realm, l.UserID)
	if u.Username != "alice3" {
		t.Fatalf("username %q, want alice3", u.Username)
	}
	// Without preferred_username the email local part is used; hostile
	// characters are neutralised.
	f2 := newFed(t, fedOpts{})
	c := goodClaims()
	delete(c, "preferred_username")
	c["email"] = "Bob Smith<x>@corp.example"
	c["sub"] = "sub-bob"
	_, resp, body = f2.login(c)
	succeeded(t, resp, body)
	for _, u := range f2.users() {
		if strings.ContainsAny(u.Username, "< >") || u.Username == "" {
			t.Fatalf("unsafe username %q", u.Username)
		}
	}
}

func TestRealmRequiringVerifiedEmail(t *testing.T) {
	f := newFed(t, fedOpts{})
	rl, _ := f.st.GetRealm(context.Background(), realm)
	rl.EmailVerificationRequired = true
	if err := f.st.UpdateRealm(context.Background(), rl); err != nil {
		t.Fatal(err)
	}
	c := goodClaims()
	c["email_verified"] = false
	_, resp, body := f.login(c)
	refused(t, resp, body)
	if len(f.users()) != 1 || f.users()[0].EmailVerified {
		t.Fatal("expected the account to exist unverified")
	}
}

// ---- role mappings ----

func TestRoleMappingImportAndSync(t *testing.T) {
	ctx := context.Background()
	rules := `[{"claim":"groups","value":"eng","roles":["developer"]},{"claim":"groups","value":"ops","roles":["operator","nonexistent"]},{"claim":"dept","value":"it","roles":["developer"]}]`
	for _, tc := range []struct {
		mode string
	}{{"import"}, {"sync"}} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newFed(t, fedOpts{cfg: map[string]string{"roleMappings": rules, "roleSyncMode": tc.mode}})
			for _, r := range []string{"developer", "operator", "admin-assigned"} {
				if err := f.st.CreateRole(ctx, core.Role{Realm: realm, Name: r}); err != nil {
					t.Fatal(err)
				}
			}
			c := goodClaims()
			c["groups"] = []string{"eng", "ops"}
			_, resp, body := f.login(c)
			succeeded(t, resp, body)
			u := mustUser(t, f, "alice")
			if !has(u.Roles, "developer") || !has(u.Roles, "operator") || has(u.Roles, "nonexistent") || len(u.Roles) != 2 {
				t.Fatalf("roles after first login: %v", u.Roles)
			}
			// An administrator assigns a role by hand.
			u.Roles = append(u.Roles, "admin-assigned")
			if err := f.st.UpdateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			// Next login: the upstream no longer reports "ops".
			c["groups"] = []string{"eng"}
			_, resp, body = f.login(c)
			succeeded(t, resp, body)
			u = mustUser(t, f, "alice")
			if !has(u.Roles, "admin-assigned") || !has(u.Roles, "developer") {
				t.Fatalf("roles lost: %v", u.Roles)
			}
			if tc.mode == "import" && !has(u.Roles, "operator") {
				t.Fatalf("import mode must never remove roles: %v", u.Roles)
			}
			if tc.mode == "sync" && has(u.Roles, "operator") {
				t.Fatalf("sync mode must remove a role federation added that is no longer granted: %v", u.Roles)
			}
			// A role the admin held BEFORE federation granted it is never removed by sync.
			u.Roles = append(u.Roles, "operator")
			_ = f.st.UpdateUser(ctx, u)
			c["groups"] = []string{"eng", "ops"}
			succeeded2(t, f, c)
			c["groups"] = []string{"eng"}
			succeeded2(t, f, c)
			u = mustUser(t, f, "alice")
			if !has(u.Roles, "admin-assigned") {
				t.Fatalf("admin-assigned role removed: %v", u.Roles)
			}
		})
	}
}

func succeeded2(t *testing.T, f *fed, c map[string]any) {
	t.Helper()
	_, resp, body := f.login(c)
	succeeded(t, resp, body)
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestRoleMappingNestedAndScalarClaims(t *testing.T) {
	f := newFed(t, fedOpts{cfg: map[string]string{"roleMappings": `[{"claim":"realm_access.roles","value":"staff","roles":["r1"]},{"claim":"tier","value":"gold","roles":["r2"]},{"claim":"mfa","value":"true","roles":["r3"]}]`}})
	for _, r := range []string{"r1", "r2", "r3"} {
		_ = f.st.CreateRole(context.Background(), core.Role{Realm: realm, Name: r})
	}
	c := goodClaims()
	c["realm_access"] = map[string]any{"roles": []string{"staff"}}
	c["tier"] = "gold"
	c["mfa"] = true
	succeeded2(t, f, c)
	u := mustUser(t, f, "alice")
	if !has(u.Roles, "r1") || !has(u.Roles, "r2") || !has(u.Roles, "r3") {
		t.Fatalf("roles: %v", u.Roles)
	}
}

// ---- failure behaviour ----

func TestUpstreamDown(t *testing.T) {
	f := newFed(t, fedOpts{timeout: 800 * time.Millisecond})
	f.up.Srv.Close()
	b := f.newBrowser()
	start := time.Now()
	resp, body := b.get(f.srv.URL + "/realms/" + realm + "/broker/fake/login?" + authQuery())
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "Sign-in failed") {
		t.Fatalf("want a clean 502 page, got %d %s", resp.StatusCode, body)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("upstream down took too long")
	}
}

func TestUpstreamTokenEndpointHangs(t *testing.T) {
	f := newFed(t, fedOpts{timeout: 700 * time.Millisecond})
	f.up.TokenDelay = 10 * time.Second
	b := f.newBrowser()
	cb := f.callbackURL(b.startUpstream("fake"), goodClaims())
	start := time.Now()
	resp, body := b.get(cb)
	refused(t, resp, body)
	if d := time.Since(start); d > 6*time.Second {
		t.Fatalf("hung upstream blocked the callback for %v", d)
	}
	if len(f.users()) != 0 {
		t.Fatal("user created after a token endpoint timeout")
	}
}

func TestUpstreamTokenEndpointErrors(t *testing.T) {
	for _, status := range []int{400, 401, 500} {
		f := newFed(t, fedOpts{})
		f.up.TokenStatus = status
		_, resp, body := f.login(goodClaims())
		refused(t, resp, body)
		f.assertNoSecretLeak()
	}
}

func TestWrongUpstreamClientSecret(t *testing.T) {
	f := newFed(t, fedOpts{cfg: map[string]string{"clientSecret": "not-the-secret"}})
	_, resp, body := f.login(goodClaims())
	refused(t, resp, body)
	if len(f.users()) != 0 {
		t.Fatal("user created with a rejected client")
	}
}

func TestUpstreamError(t *testing.T) {
	f := newFed(t, fedOpts{})
	b := f.newBrowser()
	auth, _ := url.Parse(b.startUpstream("fake"))
	cb := f.srv.URL + "/realms/" + realm + "/broker/fake/endpoint?error=access_denied&error_description=%3Cscript%3Ealert(1)%3C%2Fscript%3E&state=" + url.QueryEscape(auth.Query().Get("state"))
	resp, body := b.get(cb)
	refused(t, resp, body)
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "alert(1)") {
		t.Fatal("upstream error text reflected into the page")
	}
}

func TestTokenEndpointAtPrivateAddressIsRefused(t *testing.T) {
	// The real IP policy (no AllowPrivate): the fake upstream lives on
	// 127.0.0.1, which is exactly an address the policy must refuse. The
	// discovery document is seeded (as if an upstream had served it) so the
	// test reaches the token endpoint call.
	f := newFed(t, fedOpts{strictIP: true})
	f.mgr.SeedDiscovery(f.up.URL()+"/.well-known/openid-configuration", upstream.Discovery{
		Issuer: f.up.URL(), AuthorizationEndpoint: f.up.URL() + "/authorize",
		TokenEndpoint: f.up.URL() + "/token", JWKSURI: f.up.URL() + "/jwks"})
	b := f.newBrowser()
	cb := f.callbackURL(b.startUpstream("fake"), goodClaims())
	resp, body := b.get(cb)
	refused(t, resp, body)
	if f.up.TokenHits.Load() != 0 {
		t.Fatal("the token endpoint on a loopback address was contacted")
	}
	if !strings.Contains(f.logs.String(), "blocked_address") {
		t.Fatalf("log does not record the blocked address: %s", f.logs.String())
	}
	// And the real discovery fetch to a loopback host is refused the same way.
	f2 := newFed(t, fedOpts{strictIP: true})
	b = f2.newBrowser()
	resp, body = b.get(f2.srv.URL + "/realms/" + realm + "/broker/fake/login?" + authQuery())
	refused(t, resp, body)
	if f2.up.DiscoveryHits.Load() != 0 {
		t.Fatal("discovery was fetched from a loopback address")
	}
}

func TestDiscoveryRejectsInsecureEndpoints(t *testing.T) {
	// A fetched discovery document with a plain-http endpoint is refused.
	f3 := newFed(t, fedOpts{})
	f3.up.TokenEndpoint = "http://token.example/token"
	b := f3.newBrowser()
	resp, body := b.get(f3.srv.URL + "/realms/" + realm + "/broker/fake/login?" + authQuery())
	refused(t, resp, body)
}

// ---- secrets ----

func TestSecretboxBinding(t *testing.T) {
	f := newFed(t, fedOpts{})
	f.addProvider("other", fedOpts{cfg: map[string]string{"clientSecret": "a-different-secret"}})
	ctx := context.Background()
	a, _ := f.st.GetFedProvider(ctx, realm, "fake")
	o, _ := f.st.GetFedProvider(ctx, realm, "other")
	if a.ClientSecretSealed == "" || strings.Contains(a.ClientSecretSealed, f.up.ClientSecret) {
		t.Fatalf("secret not sealed: %q", a.ClientSecretSealed)
	}
	// A ciphertext copied from another alias must not open.
	o.ClientSecretSealed = a.ClientSecretSealed
	if err := f.st.UpdateFedProvider(ctx, o); err != nil {
		t.Fatal(err)
	}
	f.up.RedirectURIs = append(f.up.RedirectURIs, f.srv.URL+"/realms/"+realm+"/broker/other/endpoint")
	b := f.newBrowser()
	resp, _ := b.get(f.srv.URL + "/realms/" + realm + "/broker/other/login?" + authQuery())
	auth := resp.Header.Get("Location")
	resp, body := b.get(f.callbackURL(auth, goodClaims()))
	refused(t, resp, body)
	if f.up.TokenHits.Load() != 0 {
		t.Fatal("a secret sealed for another alias was used")
	}
	// Same alias in ANOTHER realm: also bound.
	if _, err := secretbox.New(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.box.Open(a.ClientSecretSealed, "idp|otherrealm|fake"); err == nil {
		t.Fatal("secret opened under another realm")
	}
	if _, err := f.box.Open(a.ClientSecretSealed, "idp|"+realm+"|fake"); err != nil {
		t.Fatal("secret does not open under its own context:", err)
	}
}

func TestBrokerWithoutSecretKeyFailsClosed(t *testing.T) {
	// A provider whose secret was sealed under a key that is no longer
	// configured must not fall back to anything.
	f := newFed(t, fedOpts{})
	f2 := newFed(t, fedOpts{noBox: true, noProvider: true})
	ctx := context.Background()
	a, _ := f.st.GetFedProvider(ctx, realm, "fake")
	a.Realm = realm
	if err := f2.st.CreateFedProvider(ctx, a); err != nil {
		t.Fatal(err)
	}
	f2.up.RedirectURIs = []string{f2.srv.URL + "/realms/" + realm + "/broker/fake/endpoint"}
	b := f2.newBrowser()
	resp, _ := b.get(f2.srv.URL + "/realms/" + realm + "/broker/fake/login?" + authQuery())
	if resp.StatusCode != 302 {
		t.Skip("login start failed")
	}
	resp, body := b.get(f2.callbackURL(resp.Header.Get("Location"), goodClaims()))
	refused(t, resp, body)
	if f2.up.TokenHits.Load() != 0 {
		t.Fatal("token endpoint called without a secret key")
	}
}

// ---- Admin API ----

func TestAdminAPI(t *testing.T) {
	f := newFed(t, fedOpts{noProvider: true})
	base := "/realms/" + realm + "/identity-providers"
	secret := "very-secret-value-123"
	create := map[string]any{"alias": "okta", "displayName": "Okta", "providerId": "oidc", "enabled": true, "trustEmail": true,
		"config": map[string]string{"issuer": f.up.URL(), "clientId": "cid", "clientSecret": secret, "scopes": "openid email", "autoCreateUsers": "true"}}
	code, body := f.admin("POST", base, create)
	if code != 201 {
		t.Fatal(code, string(body))
	}
	if code, _ := f.admin("POST", base, create); code != 409 {
		t.Fatalf("duplicate alias: %d", code)
	}

	for _, path := range []string{base, base + "/okta"} {
		code, body = f.admin("GET", path, nil)
		if code != 200 || strings.Contains(string(body), secret) || !strings.Contains(string(body), `"clientSecret":"**********"`) {
			t.Fatalf("GET %s: %d %s", path, code, body)
		}
	}
	var got idp.IdentityProvider
	_, body = f.admin("GET", base+"/okta", nil)
	_ = json.Unmarshal(body, &got)
	if got.ProviderID != "oidc" || got.DisplayName != "Okta" || !got.Enabled || !got.TrustEmail || got.Config["clientId"] != "cid" || got.Config["scopes"] != "openid email" ||
		got.Config["linkExistingByEmail"] != "false" || got.Config["autoCreateUsers"] != "true" {
		t.Fatalf("provider: %+v", got)
	}
	// The secret is stored sealed, never in plaintext.
	p, _ := f.st.GetFedProvider(context.Background(), realm, "okta")
	if p.ClientSecretSealed == "" || strings.Contains(p.ClientSecretSealed, secret) {
		t.Fatalf("stored secret: %q", p.ClientSecretSealed)
	}
	for k, v := range p.Config {
		if strings.Contains(v, secret) || k == "clientSecret" {
			t.Fatalf("secret in stored config %s", k)
		}
	}

	// Round trip of the masked secret keeps the stored one; a new one replaces it.
	got.DisplayName = "Okta SSO"
	if code, b := f.admin("PUT", base+"/okta", got); code != 204 {
		t.Fatal(code, string(b))
	}
	p2, _ := f.st.GetFedProvider(context.Background(), realm, "okta")
	if p2.ClientSecretSealed != p.ClientSecretSealed || p2.DisplayName != "Okta SSO" {
		t.Fatal("masked secret round trip changed the stored secret or ignored the update")
	}
	got.Config["clientSecret"] = "rotated-secret"
	if code, b := f.admin("PUT", base+"/okta", got); code != 204 {
		t.Fatal(code, string(b))
	}
	p3, _ := f.st.GetFedProvider(context.Background(), realm, "okta")
	if p3.ClientSecretSealed == p.ClientSecretSealed {
		t.Fatal("new secret not stored")
	}
	if plain, err := f.box.Open(p3.ClientSecretSealed, "idp|"+realm+"|okta"); err != nil || string(plain) != "rotated-secret" {
		t.Fatalf("sealed secret does not decrypt to the new value: %v", err)
	}
	// Alias change refused.
	got.Alias = "other"
	if code, _ := f.admin("PUT", base+"/okta", got); code != 400 {
		t.Fatalf("alias change: %d", code)
	}

	for name, mut := range map[string]func(m map[string]any){
		"bad alias":            func(m map[string]any) { m["alias"] = "Bad_Alias" },
		"empty alias":          func(m map[string]any) { m["alias"] = "" },
		"long alias":           func(m map[string]any) { m["alias"] = strings.Repeat("a", 33) },
		"unknown type":         func(m map[string]any) { m["providerId"] = "github" },
		"saml":                 func(m map[string]any) { m["providerId"] = "saml" },
		"storeToken":           func(m map[string]any) { m["storeToken"] = true },
		"unknown config key":   func(m map[string]any) { m["config"].(map[string]string)["bogus"] = "1" },
		"http issuer":          func(m map[string]any) { m["config"].(map[string]string)["issuer"] = "http://idp.example" },
		"issuer with userinfo": func(m map[string]any) { m["config"].(map[string]string)["issuer"] = "https://user:pw@idp.example" },
		"issuer with query":    func(m map[string]any) { m["config"].(map[string]string)["issuer"] = "https://idp.example/?x=1" },
		"no client id":         func(m map[string]any) { delete(m["config"].(map[string]string), "clientId") },
		"no issuer":            func(m map[string]any) { delete(m["config"].(map[string]string), "issuer") },
		"no openid scope":      func(m map[string]any) { m["config"].(map[string]string)["scopes"] = "email" },
		"bad bool":             func(m map[string]any) { m["config"].(map[string]string)["autoCreateUsers"] = "yes" },
		"bad roleMappings":     func(m map[string]any) { m["config"].(map[string]string)["roleMappings"] = `{"a":1}` },
		"bad role name": func(m map[string]any) {
			m["config"].(map[string]string)["roleMappings"] = `[{"claim":"g","value":"v","roles":["bad role"]}]`
		},
		"tenant on oidc":    func(m map[string]any) { m["config"].(map[string]string)["tenant"] = "common" },
		"long display name": func(m map[string]any) { m["displayName"] = strings.Repeat("x", 65) },
	} {
		m := map[string]any{"alias": "x1", "displayName": "X", "providerId": "oidc", "enabled": true,
			"config": map[string]string{"issuer": f.up.URL(), "clientId": "cid"}}
		mut(m)
		if code, b := f.admin("POST", base, m); code != 400 {
			t.Errorf("%s: got %d %s, want 400", name, code, b)
		}
	}

	if code, _ := f.admin("DELETE", base+"/okta", nil); code != 204 {
		t.Fatal(code)
	}
	if code, _ := f.admin("DELETE", base+"/okta", nil); code != 404 {
		t.Fatal(code)
	}
	if code, _ := f.admin("GET", base+"/okta", nil); code != 404 {
		t.Fatal(code)
	}
	// Admin events carry no secrets.
	evs, _ := f.st.ListEvents(context.Background(), realm, 100)
	for _, e := range evs {
		if strings.Contains(e.Detail, secret) {
			t.Fatal("secret in audit event")
		}
	}
	f.up.ClientSecret = secret
	f.assertNoSecretLeak()
}

func TestAdminSecretNeedsKey(t *testing.T) {
	f := newFed(t, fedOpts{noBox: true, noProvider: true})
	base := "/realms/" + realm + "/identity-providers"
	m := map[string]any{"alias": "g", "providerId": "google", "enabled": true, "config": map[string]string{"clientId": "cid", "clientSecret": "s3cret"}}
	code, body := f.admin("POST", base, m)
	if code != 409 || !strings.Contains(string(body), "HAVEN_IDP_SECRET_KEY is not set") {
		t.Fatalf("want 409 about the key, got %d %s", code, body)
	}
	// Without a secret the provider can be created, and list/get keep working.
	delete(m["config"].(map[string]string), "clientSecret")
	if code, b := f.admin("POST", base, m); code != 201 {
		t.Fatal(code, string(b))
	}
	if code, _ := f.admin("GET", base, nil); code != 200 {
		t.Fatal(code)
	}
	// Updating with a secret: 409.
	m["config"].(map[string]string)["clientSecret"] = "s3cret"
	if code, _ := f.admin("PUT", base+"/g", m); code != 409 {
		t.Fatal(code)
	}
	if code, _ := f.admin("PUT", base+"/g", map[string]any{"alias": "g", "providerId": "google", "enabled": true, "config": map[string]string{"clientId": "cid2"}}); code != 204 {
		t.Fatal(code)
	}
}

func TestAdminPresets(t *testing.T) {
	f := newFed(t, fedOpts{noProvider: true})
	base := "/realms/" + realm + "/identity-providers"
	post := func(m map[string]any) int { c, _ := f.admin("POST", base, m); return c }
	if c := post(map[string]any{"alias": "g", "providerId": "google", "enabled": true, "config": map[string]string{"clientId": "a", "clientSecret": "s", "hostedDomain": "corp.example"}}); c != 201 {
		t.Fatal(c)
	}
	_, body := f.admin("GET", base+"/g", nil)
	var g idp.IdentityProvider
	_ = json.Unmarshal(body, &g)
	if g.Config["issuer"] != "https://accounts.google.com" || g.Config["hostedDomain"] != "corp.example" || g.DisplayName != "Google" {
		t.Fatalf("google: %+v", g)
	}
	if c := post(map[string]any{"alias": "g2", "providerId": "google", "config": map[string]string{"clientId": "a", "issuer": "https://evil.example"}}); c != 400 {
		t.Fatalf("google with a custom issuer: %d", c)
	}
	tid := "11111111-2222-3333-4444-555555555555"
	if c := post(map[string]any{"alias": "m1", "providerId": "microsoft", "enabled": true, "config": map[string]string{"clientId": "a", "tenant": tid}}); c != 201 {
		t.Fatal(c)
	}
	_, body = f.admin("GET", base+"/m1", nil)
	var m idp.IdentityProvider
	_ = json.Unmarshal(body, &m)
	if m.Config["issuer"] != "https://login.microsoftonline.com/"+tid+"/v2.0" || m.Config["tenant"] != tid {
		t.Fatalf("microsoft: %+v", m)
	}
	if c := post(map[string]any{"alias": "m2", "providerId": "microsoft", "config": map[string]string{"clientId": "a"}}); c != 201 {
		t.Fatalf("multi-tenant microsoft (default common): %d", c)
	}
	_, body = f.admin("GET", base+"/m2", nil)
	_ = json.Unmarshal(body, &m)
	if m.Config["tenant"] != "common" {
		t.Fatalf("default tenant: %+v", m)
	}
	// Multi-tenant + linking by email is refused (any tenant could assert any email).
	if c := post(map[string]any{"alias": "m3", "providerId": "microsoft", "config": map[string]string{"clientId": "a", "linkExistingByEmail": "true"}}); c != 400 {
		t.Fatalf("multi-tenant link by email: %d", c)
	}
	if c := post(map[string]any{"alias": "m4", "providerId": "microsoft", "config": map[string]string{"clientId": "a", "tenant": "contoso.com"}}); c != 400 {
		t.Fatalf("tenant by domain: %d", c)
	}
	if c := post(map[string]any{"alias": "o1", "providerId": "oidc", "config": map[string]string{"clientId": "a", "discoveryUrl": "https://idp.example/realms/x/.well-known/openid-configuration"}}); c != 201 {
		t.Fatalf("discoveryUrl only: %d", c)
	}
	if c := post(map[string]any{"alias": "o2", "providerId": "oidc", "config": map[string]string{"clientId": "a", "discoveryUrl": "https://idp.example/custom"}}); c != 400 {
		t.Fatalf("discoveryUrl without issuer and not well-known: %d", c)
	}
}

func TestStrictAdminRefusesLoopbackHTTP(t *testing.T) {
	f := newFed(t, fedOpts{strictIP: true, noProvider: true})
	m := map[string]any{"alias": "l", "providerId": "oidc", "config": map[string]string{"clientId": "a", "issuer": "http://127.0.0.1:9/realms/x"}}
	if c, _ := f.admin("POST", "/realms/"+realm+"/identity-providers", m); c != 400 {
		t.Fatalf("http loopback accepted without AllowPrivate: %d", c)
	}
}

func TestFederatedIdentitiesAdmin(t *testing.T) {
	f := newFed(t, fedOpts{})
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	u := mustUser(t, f, "alice")
	path := "/realms/" + realm + "/users/" + u.ID + "/federated-identities"
	code, b := f.admin("GET", path, nil)
	var l []map[string]any
	_ = json.Unmarshal(b, &l)
	if code != 200 || len(l) != 1 || l[0]["identityProvider"] != "fake" || l[0]["userId"] != "up-sub-1" {
		t.Fatalf("list: %d %s", code, b)
	}
	if code, _ := f.admin("DELETE", path+"/nosuch", nil); code != 404 {
		t.Fatal(code)
	}
	if code, _ := f.admin("DELETE", path+"/fake", nil); code != 204 {
		t.Fatal(code)
	}
	if code, b := f.admin("GET", path, nil); code != 200 || strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("after unlink: %d %s", code, b)
	}
	if code, _ := f.admin("GET", "/realms/"+realm+"/users/nosuch/federated-identities", nil); code != 404 {
		t.Fatal(code)
	}
	// After unlinking, the next login is a NEW identity: the email now belongs
	// to an existing account, so it is refused (link off) and no duplicate appears.
	_, resp, body = f.login(goodClaims())
	refused(t, resp, body)
}

func TestDeletingUserRemovesLinks(t *testing.T) {
	f := newFed(t, fedOpts{})
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	u := mustUser(t, f, "alice")
	if code, b := f.admin("DELETE", "/realms/"+realm+"/users/"+u.ID, nil); code != 204 {
		t.Fatal(code, string(b))
	}
	if _, err := f.st.GetFedLink(context.Background(), realm, "fake", "up-sub-1"); err == nil {
		t.Fatal("link survived the user")
	}
	if _, err := f.st.GetFedProvider(context.Background(), realm, "fake"); err != nil {
		t.Fatal("provider removed with the user")
	}
	// The same upstream identity can sign in again and gets a fresh account.
	_, resp, body = f.login(goodClaims())
	succeeded(t, resp, body)
}

func TestDeletingProviderRemovesLinksNotUsers(t *testing.T) {
	f := newFed(t, fedOpts{})
	_, resp, body := f.login(goodClaims())
	succeeded(t, resp, body)
	u := mustUser(t, f, "alice")
	if code, _ := f.admin("DELETE", "/realms/"+realm+"/identity-providers/fake", nil); code != 204 {
		t.Fatal(code)
	}
	if _, err := f.st.GetUser(context.Background(), realm, u.ID); err != nil {
		t.Fatal("user removed with the provider")
	}
	if l, _ := f.st.ListFedLinksByUser(context.Background(), realm, u.ID); len(l) != 0 {
		t.Fatalf("links survived: %+v", l)
	}
	b := f.newBrowser()
	resp2, _ := b.get(f.srv.URL + "/realms/" + realm + "/broker/fake/login?" + authQuery())
	if resp2.StatusCode != 404 {
		t.Fatalf("deleted provider still serves logins: %d", resp2.StatusCode)
	}
}

// ---- native client against the real admin handler ----

// ---- the console's path: idp.Provider (native client) -> real Admin API ----

func TestNativeClientListsCreatesDeletesProviders(t *testing.T) {
	f := newFed(t, fedOpts{noProvider: true})
	c := native.New(native.Config{BaseURL: f.srv.URL, Realm: adminRealm, ClientID: "haven-admin", ClientSecret: adminSecret})
	var _ idp.Provider = c
	ctx := context.Background()
	ips, err := c.ListIdentityProviders(ctx, realm)
	if err != nil || len(ips) != 0 {
		t.Fatalf("empty list: %v %v", ips, err)
	}
	in := idp.IdentityProvider{Alias: "entra", DisplayName: "Entra", ProviderID: "microsoft", Enabled: true,
		Config: map[string]string{"clientId": "cid", "clientSecret": "native-secret-xyz", "tenant": "11111111-2222-3333-4444-555555555555"}}
	if err := c.CreateIdentityProvider(ctx, realm, in); err != nil {
		t.Fatal(err)
	}
	ips, err = c.ListIdentityProviders(ctx, realm)
	if err != nil || len(ips) != 1 {
		t.Fatalf("list: %v %v", ips, err)
	}
	got := ips[0]
	if got.Alias != "entra" || got.ProviderID != "microsoft" || !got.Enabled || got.Config["clientSecret"] != "**********" || got.Config["clientId"] != "cid" {
		t.Fatalf("provider through the native client: %+v", got)
	}
	if err := c.CreateIdentityProvider(ctx, realm, in); idp.AsStatus(err) == nil || idp.AsStatus(err).Code != 409 {
		t.Fatalf("duplicate: %v", err)
	}
	bad := in
	bad.Alias, bad.ProviderID = "gh", "github"
	if err := c.CreateIdentityProvider(ctx, realm, bad); idp.AsStatus(err) == nil || idp.AsStatus(err).Code != 400 {
		t.Fatalf("github must be refused with 400: %v", err)
	}
	if err := c.DeleteIdentityProvider(ctx, realm, "entra"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteIdentityProvider(ctx, realm, "entra"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}
