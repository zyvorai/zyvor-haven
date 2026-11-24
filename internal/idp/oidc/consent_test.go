// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
	"github.com/zyvorai/haven/internal/idp/upstream"
)

const cbC = "http://localhost:8765/callback"

// cenv is a denv with the CIMD fetch client allowed to reach loopback and a
// metadata-document server whose answers a test controls.
type cenv struct {
	*denv
	srv  *httptest.Server
	mu   sync.Mutex
	hits map[string]int
	// serve overrides the document answer for a path (nil = default document).
	serve map[string]func(w http.ResponseWriter, r *http.Request)
	redir []string // redirect_uris of the default document
	name  string
}

func newCEnv(t *testing.T, allowPrivate bool, o devOpts) *cenv {
	t.Helper()
	e := &cenv{denv: newDEnv(t, o), hits: map[string]int{}, serve: map[string]func(http.ResponseWriter, *http.Request){},
		redir: []string{cbC}, name: "Demo MCP"}
	e.srv = httptest.NewServer(http.HandlerFunc(e.handle))
	t.Cleanup(e.srv.Close)
	clock := func() time.Time { e.denv.mu.Lock(); defer e.denv.mu.Unlock(); return e.denv.now }
	var st core.Store = e.denv.st
	if o.store != nil {
		st = o.store(st)
	}
	e.h = New(Config{Store: st, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{}, BaseURL: idpBase, Clock: clock,
		CSRFKey:    []byte("0123456789abcdef0123456789abcdef"),
		Federation: upstream.NewManager(safehttp.Options{AllowPrivate: allowPrivate}, clock)})
	return e
}

func (e *cenv) handle(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	e.hits[r.URL.Path]++
	h := e.serve[r.URL.Path]
	e.mu.Unlock()
	if h != nil {
		h(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"client_id":%q,"client_name":%q,"client_uri":"https://demo.example","redirect_uris":[%s],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}`,
		e.srv.URL+r.URL.Path, e.name, `"`+strings.Join(e.redir, `","`)+`"`)
}

func (e *cenv) hitCount(path string) int { e.mu.Lock(); defer e.mu.Unlock(); return e.hits[path] }
func (e *cenv) id(path string) string    { return e.srv.URL + path }

func (e *cenv) policy(p core.ConsentPolicy) {
	e.t.Helper()
	p.Realm = "r"
	if err := e.denv.st.PutConsentPolicy(context.Background(), p); err != nil {
		e.t.Fatal(err)
	}
}

func cq(clientID string, over map[string]string) url.Values {
	q := url.Values{"client_id": {clientID}, "redirect_uri": {cbC}, "response_type": {"code"}, "state": {"st8"},
		"scope": {"openid profile"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	for k, v := range over {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q
}

var digestRe = regexp.MustCompile(`name="consent_proof" value="([^"]+)"`)

// authorize drives /auth: GET, log in when asked. It returns the response that
// is NOT a login page (a consent page, a redirect, an error).
func (b *browser) authorize(q url.Values) *httptest.ResponseRecorder {
	return b.authorizeAs(q, "alice")
}

func (b *browser) authorizeAs(q url.Values, user string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	u := base + "auth?" + q.Encode()
	w := b.do("GET", u, nil)
	if w.Code == 200 && strings.Contains(w.Body.String(), `name="username"`) {
		m := csrfRe.FindStringSubmatch(w.Body.String())
		w = b.do("POST", u, url.Values{"username": {user}, "password": {"pw"}, "csrf": {m[1]}})
	}
	return w
}

// consentDecide posts the consent form shown in page.
func (b *browser) consentDecide(page *httptest.ResponseRecorder, q url.Values, decision string) *httptest.ResponseRecorder {
	b.e.t.Helper()
	body := page.Body.String()
	c, d := csrfRe.FindStringSubmatch(body), digestRe.FindStringSubmatch(body)
	if c == nil || d == nil {
		b.e.t.Fatalf("not a consent page (%d): %s", page.Code, body)
	}
	return b.do("POST", base+"auth?"+q.Encode(), url.Values{"csrf": {c[1]}, "consent_proof": {d[1]}, "consent_decision": {decision}})
}

func isConsentPage(w *httptest.ResponseRecorder) bool {
	return w.Code == 200 && strings.Contains(w.Body.String(), "consent_decision")
}

func codeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != 302 {
		t.Fatalf("want redirect with code, got %d: %s", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code in %s", loc)
	}
	return loc.Query().Get("code")
}

func errOfRedirect(w *httptest.ResponseRecorder) string {
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 302 {
		return ""
	}
	return loc.Query().Get("error")
}

func (e *cenv) exchange(clientID, code string) (int, map[string]any) {
	c, out, _ := e.post(base+"token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cbC},
		"client_id": {clientID}, "code_verifier": {verifier}}, "", "", "")
	return c, out
}

func (e *cenv) receipts() []core.ConsentReceipt {
	rs, err := e.denv.st.ListConsentReceipts(context.Background(), "r", "", 0, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	return rs
}

// ---- parsing ----

func TestParseCIMD(t *testing.T) {
	const id = "https://app.example/client.json"
	ok := `{"client_id":"https://app.example/client.json","client_name":"App","redirect_uris":["https://app.example/cb","http://127.0.0.1:9/cb","com.example.app:/cb"]}`
	d, err := parseCIMD(id, []byte(ok), false)
	if err != nil || d.Name != "App" || len(d.RedirectURIs) != 3 {
		t.Fatalf("valid document refused: %+v %v", d, err)
	}
	with := func(extra string) string {
		return `{"client_id":"https://app.example/client.json","redirect_uris":["https://app.example/cb"],` + extra + `}`
	}
	bad := map[string]string{
		"client_id differs (slash)":      `{"client_id":"https://app.example/client.json/","redirect_uris":["https://app.example/cb"]}`,
		"client_id differs (case)":       `{"client_id":"https://APP.example/client.json","redirect_uris":["https://app.example/cb"]}`,
		"client_id missing":              `{"redirect_uris":["https://app.example/cb"]}`,
		"client_id not a string":         `{"client_id":5,"redirect_uris":["https://app.example/cb"]}`,
		"no redirect_uris":               `{"client_id":"https://app.example/client.json"}`,
		"empty redirect_uris":            `{"client_id":"https://app.example/client.json","redirect_uris":[]}`,
		"wildcard redirect":              `{"client_id":"https://app.example/client.json","redirect_uris":["https://*.example/cb"]}`,
		"http non-loopback":              `{"client_id":"https://app.example/client.json","redirect_uris":["http://app.example/cb"]}`,
		"fragment redirect":              `{"client_id":"https://app.example/client.json","redirect_uris":["https://app.example/cb#x"]}`,
		"javascript redirect":            `{"client_id":"https://app.example/client.json","redirect_uris":["javascript:alert(1)"]}`,
		"scheme without dot":             `{"client_id":"https://app.example/client.json","redirect_uris":["myapp://cb"]}`,
		"userinfo redirect":              `{"client_id":"https://app.example/client.json","redirect_uris":["https://u:p@app.example/cb"]}`,
		"duplicate redirect":             `{"client_id":"https://app.example/client.json","redirect_uris":["https://app.example/cb","https://app.example/cb"]}`,
		"redirect not strings":           `{"client_id":"https://app.example/client.json","redirect_uris":[1]}`,
		"client_secret":                  with(`"client_secret":"x"`),
		"client_secret_expires_at":       with(`"client_secret_expires_at":0`),
		"registration_access_token":      with(`"registration_access_token":"x"`),
		"auth method basic":              with(`"token_endpoint_auth_method":"client_secret_basic"`),
		"auth method post":               with(`"token_endpoint_auth_method":"client_secret_post"`),
		"auth method private_key_jwt":    with(`"token_endpoint_auth_method":"private_key_jwt"`),
		"auth method not a string":       with(`"token_endpoint_auth_method":["none"]`),
		"client_credentials grant":       with(`"grant_types":["client_credentials"]`),
		"implicit response type":         with(`"response_types":["token"]`),
		"not JSON":                       `nope`,
		"JSON array":                     `[]`,
		"null":                           `null`,
		"trailing data":                  ok + `{}`,
		"too many redirects":             `{"client_id":"https://app.example/client.json","redirect_uris":["` + strings.Join(manyURIs(11), `","`) + `"]}`,
		"redirect with space":            `{"client_id":"https://app.example/client.json","redirect_uris":["https://app.example/a b"]}`,
		"redirect with backslash":        `{"client_id":"https://app.example/client.json","redirect_uris":["https://app.example\\@evil/cb"]}`,
		"data redirect":                  `{"client_id":"https://app.example/client.json","redirect_uris":["data:text/html,x"]}`,
		"client_name not a string":       with(`"client_name":{}`),
		"response_types two entries":     with(`"response_types":["code","token"]`),
		"refresh+device grant":           with(`"grant_types":["urn:ietf:params:oauth:grant-type:device_code"]`),
		"auth method private_key_jwt #2": with(`"token_endpoint_auth_method":"tls_client_auth"`),
	}
	for name, doc := range bad {
		if _, err := parseCIMD(id, []byte(doc), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Optional fields: an invalid client_uri is dropped, not fatal; names are cleaned.
	d, err = parseCIMD(id, []byte(with(`"client_uri":"javascript:x","client_name":"Evil‮App\u0007 `+strings.Repeat("x", 200)+`"`)), false)
	if err != nil || d.ClientURI != "" || strings.ContainsAny(d.Name, "‮\u0007") || len([]rune(d.Name)) > cimdMaxName {
		t.Errorf("optional fields: %+v %v", d, err)
	}
	// Unknown members are ignored.
	if _, err := parseCIMD(id, []byte(with(`"software_statement":"x","jwks_uri":"https://x"`)), false); err != nil {
		t.Errorf("unknown members must be ignored: %v", err)
	}
}

func manyURIs(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("https://app.example/cb%d", i))
	}
	return out
}

func TestCIMDClientIDShape(t *testing.T) {
	good := []string{"https://app.example/client.json", "https://app.example:8443/a/b", "https://app.example/c?x=1"}
	for _, s := range good {
		if !isCIMDClientID(s, false) {
			t.Errorf("%s refused", s)
		}
	}
	bad := []string{"hc_abc", "app", "https://app.example", "https://app.example/", "http://app.example/c.json",
		"https://user:pw@app.example/c.json", "https://app.example/c.json#f", "https://app.example/a/../c.json",
		"https://app.example/a/./c.json", "https://app.example/%2e%2e/c.json", "https://app.example/c json",
		"https://app.example/a\\b", "ftp://app.example/c.json", "https:///c.json", "https://app.example/" + strings.Repeat("a", 2100)}
	for _, s := range bad {
		if isCIMDClientID(s, false) {
			t.Errorf("%q accepted", s)
		}
	}
	if isCIMDClientID("http://127.0.0.1:9/c.json", false) || !isCIMDClientID("http://127.0.0.1:9/c.json", true) {
		t.Error("http loopback must be allowed only with the dev switch")
	}
	if isCIMDClientID("http://app.example/c.json", true) {
		t.Error("http to a public host must never be allowed")
	}
}

func TestCacheTTL(t *testing.T) {
	for cc, want := range map[string]time.Duration{"": cimdDefaultTTL, "max-age=1": cimdMinTTL, "max-age=1800": 30 * time.Minute,
		"public, max-age=999999": cimdMaxTTL, "no-store": cimdMinTTL, "max-age=abc": cimdDefaultTTL, "max-age=-5": cimdDefaultTTL} {
		if got := cacheTTL(http.Header{"Cache-Control": {cc}}); got != want {
			t.Errorf("%q -> %v want %v", cc, got, want)
		}
	}
}

// ---- CIMD resolution ----

func TestCIMDOffByDefault(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	b := e.browser()
	w := b.do("GET", base+"auth?"+cq(e.id("/c/app.json"), nil).Encode(), nil)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "Invalid client") {
		t.Fatalf("CIMD must be off by default: %d %s", w.Code, w.Body)
	}
	if e.hitCount("/c/app.json") != 0 {
		t.Fatal("the document was fetched although the realm did not opt in")
	}
	if _, err := e.denv.st.GetClientByClientID(context.Background(), "r", e.id("/c/app.json")); err == nil {
		t.Fatal("a client was created while the feature is off")
	}
}

func TestCIMDFullFlowAndAlwaysConsent(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	id := e.id("/c/app.json")
	b := e.browser()
	q := cq(id, map[string]string{"resource": "https://mcp.example/mcp"})

	w := b.authorize(q)
	if !isConsentPage(w) {
		t.Fatalf("a CIMD client must reach the consent screen, got %d: %s", w.Code, w.Body)
	}
	page := w.Body.String()
	for _, want := range []string{"Demo MCP", id, "https://mcp.example/mcp", "<code>profile</code>", cbC, "https://demo.example"} {
		if !strings.Contains(page, want) {
			t.Errorf("consent page lacks %q", want)
		}
	}
	if strings.Contains(w.Header().Get("Location"), "code=") {
		t.Fatal("code issued before consent")
	}
	// Page hardening.
	h := w.Header()
	if h.Get("X-Frame-Options") != "DENY" || h.Get("Cache-Control") != "no-store" ||
		!strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		!strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") || strings.Contains(h.Get("Content-Security-Policy"), "script-src") {
		t.Errorf("consent page headers: %v", h)
	}
	nonce := regexp.MustCompile(`style-src 'nonce-([^']+)'`).FindStringSubmatch(h.Get("Content-Security-Policy"))
	if nonce == nil || !strings.Contains(page, `<style nonce="`+nonce[1]+`">`) {
		t.Error("CSP nonce does not match the page")
	}
	// The materialised client is a public, PKCE-only, auth-code client.
	cl, err := e.denv.st.GetClientByClientID(context.Background(), "r", id)
	if err != nil || !cl.Public || !cl.RequirePKCE || !cl.AuthCodeFlow || cl.SecretHash != "" || cl.PasswordFlow || cl.ServiceAccount || len(cl.RedirectURIs) != 1 {
		t.Fatalf("cimd client row: %+v %v", cl, err)
	}

	// Allow: code, token exchange, grant, receipt, event.
	code := codeOf(t, b.consentDecide(w, q, "allow"))
	if st, tok := e.exchange(id, code); st != 200 || tok["access_token"] == nil {
		t.Fatalf("token exchange for the CIMD client: %d %v", st, tok)
	}
	gs, _ := e.denv.st.ListConsentGrants(context.Background(), "r", "u1", id, false, e.now, 10)
	if len(gs) != 1 || strings.Join(gs[0].Scopes, " ") != "openid profile" || strings.Join(gs[0].Resources, " ") != "https://mcp.example/mcp" {
		t.Fatalf("grant: %+v", gs)
	}
	rs := e.receipts()
	if len(rs) != 1 || rs[0].Type != core.ReceiptGrant || rs[0].UserID != "u1" || rs[0].ClientID != id || rs[0].Actor != "u1" {
		t.Fatalf("receipts: %+v", rs)
	}
	var sawEvent bool
	evs, _ := e.denv.st.ListEvents(context.Background(), "r", 100)
	for _, ev := range evs {
		sawEvent = sawEvent || ev.Type == "CONSENT_GRANT"
	}
	if !sawEvent {
		t.Error("no CONSENT_GRANT audit event")
	}

	// Never auto-trusted: with a live grant and a live SSO session the consent
	// screen shows again, because RememberCIMD is off.
	if w2 := b.authorize(q); !isConsentPage(w2) {
		t.Fatalf("CIMD clients must be asked every time: %d %s", w2.Code, w2.Body)
	}
	// prompt=none cannot show it: consent_required, never a code.
	if w3 := b.authorize(cq(id, map[string]string{"prompt": "none", "resource": "https://mcp.example/mcp"})); errOfRedirect(w3) != "consent_required" {
		t.Fatalf("prompt=none: %d %s", w3.Code, w3.Header().Get("Location"))
	}
}

func TestCIMDRememberOptIn(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true, RememberCIMD: true})
	id := e.id("/c/app.json")
	b := e.browser()
	q := cq(id, nil)
	w := b.authorize(q)
	codeOf(t, b.consentDecide(w, q, "allow"))
	// Remembered: straight to a code.
	codeOf(t, b.authorize(q))
	// More scopes than the grant covers: asked again.
	if w := b.authorize(cq(id, map[string]string{"scope": "openid profile email"})); !isConsentPage(w) {
		t.Fatalf("a wider scope must re-ask: %d", w.Code)
	}
	// A resource the grant does not cover: asked again.
	if w := b.authorize(cq(id, map[string]string{"resource": "https://other.example/mcp"})); !isConsentPage(w) {
		t.Fatalf("a new resource must re-ask: %d", w.Code)
	}
	// prompt=consent forces it.
	if w := b.authorize(cq(id, map[string]string{"prompt": "consent"})); !isConsentPage(w) {
		t.Fatalf("prompt=consent must show the screen: %d", w.Code)
	}
	// The grant expires.
	e.advance(core.ConsentDefaultGrantTTL + time.Hour)
	b2 := e.browser()
	if w := b2.authorize(q); !isConsentPage(w) {
		t.Fatalf("an expired grant must re-ask: %d", w.Code)
	}
}

func TestCIMDFingerprintChangeReasks(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true, RememberCIMD: true})
	id := e.id("/c/app.json")
	b := e.browser()
	q := cq(id, nil)
	codeOf(t, b.consentDecide(b.authorize(q), q, "allow"))
	codeOf(t, b.authorize(q))
	// The document changes its name and adds a redirect URI: the cache expires,
	// the new document is fetched, and the old consent no longer applies.
	e.mu.Lock()
	e.name, e.redir = "Renamed", []string{cbC, "http://localhost:9/other"}
	e.mu.Unlock()
	e.advance(2 * time.Hour)
	w := b.authorize(q)
	if !isConsentPage(w) || !strings.Contains(w.Body.String(), "Renamed") {
		t.Fatalf("a changed document must re-ask with the new name: %d %s", w.Code, w.Body)
	}
	if n := e.hitCount("/c/app.json"); n != 2 {
		t.Fatalf("fetches: %d", n)
	}
}

func TestCIMDCache(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	id := e.id("/c/app.json")
	for i := 0; i < 3; i++ {
		b := e.browser()
		if w := b.do("GET", base+"auth?"+cq(id, nil).Encode(), nil); w.Code != 200 {
			t.Fatalf("login page %d", w.Code)
		}
	}
	if n := e.hitCount("/c/app.json"); n != 1 {
		t.Fatalf("a cached document was fetched %d times", n)
	}
	e.advance(cimdDefaultTTL + time.Minute)
	e.browser().do("GET", base+"auth?"+cq(id, nil).Encode(), nil)
	if n := e.hitCount("/c/app.json"); n != 2 {
		t.Fatalf("an expired cache must refetch once: %d", n)
	}
	// Refetch failure after expiry fails closed even though an old copy exists.
	e.mu.Lock()
	e.serve["/c/app.json"] = func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", 500) }
	e.mu.Unlock()
	e.advance(cimdDefaultTTL + time.Minute)
	if w := e.browser().do("GET", base+"auth?"+cq(id, nil).Encode(), nil); w.Code != 400 {
		t.Fatalf("stale document used after a failed refetch: %d", w.Code)
	}
}

func TestCIMDRefusals(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	var evil sync.Mutex
	evilHits := 0
	evilSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evil.Lock()
		evilHits++
		evil.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":[%q]}`, r.Host, cbC)
	}))
	defer evilSrv.Close()
	set := func(path string, f func(http.ResponseWriter, *http.Request)) {
		e.mu.Lock()
		e.serve[path] = f
		e.mu.Unlock()
	}
	set("/c/redirect.json", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evilSrv.URL+"/x", http.StatusFound) })
	set("/c/other-id.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":"https://elsewhere.example/c.json","redirect_uris":[%q]}`, cbC)
	})
	set("/c/html.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`{}`))
	})
	set("/c/big.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"%s","redirect_uris":[%q]}`, e.srv.URL+r.URL.Path, strings.Repeat("x", cimdMaxBody), cbC)
	})
	set("/c/secret.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_secret":"s","redirect_uris":[%q]}`, e.srv.URL+r.URL.Path, cbC)
	})
	set("/c/404.json", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	for _, path := range []string{"/c/redirect.json", "/c/other-id.json", "/c/html.json", "/c/big.json", "/c/secret.json", "/c/404.json"} {
		w := e.browser().do("GET", base+"auth?"+cq(e.id(path), nil).Encode(), nil)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "Invalid client") {
			t.Errorf("%s: want Invalid client, got %d", path, w.Code)
		}
		if _, err := e.denv.st.GetClientByClientID(context.Background(), "r", e.id(path)); err == nil {
			t.Errorf("%s: a client was created from a refused document", path)
		}
	}
	evil.Lock()
	defer evil.Unlock()
	if evilHits != 0 {
		t.Fatal("a redirect from the metadata server was followed")
	}
}

func TestCIMDRedirectURIExact(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	id := e.id("/c/app.json")
	for _, ru := range []string{"http://localhost:8765/callback/", "http://localhost:8766/callback", "http://localhost:8765/callback?x=1",
		"https://localhost:8765/callback", "http://evil.example/callback", ""} {
		q := cq(id, map[string]string{"redirect_uri": ru})
		if ru == "" {
			q.Del("redirect_uri")
		}
		w := e.browser().do("GET", base+"auth?"+q.Encode(), nil)
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Errorf("redirect_uri %q: %d (must be an error page, never a redirect)", ru, w.Code)
		}
	}
}

func TestCIMDHostAllowlistAndRateLimit(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true, CIMDHosts: []string{"docs.example"}})
	if w := e.browser().do("GET", base+"auth?"+cq(e.id("/c/app.json"), nil).Encode(), nil); w.Code != 400 {
		t.Fatalf("host not on the allowlist: %d", w.Code)
	}
	if e.hitCount("/c/app.json") != 0 {
		t.Fatal("fetched a host that is not allowed")
	}
	// Rate limit: unique documents from one IP are capped per window.
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	okCount := 0
	for i := 0; i < cimdIPLimit+5; i++ {
		w := e.browser().do("GET", base+"auth?"+cq(e.id(fmt.Sprintf("/c/n%d.json", i)), nil).Encode(), nil)
		if w.Code == 200 {
			okCount++
		}
	}
	if okCount != cimdIPLimit {
		t.Fatalf("per-IP fetch limit: %d succeeded, want %d", okCount, cimdIPLimit)
	}
}

func TestCIMDSSRFBlocked(t *testing.T) {
	// Production policy (no AllowPrivate): even a syntactically fine https URL
	// that points at a loopback address is refused at dial time.
	e := newCEnv(t, false, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	u, _ := url.Parse(e.srv.URL)
	for _, id := range []string{"https://" + u.Host + "/c/app.json", "https://127.0.0.1:1/c.json", "https://[::1]:1/c.json",
		"https://169.254.169.254/latest/meta-data", "https://10.0.0.1/c.json", "https://localhost/c.json"} {
		w := e.browser().do("GET", base+"auth?"+cq(id, nil).Encode(), nil)
		if w.Code != 400 {
			t.Errorf("%s: %d", id, w.Code)
		}
	}
	if e.hitCount("/c/app.json") != 0 {
		t.Fatal("the loopback metadata server was reached")
	}
	// http is refused outright.
	if w := e.browser().do("GET", base+"auth?"+cq(e.srv.URL+"/c/app.json", nil).Encode(), nil); w.Code != 400 || e.hitCount("/c/app.json") != 0 {
		t.Fatalf("plain http client_id: %d", w.Code)
	}
}

// ---- consent screen ----

func TestConsentDecisionSecurity(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	e.name = `<script>alert(1)</script>"><img src=x onerror=alert(2)>`
	id := e.id("/c/app.json")
	q := cq(id, nil)
	b := e.browser()
	w := b.authorize(q)
	if !isConsentPage(w) || strings.Contains(w.Body.String(), "<script>alert(1)") || strings.Contains(w.Body.String(), "<img src=x") {
		t.Fatalf("client name not escaped: %s", w.Body)
	}
	post := func(b *browser, form url.Values) *httptest.ResponseRecorder {
		return b.do("POST", base+"auth?"+q.Encode(), form)
	}
	good := func() url.Values {
		c, d := csrfRe.FindStringSubmatch(w.Body.String()), digestRe.FindStringSubmatch(w.Body.String())
		return url.Values{"csrf": {c[1]}, "consent_proof": {d[1]}, "consent_decision": {"allow"}}
	}
	noCode := func(name string, r *httptest.ResponseRecorder, wantStatus int) {
		t.Helper()
		if r.Code != wantStatus || strings.Contains(r.Header().Get("Location"), "code=") {
			t.Errorf("%s: %d %s", name, r.Code, r.Header().Get("Location"))
		}
	}
	// No CSRF token / wrong one / cookie only / token only.
	f := good()
	f.Del("csrf")
	noCode("missing csrf", post(b, f), 403)
	f = good()
	f.Set("csrf", "forged.token")
	noCode("forged csrf", post(b, f), 403)
	// A token with no matching cookie (an attacker's page cannot read the cookie).
	nb := e.browser()
	nb.cookies = map[string]*http.Cookie{}
	noCode("no cookies at all", post(nb, good()), 403)
	// CSRF cookie present but no SSO session: cannot decide for anyone.
	sb := e.browser()
	sb.cookies = map[string]*http.Cookie{}
	for k, c := range b.cookies {
		if c.Name == csrfCookie {
			sb.cookies[k] = c
		}
	}
	noCode("no sso session", post(sb, good()), 403)
	// A digest for something else.
	// Valid session and CSRF pair but no proof: this is what an attacker holding
	// a stolen SSO cookie would send to skip ssoReuse's max_age / step-up checks.
	f = good()
	f.Del("consent_proof")
	noCode("no proof (direct post with an sso cookie)", post(b, f), 403)
	f = good()
	f.Set("consent_proof", strings.Repeat("0", 32))
	noCode("forged proof", post(b, f), 403)
	// A genuine proof, but for another request (a wider scope): the page the
	// user saw is not what is being decided, so it is shown again.
	other := b.authorize(cq(id, map[string]string{"scope": "openid"}))
	oc, op := csrfRe.FindStringSubmatch(other.Body.String()), digestRe.FindStringSubmatch(other.Body.String())
	noCode("proof of another request", post(b, url.Values{"csrf": {oc[1]}, "consent_proof": {op[1]}, "consent_decision": {"allow"}}), 409)
	// A proof issued to another user's session is worthless to this one.
	if err := e.denv.st.CreateUser(context.Background(), core.User{ID: "u2", Realm: "r", Username: "bob", Enabled: true, EmailVerified: true, PasswordHash: "H:pw"}); err != nil {
		t.Fatal(err)
	}
	bobPage := e.browser().authorizeAs(q, "bob")
	bp := digestRe.FindStringSubmatch(bobPage.Body.String())
	w = b.authorize(q)
	f = good()
	f.Set("consent_proof", bp[1])
	noCode("another user's proof", post(b, f), 403)
	// A rejected digest re-renders the page with a fresh CSRF pair: use it.
	w = b.authorize(q)
	// An unknown decision.
	f = good()
	f.Set("consent_decision", "maybe")
	noCode("unknown decision", post(b, f), 400)
	if n := len(e.receipts()); n != 0 {
		t.Fatalf("receipts were written by rejected requests: %d", n)
	}
	if gs, _ := e.denv.st.ListConsentGrants(context.Background(), "r", "", "", true, e.now, 10); len(gs) != 0 {
		t.Fatal("a grant exists after only rejected requests")
	}
	// The real thing still works afterwards.
	codeOf(t, post(b, good()))
}

func TestConsentDeny(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	id := e.id("/c/app.json")
	q := cq(id, nil)
	b := e.browser()
	w := b.consentDecide(b.authorize(q), q, "deny")
	if errOfRedirect(w) != "access_denied" || strings.Contains(w.Header().Get("Location"), "code=") ||
		!strings.HasPrefix(w.Header().Get("Location"), cbC+"?") || !strings.Contains(w.Header().Get("Location"), "state=st8") {
		t.Fatalf("deny: %d %s", w.Code, w.Header().Get("Location"))
	}
	rs := e.receipts()
	if len(rs) != 1 || rs[0].Type != core.ReceiptDeny {
		t.Fatalf("receipts: %+v", rs)
	}
	if gs, _ := e.denv.st.ListConsentGrants(context.Background(), "r", "", "", true, e.now, 10); len(gs) != 0 {
		t.Fatal("deny created a grant")
	}
}

func TestConsentRequiredByKind(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	ctx := context.Background()
	// "app" is an admin-registered client: no consent by default.
	b := e.browser()
	cqApp := authQuery(nil)
	if w := b.authorize(cqApp); w.Code != 302 || errOfRedirect(w) != "" {
		t.Fatalf("admin client must not see consent by default: %d %s", w.Code, w.Body)
	}
	// RequireAll turns it on; SkipClients exempts it.
	e.policy(core.ConsentPolicy{RequireAll: true})
	b = e.browser()
	if w := b.authorize(cqApp); !isConsentPage(w) {
		t.Fatalf("RequireAll: %d %s", w.Code, w.Body)
	}
	e.policy(core.ConsentPolicy{RequireAll: true, SkipClients: []string{"app"}})
	if w := e.browser().authorize(cqApp); w.Code != 302 {
		t.Fatalf("SkipClients: %d", w.Code)
	}
	// A dynamically registered client always needs consent, and SkipClients
	// cannot exempt it (nor a CIMD client).
	dc, _ := core.StoreAs[core.DCRStore](e.denv.st)
	if err := e.denv.st.CreateClient(ctx, core.Client{ID: "dcr1", Realm: "r", ClientID: "hc_dyn", Name: "Dyn", Enabled: true, Public: true,
		AuthCodeFlow: true, RequirePKCE: true, RedirectURIs: []string{cb}}); err != nil {
		t.Fatal(err)
	}
	if err := dc.PutRegisteredClient(ctx, core.RegisteredClient{Realm: "r", ClientID: "hc_dyn", ClientUUID: "dcr1", CreatedVia: "dcr", RegTokenHash: "x"}); err != nil {
		t.Fatal(err)
	}
	e.policy(core.ConsentPolicy{SkipClients: []string{"hc_dyn", e.id("/c/app.json")}, CIMDEnabled: true})
	dq := authQuery(map[string]string{"client_id": "hc_dyn"})
	b = e.browser()
	w := b.authorize(dq)
	if !isConsentPage(w) || !strings.Contains(w.Body.String(), "registered itself automatically") {
		t.Fatalf("DCR client: %d %s", w.Code, w.Body)
	}
	// DCR clients' grants are remembered by default.
	codeOf(t, b.consentDecide(w, dq, "allow"))
	codeOf(t, b.authorize(dq))
	if w := e.browser().authorize(cq(e.id("/c/app.json"), nil)); !isConsentPage(w) {
		t.Fatalf("a CIMD client in SkipClients must still be asked: %d", w.Code)
	}
}

func TestConsentPromptNone(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{RequireAll: true})
	b := e.browser()
	q := authQuery(nil)
	// No session at all: login_required, as before.
	if w := b.do("GET", base+"auth?"+authQuery(map[string]string{"prompt": "none"}).Encode(), nil); errOfRedirect(w) != "login_required" {
		t.Fatalf("no session: %d", w.Code)
	}
	w := b.authorize(q)
	codeOf(t, b.consentDecide(w, q, "allow"))
	// Remembered grant covers it: prompt=none yields a code.
	codeOf(t, b.do("GET", base+"auth?"+authQuery(map[string]string{"prompt": "none"}).Encode(), nil))
	// A wider scope is not covered: consent_required, no code, no page.
	if w := b.do("GET", base+"auth?"+authQuery(map[string]string{"prompt": "none", "scope": "openid email roles"}).Encode(), nil); errOfRedirect(w) != "consent_required" {
		t.Fatalf("prompt=none beyond the grant: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestConsentInvalidResource(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{RequireAll: true})
	b := e.browser()
	for _, res := range []string{"not a uri", "https://x.example/a#frag", "http://public.example/mcp", "javascript:alert(1)", "https://u:p@x.example/"} {
		w := b.authorize(authQuery(map[string]string{"resource": res}))
		if errOfRedirect(w) != "invalid_target" {
			t.Errorf("resource %q: %d %s", res, w.Code, w.Header().Get("Location"))
		}
	}
}

// ---- account page, revocation, kill switch ----

func TestAccountConsentsRevoke(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{RequireAll: true})
	b := e.browser()
	q := authQuery(nil)
	code := codeOf(t, b.consentDecide(b.authorize(q), q, "allow"))
	_, tok, _ := e.post(base+"token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb},
		"client_id": {"app"}, "code_verifier": {verifier}}, "", "", "")
	rt, _ := tok["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token: %v", tok)
	}
	const acct = "/realms/r/account/consents"
	// Needs a session.
	if w := e.browser().do("GET", acct, nil); w.Code != 401 {
		t.Fatalf("anonymous account page: %d", w.Code)
	}
	w := b.do("GET", acct, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "app") || !strings.Contains(w.Body.String(), "openid") || !strings.Contains(w.Body.String(), "Revoke access") {
		t.Fatalf("account page: %d %s", w.Code, w.Body)
	}
	gid := regexp.MustCompile(`name="grant_id" value="([^"]+)"`).FindStringSubmatch(w.Body.String())[1]
	csrf := csrfRe.FindStringSubmatch(w.Body.String())[1]
	// CSRF is enforced.
	if r := b.do("POST", acct, url.Values{"action": {"revoke"}, "grant_id": {gid}}); r.Code != 403 {
		t.Fatalf("revoke without csrf: %d", r.Code)
	}
	if r := b.do("POST", acct, url.Values{"action": {"revoke"}, "grant_id": {gid}, "csrf": {"x.y"}}); r.Code != 403 {
		t.Fatalf("revoke with a bad csrf: %d", r.Code)
	}
	// Another user cannot revoke it: create bob and his session.
	ctx := context.Background()
	if err := e.denv.st.CreateUser(ctx, core.User{ID: "u2", Realm: "r", Username: "bob", Enabled: true, EmailVerified: true, PasswordHash: "H:pw"}); err != nil {
		t.Fatal(err)
	}
	bob := e.browser()
	bu := base + "auth?" + authQuery(nil).Encode()
	lp := bob.do("GET", bu, nil)
	bob.do("POST", bu, url.Values{"username": {"bob"}, "password": {"pw"}, "csrf": {csrfRe.FindStringSubmatch(lp.Body.String())[1]}})
	bw := bob.do("GET", acct, nil)
	if bw.Code != 200 || strings.Contains(bw.Body.String(), "Revoke access") {
		t.Fatalf("bob sees alice's grants: %d %s", bw.Code, bw.Body)
	}
	bcsrf := bob.cookies[csrfCookie+"|"+acct].Value // bob has no grants, so no form: use the cookie value (double submit)
	if r := bob.do("POST", acct, url.Values{"action": {"revoke"}, "grant_id": {gid}, "csrf": {bcsrf}}); r.Code != 404 {
		t.Fatalf("bob revoking alice's grant: %d", r.Code)
	}
	if _, err := e.denv.st.GetActiveConsentGrant(ctx, "r", "u1", "app", e.now); err != nil {
		t.Fatal("alice's grant was revoked by bob")
	}
	// Alice revokes: grant ends, refresh token dies, receipt written.
	if r := b.do("POST", acct, url.Values{"action": {"revoke"}, "grant_id": {gid}, "csrf": {csrf}}); r.Code != 200 || !strings.Contains(r.Body.String(), "Access revoked") {
		t.Fatalf("revoke: %d %s", r.Code, r.Body)
	}
	if c, out, _ := e.post(base+"token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"app"}}, "", "", ""); c == 200 {
		t.Fatalf("refresh token still works after revoke: %v", out)
	}
	if _, err := e.denv.st.GetActiveConsentGrant(ctx, "r", "u1", "app", e.now); err == nil {
		t.Fatal("grant still active")
	}
	rs := e.receipts()
	if last := rs[len(rs)-1]; last.Type != core.ReceiptRevoke || last.UserID != "u1" || last.Actor != "u1" {
		t.Fatalf("revoke receipt: %+v", last)
	}
	if err := core.VerifyConsentChain(rs, 0, ""); err != nil {
		t.Fatal(err)
	}
	// And the next authorization asks again.
	if w := b.authorize(q); !isConsentPage(w) {
		t.Fatalf("after revoke the screen must show again: %d", w.Code)
	}
}

func TestKillSwitchClientBlocksEverything(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true, RememberCIMD: true})
	ctx := context.Background()
	id := e.id("/c/app.json")
	q := cq(id, nil)
	b := e.browser()
	code := codeOf(t, b.consentDecide(b.authorize(q), q, "allow"))
	_, tok := e.exchange(id, code)
	rt, _ := tok["refresh_token"].(string)
	if rt == "" {
		// the dev realm hands refresh tokens for offline_access only; ask for it
		q = cq(id, map[string]string{"scope": "openid offline_access"})
		code = codeOf(t, b.consentDecide(b.authorize(q), q, "allow"))
		_, tok = e.exchange(id, code)
		rt, _ = tok["refresh_token"].(string)
	}
	if rt == "" {
		t.Fatalf("no refresh token: %v", tok)
	}

	res, err := core.KillClient(ctx, e.denv.st, e.denv.st, "r", id, "admin:root", "compromised", e.now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ClientDisabled || res.GrantsRevoked < 1 || res.RefreshRevoked < 1 || res.ReceiptSeq == 0 {
		t.Fatalf("kill result: %+v", res)
	}
	// New authorizations: refused (same page as an unknown client).
	if w := e.browser().do("GET", base+"auth?"+cq(id, nil).Encode(), nil); w.Code != 400 || !strings.Contains(w.Body.String(), "Invalid client") {
		t.Fatalf("authorize after kill: %d", w.Code)
	}
	// Existing refresh token: dead. The client cannot authenticate any more.
	if c, out, _ := e.post(base+"token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {id}}, "", "", ""); c == 200 {
		t.Fatalf("refresh works after kill: %v", out)
	}
	// Even a freshly fetched document cannot bring it back while blocked.
	e.advance(48 * time.Hour)
	if w := e.browser().do("GET", base+"auth?"+cq(id, nil).Encode(), nil); w.Code != 400 {
		t.Fatalf("blocked client re-resolved: %d", w.Code)
	}
	// Idempotent.
	if _, err := core.KillClient(ctx, e.denv.st, e.denv.st, "r", id, "admin:root", "again", e.now); err != nil {
		t.Fatal(err)
	}
	// Unkill: resolvable again, but consent is needed again (grants stayed revoked).
	if err := core.UnkillClient(ctx, e.denv.st, e.denv.st, "r", id, "admin:root", e.now); err != nil {
		t.Fatal(err)
	}
	if w := e.browser().authorize(cq(id, nil)); !isConsentPage(w) {
		t.Fatalf("after unkill: %d %s", w.Code, w.Body)
	}
	if err := core.VerifyConsentChain(e.receipts(), 0, ""); err != nil {
		t.Fatal(err)
	}
}

func TestKillSwitchAgent(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	ctx := context.Background()
	as, _ := core.StoreAs[core.AgentStore](e.denv.st)
	ag, err := as.CreateAgent(ctx, core.Agent{Realm: "r", Name: "bot", Kind: "agent", ClientID: "agent-bot", OwnerUserID: "u1",
		AllowedScopes: []string{"openid"}, TokenTTL: 300, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.denv.st.CreateClient(ctx, core.Client{Realm: "r", ClientID: "agent-bot", Enabled: true, Public: true}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := as.CreateAgentCredential(ctx, core.AgentCredential{Realm: "r", AgentID: ag.ID, SecretHash: fmt.Sprint("h", i),
			ExpiresAt: e.now.Add(time.Hour)}, 5, e.now); err != nil {
			t.Fatal(err)
		}
	}
	res, err := core.KillClient(ctx, e.denv.st, e.denv.st, "r", ag.ClientID, "admin:root", "rogue agent", e.now)
	if err != nil || !res.AgentDisabled || res.CredentialsEnd != 2 || !res.ClientDisabled {
		t.Fatalf("agent kill: %+v %v", res, err)
	}
	got, _ := as.GetAgent(ctx, "r", ag.ID)
	if got.Enabled {
		t.Fatal("agent still enabled")
	}
	creds, _ := as.ListAgentCredentials(ctx, "r", ag.ID)
	for _, c := range creds {
		if c.Active(e.now) {
			t.Fatal("agent credential still active")
		}
	}
}

func TestReceiptChainDetectsTampering(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{RequireAll: true})
	for i := 0; i < 3; i++ {
		b := e.browser()
		q := authQuery(map[string]string{"prompt": "consent"})
		codeOf(t, b.consentDecide(b.authorize(q), q, "allow"))
	}
	rs := e.receipts()
	if len(rs) != 3 {
		t.Fatalf("receipts: %d", len(rs))
	}
	if err := core.VerifyConsentChain(rs, 0, ""); err != nil {
		t.Fatal(err)
	}
	e.denv.st.TamperConsentReceipt("r", 2, func(r *core.ConsentReceipt) { r.Scopes = []string{"openid", "roles"} })
	if err := core.VerifyConsentChain(e.receipts(), 0, ""); err == nil || !strings.Contains(err.Error(), "seq 2") {
		t.Fatalf("an edited receipt was not detected: %v", err)
	}
}

// ---- feature off / discovery ----

// noConsentStore hides the ConsentStore (and Unwrap), like a store that does
// not implement it.
type noConsentStore struct{ core.Store }

func TestFeatureOffFailsClosed(t *testing.T) {
	e := newCEnv(t, true, devOpts{store: func(s core.Store) core.Store { return noConsentStore{s} }})
	if w := e.browser().do("GET", base+"auth?"+cq(e.id("/c/app.json"), nil).Encode(), nil); w.Code != 400 || e.hitCount("/c/app.json") != 0 {
		t.Fatalf("CIMD without a ConsentStore: %d, fetched %d", w.Code, e.hitCount("/c/app.json"))
	}
	if w := e.browser().do("GET", "/realms/r/account/consents", nil); w.Code != 404 {
		t.Fatalf("account page without a ConsentStore: %d", w.Code)
	}
	// Ordinary logins are unaffected.
	if w := e.browser().authorize(authQuery(nil)); w.Code != 302 {
		t.Fatalf("plain login: %d", w.Code)
	}
}

func TestDiscoveryAdvertisesCIMDOnlyWhenEnabled(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	get := func() string {
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, httptest.NewRequest("GET", "/realms/r/.well-known/openid-configuration", nil))
		return w.Body.String()
	}
	if d := get(); strings.Contains(d, "client_id_metadata_document_supported") || !strings.Contains(d, `"consent"`) {
		t.Fatalf("default discovery: %s", d)
	}
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	if !strings.Contains(get(), `"client_id_metadata_document_supported":true`) {
		t.Fatal("discovery does not advertise CIMD")
	}
}

// A kill-switch block is enforced by itself, not only through the disabled
// client row: it covers a document nobody has fetched yet and survives the
// client row being deleted.
func TestKillSwitchBlocksUnseenAndDeletedCIMDClient(t *testing.T) {
	e := newCEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{CIMDEnabled: true})
	ctx := context.Background()
	unseen := e.id("/c/unseen.json")
	if _, err := core.KillClient(ctx, e.denv.st, e.denv.st, "r", unseen, "admin:root", "pre-emptive", e.now); err != nil {
		t.Fatal(err)
	}
	if w := e.browser().do("GET", base+"auth?"+cq(unseen, nil).Encode(), nil); w.Code != 400 || e.hitCount("/c/unseen.json") != 0 {
		t.Fatalf("a blocked, never-seen client: %d, fetched %d times", w.Code, e.hitCount("/c/unseen.json"))
	}
	// Seen client, killed, then its row deleted (an admin cleanup): the block still holds.
	id := e.id("/c/app.json")
	e.browser().do("GET", base+"auth?"+cq(id, nil).Encode(), nil)
	if _, err := core.KillClient(ctx, e.denv.st, e.denv.st, "r", id, "admin:root", "x", e.now); err != nil {
		t.Fatal(err)
	}
	cl, _ := e.denv.st.GetClientByClientID(ctx, "r", id)
	if err := e.denv.st.DeleteClient(ctx, "r", cl.ID); err != nil {
		t.Fatal(err)
	}
	hits := e.hitCount("/c/app.json")
	if w := e.browser().do("GET", base+"auth?"+cq(id, nil).Encode(), nil); w.Code != 400 || e.hitCount("/c/app.json") != hits {
		t.Fatalf("a blocked client came back after its row was deleted: %d", w.Code)
	}
}
