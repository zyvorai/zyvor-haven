package devui

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const (
	testAdminSecret  = "ADMIN-SECRET-do-not-leak-0123456789"
	testClientSecret = "GENERATED-CLIENT-SECRET-abcdef"
	testHost         = "127.0.0.1:8081"
)

// fakeIdP is the slice of haven-idp the wizard backend talks to.
type fakeIdP struct {
	*httptest.Server
	mu       sync.Mutex
	adminReq []map[string]any // bodies POSTed to the clients endpoint
	tokenReq int
	status   int // forced status for the clients endpoint (0 = normal)
	reply    string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/demo/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.tokenReq++
		f.mu.Unlock()
		u, p, ok := r.BasicAuth()
		_ = r.ParseForm()
		if !ok || u != "haven-admin" || p != testAdminSecret || r.PostForm.Get("grant_type") != "client_credentials" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ADMIN-TOKEN","token_type":"Bearer"}`))
	})
	mux.HandleFunc("/admin/v1/realms/demo/clients", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ADMIN-TOKEN" {
			http.Error(w, `{"error":"invalid or missing token"}`, http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.adminReq = append(f.adminReq, body)
		st, reply := f.status, f.reply
		f.mu.Unlock()
		if st != 0 {
			w.WriteHeader(st)
			_, _ = w.Write([]byte(reply))
			return
		}
		w.WriteHeader(http.StatusCreated)
		if body["publicClient"] == false {
			_, _ = w.Write([]byte(`{"id":"id-1","secret":"` + testClientSecret + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"id-1"}`))
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIdP) handler(secret func() (string, error)) http.Handler {
	return New(Config{Issuer: f.URL + "/realms/demo", ClientID: "pg", AdminSecret: secret})
}

func okSecret() (string, error) { return testAdminSecret, nil }

func post(h http.Handler, body string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/dev/api/clients", strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Haven-Dev", "1")
	r.Header.Set("Origin", "http://"+testHost)
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const goodWeb = `{"type":"web","name":"Billing","redirectUris":["https://billing.example.com/cb"],"playgroundCallback":true}`

func TestCreateEachType(t *testing.T) {
	cases := []struct {
		name, body string
		public     bool
		secret     bool
		wantURIs   []string
		sa         bool
	}{
		{"spa", `{"type":"spa","name":"My SPA","redirectUris":["http://localhost:5173/cb"],"playgroundCallback":true}`, true, false,
			[]string{"http://localhost:5173/cb", "http://" + testHost + "/dev/"}, false},
		{"web", goodWeb, false, true, []string{"https://billing.example.com/cb", "http://" + testHost + "/dev/"}, false},
		{"native", `{"type":"native","name":"cli","redirectUris":["http://127.0.0.1:8000"]}`, true, false, []string{"http://127.0.0.1:8000"}, false},
		{"m2m", `{"type":"m2m","name":"nightly job"}`, false, true, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeIdP(t)
			w := post(f.handler(okSecret), c.body, nil)
			if w.Code != 201 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Error("response must be no-store")
			}
			var got createResp
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Public != c.public || (got.Secret != "") != c.secret || (c.secret && got.Secret != testClientSecret) {
				t.Errorf("public=%v secret=%q", got.Public, got.Secret)
			}
			if !regexp.MustCompile(`^[a-z0-9-]+-[0-9a-f]{6}$`).MatchString(got.ClientID) {
				t.Errorf("client id %q", got.ClientID)
			}
			if strings.Contains(w.Body.String(), testAdminSecret) || strings.Contains(w.Body.String(), "ADMIN-TOKEN") {
				t.Error("admin credential in response")
			}
			if len(f.adminReq) != 1 {
				t.Fatalf("admin calls: %d", len(f.adminReq))
			}
			up := f.adminReq[0]
			if up["publicClient"] != c.public || up["serviceAccountsEnabled"] != c.sa || up["standardFlowEnabled"] != !c.sa {
				t.Errorf("upstream body %v", up)
			}
			if attrs, _ := up["attributes"].(map[string]any); attrs["pkce.code.challenge.method"] != "S256" {
				t.Error("PKCE S256 must be required")
			}
			if len(c.wantURIs) > 0 {
				uris, _ := json.Marshal(up["redirectUris"])
				want, _ := json.Marshal(c.wantURIs)
				if string(uris) != string(want) {
					t.Errorf("redirectUris %s want %s", uris, want)
				}
			} else if _, ok := up["redirectUris"]; ok {
				t.Error("m2m must not register redirect URIs")
			}
		})
	}
}

func TestCreateValidation(t *testing.T) {
	f := newFakeIdP(t)
	h := f.handler(okSecret)
	var vec struct{ OK, Bad []string }
	b, err := os.ReadFile("testdata/redirects.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vec); err != nil {
		t.Fatal(err)
	}
	mk := func(typ, name string, uris ...string) string {
		j, _ := json.Marshal(map[string]any{"type": typ, "name": name, "redirectUris": uris})
		return string(j)
	}
	for _, u := range vec.Bad {
		if w := post(h, mk("web", "x", u), nil); w.Code != 400 {
			t.Errorf("redirect %q: %d, want 400", u, w.Code)
		}
	}
	for _, u := range vec.OK {
		if err := ValidateRedirect(u); err != nil {
			t.Errorf("ValidateRedirect(%q): %v", u, err)
		}
	}
	for _, u := range vec.Bad {
		if ValidateRedirect(u) == nil {
			t.Errorf("ValidateRedirect(%q) accepted", u)
		}
	}
	bad := map[string]string{
		"unknown type":         mk("mobile", "x", "https://a/cb"),
		"empty name":           mk("web", "  ", "https://a/cb"),
		"newline in name":      mk("web", "a\nb", "https://a/cb"),
		"long name":            mk("web", strings.Repeat("n", 101), "https://a/cb"),
		"no redirects":         mk("web", "x"),
		"duplicate":            mk("web", "x", "https://a/cb", "https://a/cb"),
		"too many":             mk("web", "x", "https://a/1", "https://a/2", "https://a/3", "https://a/4", "https://a/5", "https://a/6", "https://a/7", "https://a/8", "https://a/9", "https://a/10", "https://a/11"),
		"native with https":    mk("native", "x", "https://a/cb"),
		"m2m with redirect":    mk("m2m", "x", "https://a/cb"),
		"unknown field":        `{"type":"web","name":"x","redirectUris":["https://a/cb"],"secret":"mine"}`,
		"clientId not allowed": `{"type":"web","name":"x","redirectUris":["https://a/cb"],"clientId":"admin"}`,
		"trailing json":        goodWeb + `{"x":1}`,
		"not json":             `type=web`,
		"empty body":           ``,
	}
	for n, body := range bad {
		if w := post(h, body, nil); w.Code != 400 {
			t.Errorf("%s: %d %s, want 400", n, w.Code, w.Body)
		}
	}
	if f.tokenReq != 0 || len(f.adminReq) != 0 {
		t.Errorf("invalid input reached the IdP: %d token, %d admin calls", f.tokenReq, len(f.adminReq))
	}
}

func TestCreateCSRFAndOrigin(t *testing.T) {
	f := newFakeIdP(t)
	h := f.handler(okSecret)
	cases := map[string]struct {
		mod  func(*http.Request)
		want int
	}{
		"no custom header":    {func(r *http.Request) { r.Header.Del("X-Haven-Dev") }, 403},
		"wrong header value":  {func(r *http.Request) { r.Header.Set("X-Haven-Dev", "0") }, 403},
		"no origin":           {func(r *http.Request) { r.Header.Del("Origin") }, 403},
		"foreign origin":      {func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
		"other loopback port": {func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:9999") }, 403},
		"null origin":         {func(r *http.Request) { r.Header.Set("Origin", "null") }, 403},
		"cross-site fetch":    {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		"same-site fetch":     {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, 403},
		"form content type":   {func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, 415},
		"text/plain":          {func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		"dns rebinding host": {func(r *http.Request) {
			r.Host = "attacker.example:8081"
			r.Header.Set("Origin", "http://attacker.example:8081")
		}, 403},
		"public ip host": {func(r *http.Request) {
			r.Host = "192.168.1.5:8081"
			r.Header.Set("Origin", "http://192.168.1.5:8081")
		}, 403},
	}
	for n, c := range cases {
		if w := post(h, goodWeb, c.mod); w.Code != c.want {
			t.Errorf("%s: %d %s, want %d", n, w.Code, w.Body, c.want)
		}
	}
	if f.tokenReq != 0 || len(f.adminReq) != 0 {
		t.Errorf("rejected requests reached the IdP (%d token, %d admin)", f.tokenReq, len(f.adminReq))
	}
	// Positive controls: each accepted variant of the same request.
	for n, mod := range map[string]func(*http.Request){
		"same-origin fetch": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") },
		"charset param":     func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") },
		"localhost host": func(r *http.Request) {
			r.Host = "localhost:8081"
			r.Header.Set("Origin", "http://localhost:8081")
		},
		"ipv6 host": func(r *http.Request) {
			r.Host = "[::1]:8081"
			r.Header.Set("Origin", "http://[::1]:8081")
		},
	} {
		if w := post(h, goodWeb, mod); w.Code != 201 {
			t.Errorf("%s: %d %s, want 201", n, w.Code, w.Body)
		}
	}
}

func TestCreateMethodsAndBodyLimit(t *testing.T) {
	f := newFakeIdP(t)
	h := f.handler(okSecret)
	for _, m := range []string{"GET", "PUT", "DELETE", "PATCH"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(m, "/dev/api/clients", nil))
		if w.Code != 405 || w.Header().Get("Allow") != "POST" {
			t.Errorf("%s: %d allow=%q", m, w.Code, w.Header().Get("Allow"))
		}
	}
	big := `{"type":"web","name":"` + strings.Repeat("a", maxBody) + `","redirectUris":["https://a/cb"]}`
	if w := post(h, big, nil); w.Code != 413 {
		t.Errorf("oversize body: %d, want 413", w.Code)
	}
	// Just under the limit but invalid for another reason must not be 413.
	if w := post(h, `{"type":"web","name":"`+strings.Repeat("a", 5000)+`","redirectUris":["https://a/cb"]}`, nil); w.Code != 400 {
		t.Errorf("5000-char name: %d, want 400", w.Code)
	}
	if len(f.adminReq) != 0 {
		t.Error("oversize or invalid body reached the IdP")
	}
	if w := get(t, h, "/dev/api/other"); w.Code != 404 {
		t.Errorf("unknown api path: %d", w.Code)
	}
}

// The generated secret appears exactly once, in the 201 to the creating
// request. It must not reach logs, config.json, the page, errors or any later response.
func TestSecretNeverLoggedOrReserved(t *testing.T) {
	var logs bytes.Buffer
	oldSlog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	oldFlags, oldOut := log.Flags(), log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { slog.SetDefault(oldSlog); log.SetOutput(oldOut); log.SetFlags(oldFlags) })

	f := newFakeIdP(t)
	h := f.handler(okSecret)
	w := post(h, goodWeb, nil)
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if n := strings.Count(w.Body.String(), testClientSecret); n != 1 {
		t.Fatalf("secret appears %d times in the creating response, want 1", n)
	}
	var later []string
	for _, p := range []string{"/dev/", "/dev/config.json", "/dev/app.js", "/dev/lib.js", "/dev/wizard.js", "/dev/snippets.js", "/dev/api/clients", "/dev/nope"} {
		later = append(later, get(t, h, p).Body.String())
	}
	later = append(later,
		post(h, goodWeb, func(r *http.Request) { r.Header.Del("X-Haven-Dev") }).Body.String(),
		post(h, `{bad`, nil).Body.String(),
		post(h, `{"type":"web","name":"x","redirectUris":["http://evil/cb"]}`, nil).Body.String())
	f.mu.Lock()
	f.status, f.reply = 500, `upstream says `+testClientSecret
	f.mu.Unlock()
	later = append(later, post(h, goodWeb, nil).Body.String())
	for i, body := range later {
		if strings.Contains(body, testClientSecret) {
			t.Errorf("later response %d re-serves the client secret", i)
		}
	}
	for i, body := range append(later, w.Body.String()) {
		if strings.Contains(body, testAdminSecret) || strings.Contains(body, "ADMIN-TOKEN") {
			t.Errorf("response %d leaks the admin credential", i)
		}
	}
	if s := logs.String(); strings.Contains(s, testClientSecret) || strings.Contains(s, testAdminSecret) || strings.Contains(s, "ADMIN-TOKEN") {
		t.Errorf("a secret reached the logs: %s", s)
	}
}

func TestUpstreamFailuresAreGeneric(t *testing.T) {
	f := newFakeIdP(t)
	h := f.handler(okSecret)
	cases := []struct {
		status int
		reply  string
		want   int
	}{
		{409, `{"error":"conflict"}`, 409},
		{500, `stack trace with token ADMIN-TOKEN`, 502},
		{401, `{"error":"invalid or missing token"}`, 502},
		{200, `not 201`, 502},
	}
	for _, c := range cases {
		f.mu.Lock()
		f.status, f.reply = c.status, c.reply
		f.mu.Unlock()
		w := post(h, goodWeb, nil)
		if w.Code != c.want {
			t.Errorf("upstream %d: got %d %s", c.status, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "ADMIN-TOKEN") || strings.Contains(w.Body.String(), "stack trace") {
			t.Errorf("upstream body leaked: %s", w.Body)
		}
	}
	// The admin secret is wrong: a generic error, not the IdP's reply.
	w := post(f.handler(func() (string, error) { return "wrong", nil }), goodWeb, nil)
	if w.Code != 502 || strings.Contains(w.Body.String(), "wrong") {
		t.Errorf("bad admin secret: %d %s", w.Code, w.Body)
	}
	w = post(f.handler(func() (string, error) { return "", errors.New("read /home/u/.config/haven-idp/dev.json: boom") }), goodWeb, nil)
	if w.Code != 502 || strings.Contains(w.Body.String(), "dev.json") {
		t.Errorf("secret source error: %d %s", w.Code, w.Body)
	}
	w = post(New(Config{Issuer: f.URL + "/realms/demo"}), goodWeb, nil)
	if w.Code != 503 {
		t.Errorf("no AdminSecret: %d", w.Code)
	}
}

// The admin credential may only ever be sent to a loopback issuer.
func TestAdminCredentialOnlyToLoopback(t *testing.T) {
	var asked bool
	secret := func() (string, error) { asked = true; return testAdminSecret, nil }
	for _, iss := range []string{"https://idp.example.com/realms/demo", "http://10.0.0.5:8081/realms/demo", "http://127.0.0.1:1/other", "http://127.0.0.1:1/realms/a/b", "ftp://127.0.0.1/realms/demo", ""} {
		w := post(New(Config{Issuer: iss, AdminSecret: secret}), goodWeb, nil)
		if w.Code != 500 {
			t.Errorf("issuer %q: %d, want 500", iss, w.Code)
		}
	}
	if asked {
		t.Error("the admin secret was read for a non-loopback issuer")
	}
}

func TestWizardAssets(t *testing.T) {
	h := New(Config{})
	html := get(t, h, "/dev/").Body.String()
	for _, m := range regexp.MustCompile(`<script src="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		if w := get(t, h, "/dev/"+m[1]); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
			t.Errorf("%s: %d %s", m[1], w.Code, w.Header().Get("Content-Type"))
		}
	}
	for _, p := range []string{"/dev/wizard.js", "/dev/snippets.js"} {
		js := get(t, h, p).Body.String()
		if regexp.MustCompile(`\binnerHTML\b|\beval\(|new Function|document\.write|XMLHttpRequest|importScripts`).MatchString(js) {
			t.Errorf("%s uses an unsafe or non-same-origin API", p)
		}
	}
	w := get(t, h, "/dev/wizard.js").Body.String()
	if regexp.MustCompile(`https?://`).MatchString(w) {
		t.Error("wizard.js contains an absolute URL")
	}
	for _, m := range regexp.MustCompile(`fetch\(([^,)]+)`).FindAllStringSubmatch(get(t, h, "/dev/wizard.js").Body.String()+get(t, h, "/dev/app.js").Body.String(), -1) {
		if strings.Contains(m[1], "http") {
			t.Errorf("fetch to an absolute URL: %s", m[0])
		}
	}
}

var _ = io.Discard
