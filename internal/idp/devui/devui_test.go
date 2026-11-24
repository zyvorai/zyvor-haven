package devui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

func TestHeadersAndAssets(t *testing.T) {
	h := New(Config{Issuer: "http://x/realms/r", ClientID: "pg"})
	want := map[string]string{
		"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "no-store",
	}
	for _, p := range []string{"/dev/", "/dev/index.html", "/dev/app.js", "/dev/lib.js", "/dev/style.css", "/dev/config.json"} {
		w := get(t, h, p)
		if w.Code != 200 {
			t.Fatalf("%s: %d", p, w.Code)
		}
		for k, v := range want {
			if g := w.Header().Get(k); g != v {
				t.Errorf("%s %s = %q, want %q", p, k, g, v)
			}
		}
	}
}

func TestConfigJSON(t *testing.T) {
	w := get(t, New(Config{Issuer: "http://x/realms/r", ClientID: "pg"}), "/dev/config.json")
	var m map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["issuer"] != "http://x/realms/r" || m["client_id"] != "pg" || len(m) != 2 {
		t.Fatalf("got %v", m)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatal(ct)
	}
}

func TestUnknown404(t *testing.T) {
	h := New(Config{})
	for _, p := range []string{"/dev/nope", "/dev/devui.go", "/dev/app.js/x", "/dev/lib.test.js"} {
		if w := get(t, h, p); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/dev/", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}

func TestNoInlineNoExternal(t *testing.T) {
	h := New(Config{})
	html := get(t, h, "/dev/").Body.String()
	for _, m := range regexp.MustCompile(`(?is)<script\b([^>]*)>`).FindAllStringSubmatch(html, -1) {
		if !strings.Contains(m[1], "src=") {
			t.Errorf("inline script tag: %s", m[0])
		}
	}
	if regexp.MustCompile(`(?i)<style\b|\sstyle\s*=|\son[a-z]+\s*=`).MatchString(html) {
		t.Error("inline style or event handler in index.html")
	}
	ext := regexp.MustCompile(`https?://`)
	for _, p := range []string{"/dev/", "/dev/app.js", "/dev/lib.js", "/dev/style.css"} {
		if ext.MatchString(get(t, h, p).Body.String()) {
			t.Errorf("%s contains an http(s):// URL", p)
		}
	}
}

func TestJS(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	cmd := exec.Command(node, "--test", "lib.test.js", "snippets.test.js", "wizard.test.js")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("node tests failed: %v", err)
	}
}
