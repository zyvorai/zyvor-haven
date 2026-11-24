// Package devui serves a self-hosted OIDC playground and debugger for
// haven-idp. It is for DEV MODE ONLY and must never be exposed publicly.
package devui

import (
	"embed"
	"encoding/json"
	"net/http"
	"strings"
)

//go:embed index.html app.js lib.js snippets.js wizard.js style.css
var assets embed.FS

// Config injects deployment values into the page via /dev/config.json.
type Config struct {
	Issuer   string
	ClientID string
	// AdminSecret returns the secret of the haven-admin client. It is called
	// per request and its value never leaves the server. nil disables the
	// add-an-app backend (POST /dev/api/clients answers 503).
	AdminSecret func() (string, error)
}

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
	"img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

var files = map[string]struct{ name, ctype string }{
	"/":            {"index.html", "text/html; charset=utf-8"},
	"/index.html":  {"index.html", "text/html; charset=utf-8"},
	"/app.js":      {"app.js", "text/javascript; charset=utf-8"},
	"/lib.js":      {"lib.js", "text/javascript; charset=utf-8"},
	"/snippets.js": {"snippets.js", "text/javascript; charset=utf-8"},
	"/wizard.js":   {"wizard.js", "text/javascript; charset=utf-8"},
	"/style.css":   {"style.css", "text/css; charset=utf-8"},
}

// New returns a handler meant to be mounted at /dev/. It accepts paths with
// or without the "/dev" prefix.
func New(cfg Config) http.Handler {
	cfgJSON, _ := json.Marshal(map[string]string{"issuer": cfg.Issuer, "client_id": cfg.ClientID})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		if strings.TrimPrefix(r.URL.Path, "/dev") == "/api/clients" {
			if r.Method != http.MethodPost {
				h.Set("Allow", "POST")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			cfg.createClient(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/dev")
		if p == "" {
			p = "/"
		}
		if p == "/config.json" {
			h.Set("Content-Type", "application/json")
			_, _ = w.Write(cfgJSON)
			return
		}
		f, ok := files[p]
		if !ok {
			http.NotFound(w, r)
			return
		}
		b, err := assets.ReadFile(f.name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		h.Set("Content-Type", f.ctype)
		_, _ = w.Write(b)
	})
}
