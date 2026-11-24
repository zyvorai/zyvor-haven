// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package backchannel

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type env struct {
	t    *testing.T
	st   *memstore.Store
	sg   core.Signer
	logs *syncBuf
	now  time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, st: memstore.New(), logs: &syncBuf{}, now: time.Now().UTC().Truncate(time.Second)}
	ctx := context.Background()
	if err := e.st.CreateRealm(ctx, core.Realm{Name: "r", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	e.sg = keys.New(e.st, keys.Options{Clock: func() time.Time { return e.now }})
	if err := e.sg.EnsureKey(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) client(id, uri string, enabled bool) {
	e.t.Helper()
	if err := e.st.CreateClient(context.Background(), core.Client{Realm: "r", ClientID: id, Enabled: enabled, BackchannelLogoutURI: uri}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) notifier(srv *httptest.Server, mut func(*Config)) *Notifier {
	cfg := Config{Store: e.st, Signer: e.sg, BaseURL: "https://idp.example/", Clock: func() time.Time { return e.now },
		Logger:  slog.New(slog.NewTextHandler(e.logs, nil)),
		Timeout: 2 * time.Second, Backoff: time.Millisecond, Retries: 2}
	if srv != nil {
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		cfg.RootCAs = pool
		cfg.AllowPrivate = true
	}
	if mut != nil {
		mut(&cfg)
	}
	return New(cfg)
}

var sess = core.Session{ID: "sid-1", UserID: "user-1", Realm: "r", Clients: []string{"app"}}

type hit struct {
	ct, cc, body string
}

func recorder(status func(n int) int) (*httptest.Server, *[]hit, *atomic.Int32) {
	var mu sync.Mutex
	var hits []hit
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		hits = append(hits, hit{r.Header.Get("Content-Type"), r.Header.Get("Cache-Control"), r.PostForm.Get("logout_token")})
		mu.Unlock()
		w.WriteHeader(status(int(n.Add(1))))
	}))
	return srv, &hits, &n
}

func TestDeliversLogoutToken(t *testing.T) {
	e := newEnv(t)
	srv, hits, _ := recorder(func(int) int { return 204 })
	defer srv.Close()
	e.client("app", srv.URL+"/bcl", true)
	n := e.notifier(srv, nil)
	n.Notify(context.Background(), "r", sess)
	n.Drain()
	if len(*hits) != 1 {
		t.Fatalf("hits=%d", len(*hits))
	}
	h := (*hits)[0]
	if h.ct != "application/x-www-form-urlencoded" || h.cc != "no-store" {
		t.Fatalf("headers %+v", h)
	}
	c, err := e.sg.Verify(context.Background(), "r", h.body)
	if err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	if c["iss"] != "https://idp.example/realms/r" || c["aud"] != "app" || c["sub"] != "user-1" || c["sid"] != "sid-1" {
		t.Fatalf("claims %v", c)
	}
	if _, has := c["nonce"]; has {
		t.Fatal("nonce must not be present")
	}
	ev, _ := c["events"].(map[string]any)
	if _, ok := ev["http://schemas.openid.net/event/backchannel-logout"].(map[string]any); !ok {
		t.Fatalf("events %v", c["events"])
	}
	iat, _ := c["iat"].(json.Number).Int64()
	exp, _ := c["exp"].(json.Number).Int64()
	if iat != e.now.Unix() || exp-iat != 120 {
		t.Fatalf("iat/exp %d/%d", iat, exp)
	}
	if c["jti"] == nil || c["jti"] == "" {
		t.Fatal("no jti")
	}
	if strings.Contains(e.logs.String(), h.body) {
		t.Fatal("logout token leaked into logs")
	}
	if !strings.Contains(e.logs.String(), "delivered") {
		t.Fatalf("expected an info log: %s", e.logs.String())
	}
}

func TestSkipsClientsWithoutURIDisabledMissing(t *testing.T) {
	e := newEnv(t)
	srv, hits, _ := recorder(func(int) int { return 200 })
	defer srv.Close()
	e.client("nouri", "", true)
	e.client("off", srv.URL, false)
	e.client("on", srv.URL, true)
	n := e.notifier(srv, nil)
	s := sess
	s.Clients = []string{"nouri", "off", "gone", "on", "on"}
	n.Notify(context.Background(), "r", s)
	n.Drain()
	if len(*hits) != 1 {
		t.Fatalf("hits=%d, want 1", len(*hits))
	}
}

func TestRetries(t *testing.T) {
	e := newEnv(t)
	srv, hits, _ := recorder(func(n int) int {
		if n < 3 {
			return 500
		}
		return 200
	})
	defer srv.Close()
	e.client("app", srv.URL, true)
	n := e.notifier(srv, nil)
	n.Notify(context.Background(), "r", sess)
	n.Drain()
	if len(*hits) != 3 {
		t.Fatalf("hits=%d, want 3", len(*hits))
	}
}

func TestNoRetryOn400AndGivesUpAfterRetries(t *testing.T) {
	e := newEnv(t)
	srv, hits, _ := recorder(func(int) int { return 400 })
	defer srv.Close()
	e.client("app", srv.URL, true)
	n := e.notifier(srv, nil)
	n.Notify(context.Background(), "r", sess)
	n.Drain()
	if len(*hits) != 1 {
		t.Fatalf("400 retried: hits=%d", len(*hits))
	}
	srv2, hits2, _ := recorder(func(int) int { return 503 })
	defer srv2.Close()
	e2 := newEnv(t)
	e2.client("app", srv2.URL, true)
	n2 := e2.notifier(srv2, nil)
	n2.Notify(context.Background(), "r", sess)
	n2.Drain()
	if len(*hits2) != 3 {
		t.Fatalf("503 hits=%d, want 3", len(*hits2))
	}
	if !strings.Contains(e2.logs.String(), "level=WARN") {
		t.Fatalf("no warn log: %s", e2.logs.String())
	}
}

func TestRedirectsNotFollowed(t *testing.T) {
	e := newEnv(t)
	other, otherHits, _ := recorder(func(int) int { return 200 })
	defer other.Close()
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/internal", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	e.client("app", redir.URL, true)
	// trust both test servers
	pool := x509.NewCertPool()
	pool.AddCert(redir.Certificate())
	pool.AddCert(other.Certificate())
	n := e.notifier(nil, func(c *Config) { c.RootCAs = pool; c.AllowPrivate = true })
	n.Notify(context.Background(), "r", sess)
	n.Drain()
	if len(*otherHits) != 0 {
		t.Fatalf("redirect followed: %d", len(*otherHits))
	}
}

func TestPrivateTargetsRefused(t *testing.T) {
	e := newEnv(t)
	srv, hits, _ := recorder(func(int) int { return 200 })
	defer srv.Close()
	e.client("app", srv.URL, true) // 127.0.0.1
	e.client("meta", "https://169.254.169.254/latest/meta-data", true)
	e.client("rfc1918", "https://10.0.0.5/x", true)
	e.client("ula", "https://[fd00::1]/x", true)
	e.client("cgnat", "https://100.64.0.1/x", true)
	e.client("v4mapped", "https://[::ffff:127.0.0.1]/x", true)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	n := e.notifier(nil, func(c *Config) { c.RootCAs = pool })
	s := sess
	s.Clients = []string{"app", "meta", "rfc1918", "ula", "cgnat", "v4mapped"}
	n.Notify(context.Background(), "r", s)
	n.Drain()
	if len(*hits) != 0 {
		t.Fatalf("SSRF: server received %d request(s)", len(*hits))
	}
	if got := strings.Count(e.logs.String(), "blocked_address"); got != 6 {
		t.Fatalf("blocked_address logged %d times, want 6:\n%s", got, e.logs.String())
	}
	if strings.Contains(e.logs.String(), "attempt=2") {
		t.Fatal("blocked destination was retried")
	}
}

func TestBlockedIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "fe80::1",
		"fd12::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "100.64.0.1", "100.127.255.255", "::ffff:10.0.0.1", "64:ff9b::a00:1"} {
		if !blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"93.184.216.34", "8.8.8.8", "2606:4700::1111", "100.128.0.1"} {
		if blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestValidateURI(t *testing.T) {
	ok := []string{"https://app.example/bcl", "https://app.example:8443/a?b=c"}
	for _, u := range ok {
		if err := ValidateURI(u, false); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	bad := []string{"", "http://app.example/x", "ftp://a/b", "https://u:p@app.example/", "https://user@app.example/",
		"https:///x", "https://app.example/x#f", "https://app.example/a b", "http://localhost/x", "/relative",
		"https://" + strings.Repeat("a", 2100) + ".example/"}
	for _, u := range bad {
		if ValidateURI(u, false) == nil {
			t.Errorf("%q should be rejected", u)
		}
	}
	for _, u := range []string{"http://localhost:3000/bcl", "http://127.0.0.1:8080/x", "https://localhost/x"} {
		if err := ValidateURI(u, true); err != nil {
			t.Errorf("dev %s: %v", u, err)
		}
	}
	if ValidateURI("http://app.example/x", true) == nil {
		t.Error("http to non-loopback must be rejected even in dev")
	}
	if _, err := url.Parse("https://x"); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyDoesNotBlockAndDrainWaits(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	var started atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	e.client("app", srv.URL, true)
	n := e.notifier(srv, func(c *Config) { c.Retries = -1; c.Timeout = 400 * time.Millisecond })
	t0 := time.Now()
	n.Notify(context.Background(), "r", sess)
	if d := time.Since(t0); d > 100*time.Millisecond {
		t.Fatalf("Notify took %v", d)
	}
	done := make(chan struct{})
	go func() { n.Drain(); close(done) }()
	select {
	case <-done:
		// the 400ms attempt timeout must have elapsed
		if time.Since(t0) < 300*time.Millisecond {
			t.Fatal("Drain returned before delivery finished")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Drain never returned")
	}
	if started.Load() != 1 {
		t.Fatalf("started=%d", started.Load())
	}
}

func TestNotifyIgnoresCallerContext(t *testing.T) {
	e := newEnv(t)
	srv, hits, _ := recorder(func(int) int { return 200 })
	defer srv.Close()
	e.client("app", srv.URL, true)
	n := e.notifier(srv, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the request is gone; delivery must still happen
	n.Notify(ctx, "r", sess)
	n.Drain()
	if len(*hits) != 1 {
		t.Fatalf("hits=%d", len(*hits))
	}
}
