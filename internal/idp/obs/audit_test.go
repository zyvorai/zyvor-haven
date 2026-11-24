// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) lines() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return splitLines(s.b.Bytes())
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	for _, l := range bytes.Split(b, []byte("\n")) {
		if len(l) > 0 {
			out = append(out, append([]byte(nil), l...))
		}
	}
	return out
}

func ev(i int) AuditEvent {
	return AuditEvent{Type: "LOGIN", Severity: SeverityInfo, Realm: "r", Detail: strings.Repeat("x", i%7)}
}

func closeOK(t *testing.T, s AuditSink) {
	t.Helper()
	ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func counter(r *prometheus.Registry, sink, result string) float64 {
	m := newAuditMetrics(r) // returns the already registered vec
	return testutil.ToFloat64(m.events.WithLabelValues(sink, result))
}

func TestChainVerifyAndTamper(t *testing.T) {
	var c chain
	var lines [][]byte
	for i := 0; i < 6; i++ {
		lines = append(lines, c.seal(ev(i)))
	}
	if n, err := VerifyChain(lines); err != nil || n != 1 {
		t.Fatalf("clean chain: n=%d err=%v", n, err)
	}
	cp := func() [][]byte { return append([][]byte(nil), lines...) }

	rm := cp()
	rm = append(rm[:2], rm[3:]...)
	if _, err := VerifyChain(rm); err == nil {
		t.Error("removal not detected")
	}
	ro := cp()
	ro[2], ro[3] = ro[3], ro[2]
	if _, err := VerifyChain(ro); err == nil {
		t.Error("reorder not detected")
	}
	mod := cp()
	mod[2] = bytes.Replace(mod[2], []byte(`"LOGIN"`), []byte(`"LOGIN2"`), 1)
	if _, err := VerifyChain(mod); err == nil {
		t.Error("modification not detected")
	}
	if _, err := VerifyChain(lines[1:]); err == nil {
		t.Error("head truncation not detected")
	}
	// restart: a second chain appended is accepted
	var c2 chain
	both := append(cp(), c2.seal(ev(0)), c2.seal(ev(1)))
	if n, err := VerifyChain(both); err != nil || n != 2 {
		t.Fatalf("restart: n=%d err=%v", n, err)
	}
	// Seq starts at 1 with empty prev
	var first AuditEvent
	_ = json.Unmarshal(lines[0], &first)
	if first.Seq != 1 || first.Prev != "" {
		t.Fatalf("first event %+v", first)
	}
}

func TestStdoutFramingHostile(t *testing.T) {
	var buf syncBuf
	s, err := NewAuditSink("stdout", AuditOptions{stdout: &buf, Registerer: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	hostile := "a\nb\r\n{\"fake\":1}\x00\x1b[31m end"
	s.Emit(AuditEvent{Type: hostile, Severity: "info", Realm: hostile, UserID: hostile, ClientID: hostile, IP: hostile, RequestID: hostile,
		Detail: hostile + strings.Repeat("é", 600)})
	s.Emit(ev(1))
	closeOK(t, s)
	lines := buf.lines()
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
	var e AuditEvent
	if err := json.Unmarshal(lines[0], &e); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{e.Type, e.Realm, e.UserID, e.ClientID, e.IP, e.RequestID, e.Detail} {
		for _, r := range f {
			if r < 0x20 || r == 0x7f || r == ' ' {
				t.Fatalf("control char %q survived in %q", r, f)
			}
		}
	}
	if len(e.Detail) > MaxAuditDetail || !strings.HasPrefix(e.Detail, "ab{") {
		t.Fatalf("detail %d bytes %q", len(e.Detail), e.Detail[:10])
	}
	if _, err := VerifyChain(lines); err != nil {
		t.Fatal(err)
	}
}

func TestFileSink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "audit.log")
	reg := prometheus.NewRegistry()
	s, err := NewAuditSink("file:"+path, AuditOptions{Registerer: reg})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.Emit(ev(i))
	}
	closeOK(t, s)
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %v", fi.Mode().Perm())
		}
	}
	data, _ := os.ReadFile(path)
	if _, err := VerifyChain(splitLines(data)); err != nil || len(splitLines(data)) != 5 {
		t.Fatalf("err=%v lines=%d", err, len(splitLines(data)))
	}
	// appends across opens
	s, _ = NewAuditSink("file:"+path, AuditOptions{})
	s.Emit(ev(0))
	closeOK(t, s)
	data, _ = os.ReadFile(path)
	if n, err := VerifyChain(splitLines(data)); err != nil || n != 2 {
		t.Fatalf("append: n=%d err=%v", n, err)
	}
	// symlink refused
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("symlink unsupported")
	}
	if _, err := NewAuditSink("file:"+link, AuditOptions{}); err == nil {
		t.Fatal("symlink accepted")
	}
}

type whRecv struct {
	mu      sync.Mutex
	bodies  [][]byte
	sigs    []string
	ids     []string
	calls   atomic.Int32
	handler func(n int32, w http.ResponseWriter, r *http.Request) bool // true = handled
}

func (h *whRecv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := h.calls.Add(1)
	if h.handler != nil && h.handler(n, w, r) {
		return
	}
	var b bytes.Buffer
	_, _ = b.ReadFrom(r.Body)
	h.mu.Lock()
	h.bodies = append(h.bodies, b.Bytes())
	h.sigs = append(h.sigs, r.Header.Get("X-Haven-Signature"))
	h.ids = append(h.ids, r.Header.Get("X-Haven-Delivery"))
	h.mu.Unlock()
	w.WriteHeader(204)
}

func whOpts(srv *httptest.Server, reg *prometheus.Registry) AuditOptions {
	return AuditOptions{Registerer: reg, WebhookSecret: "s3cret", httpClient: srv.Client(),
		backoffBase: time.Millisecond, linger: 50 * time.Millisecond}
}

func TestWebhookSignatureBatchingAndRetry(t *testing.T) {
	h := &whRecv{handler: func(n int32, w http.ResponseWriter, r *http.Request) bool {
		switch n {
		case 1:
			w.WriteHeader(500)
			return true
		case 2:
			w.WriteHeader(429)
			return true
		}
		return false
	}}
	srv := httptest.NewTLSServer(h)
	defer srv.Close()
	reg := prometheus.NewRegistry()
	s, err := NewAuditSink("webhook:"+srv.URL+"/hook", whOpts(srv, reg))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 150; i++ {
		s.Emit(ev(i))
	}
	closeOK(t, s)
	h.mu.Lock()
	defer h.mu.Unlock()
	var all [][]byte
	for i, b := range h.bodies {
		mac := hmac.New(sha256.New, []byte("s3cret"))
		mac.Write(b)
		if h.sigs[i] != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Errorf("bad signature on body %d", i)
		}
		if len(h.ids[i]) < 16 {
			t.Errorf("delivery id %q", h.ids[i])
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(b, &arr); err != nil || len(arr) > 100 {
			t.Fatalf("body %d: %v len %d", i, err, len(arr))
		}
		for _, r := range arr {
			all = append(all, r)
		}
	}
	if len(all) != 150 {
		t.Fatalf("delivered %d", len(all))
	}
	if _, err := VerifyChain(all); err != nil {
		t.Fatal(err)
	}
	if len(h.bodies) < 2 {
		t.Errorf("expected batching into >=2 requests, got %d", len(h.bodies))
	}
	if got := counter(reg, "webhook", "sent"); got != 150 {
		t.Errorf("sent=%v", got)
	}
	if got := counter(reg, "webhook", "error"); got != 0 {
		t.Errorf("error=%v", got)
	}
}

func TestWebhookDropsAndRedirects(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		wantCall int32
	}{{"400", 400, 1}, {"redirect", 302, 1}, {"always500", 500, webhookAttempts}} {
		t.Run(tc.name, func(t *testing.T) {
			var target atomic.Int32
			tsrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { target.Add(1) }))
			defer tsrv.Close()
			h := &whRecv{handler: func(_ int32, w http.ResponseWriter, r *http.Request) bool {
				if tc.status == 302 {
					http.Redirect(w, r, tsrv.URL, http.StatusFound)
				} else {
					w.WriteHeader(tc.status)
				}
				return true
			}}
			srv := httptest.NewTLSServer(h)
			defer srv.Close()
			reg := prometheus.NewRegistry()
			s, err := NewAuditSink("webhook:"+srv.URL, whOpts(srv, reg))
			if err != nil {
				t.Fatal(err)
			}
			s.Emit(ev(1))
			s.Emit(ev(2))
			closeOK(t, s)
			if got := h.calls.Load(); got != tc.wantCall {
				t.Errorf("calls=%d want %d", got, tc.wantCall)
			}
			if target.Load() != 0 {
				t.Error("redirect followed")
			}
			if got := counter(reg, "webhook", "error"); got != 2 {
				t.Errorf("error=%v", got)
			}
		})
	}
}

func TestWebhookHTTPSEnforcement(t *testing.T) {
	o := AuditOptions{WebhookSecret: "x"}
	for _, spec := range []string{"webhook:http://example.com/x", "webhook:ftp://127.0.0.1/", "webhook:https:///x", "webhook:example.com"} {
		if _, err := NewAuditSink(spec, o); err == nil {
			t.Errorf("%s accepted", spec)
		}
	}
	for _, spec := range []string{"webhook:http://127.0.0.1:9/x", "webhook:http://localhost/x", "webhook:http://[::1]:9/x", "webhook:https://example.com/x"} {
		s, err := NewAuditSink(spec, o)
		if err != nil {
			t.Errorf("%s: %v", spec, err)
			continue
		}
		ctx, c := context.WithTimeout(context.Background(), time.Second)
		_ = s.Close(ctx)
		c()
	}
	if _, err := NewAuditSink("webhook:https://example.com/x", AuditOptions{}); err == nil {
		t.Error("missing secret accepted")
	}
	if _, err := NewAuditSink("bogus", o); err == nil {
		t.Error("bogus spec accepted")
	}
}

func TestSlowServerDoesNotBlockEmitAndQueueFullDrops(t *testing.T) {
	release := make(chan struct{})
	h := &whRecv{handler: func(_ int32, w http.ResponseWriter, r *http.Request) bool {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(204)
		return true
	}}
	srv := httptest.NewTLSServer(h)
	defer srv.Close()
	defer close(release)
	reg := prometheus.NewRegistry()
	o := whOpts(srv, reg)
	o.queue = 5
	o.linger = time.Millisecond
	s, err := NewAuditSink("webhook:"+srv.URL, o)
	if err != nil {
		t.Fatal(err)
	}
	s.Emit(ev(0))
	for h.calls.Load() == 0 { // worker is now stuck in the request
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	for i := 0; i < 100; i++ {
		s.Emit(ev(i))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Emit blocked for %v", d)
	}
	if got := counter(reg, "webhook", "dropped"); got != 95 {
		t.Errorf("dropped=%v want 95", got)
	}
	if got := testutil.ToFloat64(newAuditMetrics(reg).queue.WithLabelValues("webhook")); got != 5 {
		t.Errorf("queue length=%v", got)
	}
	// Close with an expired deadline aborts promptly and reports it.
	ctx, c := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer c()
	if err := s.Close(ctx); err == nil {
		t.Error("expected deadline error")
	}
}

func TestMultiSinkAndMetrics(t *testing.T) {
	var buf syncBuf
	path := filepath.Join(t.TempDir(), "a.log")
	reg := prometheus.NewRegistry()
	s, err := NewAuditSink("stdout, file:"+path, AuditOptions{stdout: &buf, Registerer: reg})
	if err != nil {
		t.Fatal(err)
	}
	// registering again on the same registry must not panic
	s2, err := NewAuditSink("stdout", AuditOptions{stdout: &syncBuf{}, Registerer: reg})
	if err != nil {
		t.Fatal(err)
	}
	closeOK(t, s2)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				s.Emit(ev(i))
			}
		}()
	}
	wg.Wait()
	closeOK(t, s)
	data, _ := os.ReadFile(path)
	fl := splitLines(data)
	if len(fl) != 200 || len(buf.lines()) != 200 {
		t.Fatalf("file %d stdout %d", len(fl), len(buf.lines()))
	}
	if _, err := VerifyChain(fl); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyChain(buf.lines()); err != nil {
		t.Fatal(err)
	}
	if counter(reg, "stdout", "sent") != 200 || counter(reg, "file", "sent") != 200 {
		t.Error("sent counters")
	}
	// emit after close is dropped, never blocks
	s.Emit(ev(0))
	if counter(reg, "file", "dropped") != 1 {
		t.Error("post-close emit not counted as dropped")
	}
}

func TestEmptySpecAndCloseIdempotent(t *testing.T) {
	s, err := NewAuditSink("", AuditOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s.Emit(ev(0))
	closeOK(t, s)
	var buf syncBuf
	s, _ = NewAuditSink("stdout", AuditOptions{stdout: &buf})
	closeOK(t, s)
	closeOK(t, s)
}
