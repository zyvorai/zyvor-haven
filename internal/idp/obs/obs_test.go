// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type captureSink struct {
	mu     sync.Mutex
	events []AuditEvent
	closed bool
}

func (c *captureSink) Emit(e AuditEvent) { c.mu.Lock(); c.events = append(c.events, e); c.mu.Unlock() }
func (c *captureSink) Close(context.Context) error {
	c.closed = true
	return nil
}
func (c *captureSink) get() []AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]AuditEvent(nil), c.events...)
}

func newObs(t *testing.T, sink AuditSink, env map[string]string) (*Observer, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	o, err := New(Config{
		Audit: sink, Version: "t1",
		Getenv: func(k string) string { return env[k] },
		Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return o, &buf
}

func scrape(t *testing.T, o *Observer) string {
	t.Helper()
	rec := httptest.NewRecorder()
	o.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func TestEveryContractMetricRegisteredAndExercised(t *testing.T) {
	sink := &captureSink{}
	o, _ := newObs(t, sink, nil)
	o.Login("acme", "success")
	o.Lockout("acme")
	o.TokenIssued("acme", "authorization_code", "access")
	o.TokenError("acme", "refresh_token", "invalid_grant")
	o.RefreshReuse("acme")
	o.CodeReplay("acme")
	o.AdminOp("acme", "client", "create", true)
	o.AdminAuthFailure("missing")
	o.SetStoreUp(true, 3*time.Millisecond)
	o.keyAge.WithLabelValues("acme").Set(5)
	h := o.Middleware(http.NewServeMux())
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/nope", nil))

	out := scrape(t, o)
	for _, name := range []string{
		"haven_idp_http_requests_total", "haven_idp_http_request_duration_seconds_bucket",
		"haven_idp_http_requests_in_flight", "haven_idp_logins_total", "haven_idp_lockouts_total",
		"haven_idp_tokens_issued_total", "haven_idp_token_errors_total", "haven_idp_refresh_reuse_total",
		"haven_idp_code_replay_total", "haven_idp_admin_operations_total", "haven_idp_admin_auth_failures_total",
		"haven_idp_store_up", "haven_idp_store_ping_duration_seconds", "haven_idp_signing_key_age_seconds",
		`haven_idp_build_info{goversion=`, "go_goroutines",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("metric %s missing from exposition", name)
		}
	}
	if v := testutil.ToFloat64(o.logins.WithLabelValues("acme", "success")); v != 1 {
		t.Errorf("logins = %v", v)
	}
	if v := testutil.ToFloat64(o.tokens.WithLabelValues("acme", "authorization_code", "access")); v != 1 {
		t.Errorf("tokens = %v", v)
	}
	if v := testutil.ToFloat64(o.adminOps.WithLabelValues("acme", "client", "create", "ok")); v != 1 {
		t.Errorf("adminOps = %v", v)
	}
	if v := testutil.ToFloat64(o.storeUp); v != 1 {
		t.Errorf("store_up = %v", v)
	}
	// Security signals reach the audit sink.
	types := map[string]string{}
	for _, e := range sink.get() {
		types[e.Type] = e.Severity
	}
	for _, c := range []struct{ typ, sev string }{
		{"LOCKOUT", SeverityAlert}, {"REFRESH_REUSE", SeverityAlert}, {"CODE_REPLAY", SeverityAlert}, {"ADMIN_AUTH_FAILURE", SeverityWarning},
	} {
		if types[c.typ] != c.sev {
			t.Errorf("audit %s severity = %q, want %q", c.typ, types[c.typ], c.sev)
		}
	}
	if err := o.Shutdown(context.Background()); err != nil || !sink.closed {
		t.Errorf("shutdown err=%v closed=%v", err, sink.closed)
	}
}

func TestCardinalityGuards(t *testing.T) {
	o, _ := newObs(t, nil, nil)
	hostile := `evil"realm\n{} <script>` + strings.Repeat("a", 100)
	o.Login(hostile, "<b>hax</b>")
	o.Login(strings.Repeat("a", 64), "success")
	o.Login("Upper", "success")
	o.TokenIssued("ok-realm", "weird", "x")
	o.TokenError("ok-realm", "authorization_code", "made_up")
	o.AdminOp("", "nope", "nope", false)
	o.AdminAuthFailure("zzz")

	if v := testutil.ToFloat64(o.logins.WithLabelValues("unknown", "other")); v != 1 {
		t.Errorf("hostile login -> %v", v)
	}
	if v := testutil.ToFloat64(o.logins.WithLabelValues("unknown", "success")); v != 2 {
		t.Errorf("long and uppercase realms must be unknown, got %v", v)
	}
	if v := testutil.ToFloat64(o.tokens.WithLabelValues("ok-realm", "other", "other")); v != 1 {
		t.Errorf("token enum = %v", v)
	}
	if v := testutil.ToFloat64(o.tokenErrs.WithLabelValues("ok-realm", "authorization_code", "other")); v != 1 {
		t.Errorf("token error enum = %v", v)
	}
	if v := testutil.ToFloat64(o.adminOps.WithLabelValues("unknown", "other", "other", "error")); v != 1 {
		t.Errorf("admin enum = %v", v)
	}
	if v := testutil.ToFloat64(o.adminAuth.WithLabelValues("other")); v != 1 {
		t.Errorf("admin auth enum = %v", v)
	}
	out := scrape(t, o)
	if strings.Contains(out, "evil") || strings.Contains(out, "script") {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "evil") || strings.Contains(l, "<script") {
				t.Errorf("hostile value leaked into exposition: %s", l)
			}
		}
	}
}

func TestMetricsOutputHasNoUserData(t *testing.T) {
	o, _ := newObs(t, nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	h := o.Middleware(mux)
	req := httptest.NewRequest("GET", "/realms/acme/login?username=alice&password=hunter2&client_id=secretclient", nil)
	req.Header.Set("Authorization", "Bearer sekrettoken")
	req.Header.Set("Cookie", "sid=cookievalue")
	h.ServeHTTP(httptest.NewRecorder(), req)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/realms/zed/users/alice", nil))
	out := scrape(t, o)
	for _, bad := range []string{"alice", "hunter2", "secretclient", "sekrettoken", "cookievalue", "acme", "zed"} {
		if strings.Contains(out, bad) {
			t.Errorf("exposition contains %q", bad)
		}
	}
	if !strings.Contains(out, `route="/realms/"`) {
		t.Error("expected matched pattern as route")
	}
}

func TestMiddlewareRouteAndAccessLog(t *testing.T) {
	o, logbuf := newObs(t, nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /realms/{realm}/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte("hello"))
	})
	h := o.Middleware(mux)

	req := httptest.NewRequest("GET", "/realms/acme/ping?code=SECRETCODE&password=pw", nil)
	req.Header.Set("Authorization", "Bearer TOPSECRET")
	req.Header.Set("Cookie", "sess=COOKIESECRET")
	req.RemoteAddr = "203.0.113.9:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := testutil.ToFloat64(o.httpReqs.WithLabelValues("GET /realms/{realm}/ping", "GET", "201")); got != 1 {
		t.Fatalf("r.Pattern not visible to outer middleware: count %v", got)
	}
	var line map[string]any
	if err := json.Unmarshal(logbuf.Bytes(), &line); err != nil {
		t.Fatalf("access log: %v: %s", err, logbuf.String())
	}
	if line["route"] != "GET /realms/{realm}/ping" || line["status"] != float64(201) || line["bytes"] != float64(5) ||
		line["realm"] != "acme" || line["remote"] != "203.0.113.9" || line["method"] != "GET" {
		t.Errorf("access log fields: %v", line)
	}
	for _, k := range []string{"request_id", "trace_id", "duration_ms"} {
		if _, ok := line[k]; !ok {
			t.Errorf("access log missing %s", k)
		}
	}
	for _, bad := range []string{"SECRETCODE", "TOPSECRET", "COOKIESECRET", "pw", "code=", "?"} {
		if strings.Contains(logbuf.String(), bad) {
			t.Errorf("access log contains %q: %s", bad, logbuf.String())
		}
	}

	logbuf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/totally/raw/path/123", nil))
	if got := testutil.ToFloat64(o.httpReqs.WithLabelValues("unmatched", "GET", "404")); got != 1 {
		t.Errorf("404 must be route=unmatched, got %v", got)
	}
	if strings.Contains(logbuf.String(), "/totally") || strings.Contains(scrape(t, o), "/totally") {
		t.Error("raw path leaked")
	}
}

func TestRequestID(t *testing.T) {
	o, _ := newObs(t, nil, nil)
	var seen string
	h := o.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = RequestID(r.Context()) }))
	cases := []struct {
		in   string
		keep bool
	}{
		{"abc-123_X.y", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"bad id", false},
		{"a\"b", false},
		{"", false},
		{"é", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		if c.in != "" {
			req.Header.Set("X-Request-Id", c.in)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		got := rec.Header().Get("X-Request-Id")
		if got != seen {
			t.Errorf("header %q != ctx %q", got, seen)
		}
		if c.keep && got != c.in {
			t.Errorf("%q should be kept, got %q", c.in, got)
		}
		if !c.keep && (got == c.in || len(got) != 32) {
			t.Errorf("%q should be replaced by 32 hex, got %q", c.in, got)
		}
	}
}

func TestParseTraceparent(t *testing.T) {
	const tid, sid = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	cases := []struct {
		name, in string
		ok       bool
	}{
		{"valid", "00-" + tid + "-" + sid + "-01", true},
		{"unsampled", "00-" + tid + "-" + sid + "-00", true},
		{"version ff", "ff-" + tid + "-" + sid + "-01", false},
		{"version 01", "01-" + tid + "-" + sid + "-01", false},
		{"zero trace", "00-00000000000000000000000000000000-" + sid + "-01", false},
		{"zero span", "00-" + tid + "-0000000000000000-01", false},
		{"uppercase", "00-" + strings.ToUpper(tid) + "-" + sid + "-01", false},
		{"short trace", "00-" + tid[:30] + "-" + sid + "-01", false},
		{"non-hex", "00-" + strings.Repeat("g", 32) + "-" + sid + "-01", false},
		{"extra field", "00-" + tid + "-" + sid + "-01-xx", false},
		{"bad sep", "00_" + tid + "-" + sid + "-01", false},
		{"empty", "", false},
		{"garbage", "hello", false},
	}
	for _, c := range cases {
		gt, gp, _, ok := parseTraceparent(c.in)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.name, ok, c.ok)
		}
		if ok && (gt != tid || gp != sid) {
			t.Errorf("%s: ids %s %s", c.name, gt, gp)
		}
	}

	o, logbuf := newObs(t, nil, nil)
	var ctxTrace string
	h := o.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ctxTrace = TraceID(r.Context()) }))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Traceparent", "00-"+tid+"-"+sid+"-01")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	tp := rec.Header().Get("Traceparent")
	if ctxTrace != tid || !strings.HasPrefix(tp, "00-"+tid+"-") || strings.Contains(tp, sid) {
		t.Errorf("ctx=%s traceparent=%s", ctxTrace, tp)
	}
	if !strings.Contains(logbuf.String(), tid) {
		t.Error("trace_id not in access log")
	}
	// Malformed inbound: fresh trace id.
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Traceparent", "garbage")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if _, _, _, ok := parseTraceparent(rec.Header().Get("Traceparent")); !ok || ctxTrace == tid {
		t.Errorf("malformed inbound must start a new trace: %s", rec.Header().Get("Traceparent"))
	}
}

func TestPanicRecovered(t *testing.T) {
	o, logbuf := newObs(t, nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/boom", func(http.ResponseWriter, *http.Request) { panic("kaboom\ninternal detail") })
	h := o.Middleware(mux)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/boom", nil))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "kaboom") || strings.Contains(rec.Body.String(), "goroutine") {
		t.Errorf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := testutil.ToFloat64(o.httpReqs.WithLabelValues("/boom", "GET", "500")); got != 1 {
		t.Errorf("500 count %v", got)
	}
	if testutil.ToFloat64(o.inflight) != 0 {
		t.Error("in-flight leaked after panic")
	}
	if strings.Contains(logbuf.String(), "goroutine ") {
		t.Error("stack in log")
	}
}

type flusherOnly struct {
	http.ResponseWriter
	flushed bool
}

func (f *flusherOnly) Flush() { f.flushed = true }

func TestWriterWrapperPreservesInterfaces(t *testing.T) {
	// Plain writer: no Flusher, no Hijacker.
	var plain struct{ http.ResponseWriter }
	plain.ResponseWriter = httptest.NewRecorder()
	_, w := wrapWriter(plain)
	if _, ok := w.(http.Flusher); ok {
		t.Error("must not claim Flusher")
	}
	if _, ok := w.(http.Hijacker); ok {
		t.Error("must not claim Hijacker")
	}
	f := &flusherOnly{ResponseWriter: httptest.NewRecorder()}
	sw, w := wrapWriter(f)
	fl, ok := w.(http.Flusher)
	if !ok {
		t.Fatal("must keep Flusher")
	}
	if _, ok := w.(http.Hijacker); ok {
		t.Error("must not claim Hijacker")
	}
	fl.Flush()
	if !f.flushed || sw.status != 200 {
		t.Error("flush not forwarded")
	}
}

func TestOTLPExport(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var gotHdr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		gotHdr = r.Header.Get("X-Test")
		mu.Unlock()
	}))
	defer srv.Close()
	o, _ := newObs(t, nil, map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": srv.URL, "OTEL_EXPORTER_OTLP_HEADERS": "X-Test=1",
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	h := o.Middleware(mux)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/realms/acme/x", nil))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := o.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || gotHdr != "1" {
		t.Fatalf("bodies=%d hdr=%q", len(bodies), gotHdr)
	}
	for _, want := range []string{`"name":"/realms/"`, `"http.route"`, `"haven.realm"`, `"acme"`, `"code":2`, `"service.name"`} {
		if !strings.Contains(bodies[0], want) {
			t.Errorf("span payload missing %s: %s", want, bodies[0])
		}
	}
	if strings.Contains(bodies[0], "/realms/acme/x") {
		t.Error("raw path in span")
	}
}

func TestNoTracerWithoutEndpoint(t *testing.T) {
	o, _ := newObs(t, nil, nil)
	if o.tracer != nil {
		t.Error("tracer must be off without an endpoint")
	}
	rec := httptest.NewRecorder()
	o.Middleware(http.NewServeMux()).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if !strings.HasSuffix(rec.Header().Get("Traceparent"), "-00") {
		t.Errorf("unsampled flag expected: %s", rec.Header().Get("Traceparent"))
	}
}

func TestAuditStore(t *testing.T) {
	sink := &captureSink{}
	base := memstore.New()
	_ = base.CreateRealm(context.Background(), core.Realm{Name: "r"})
	st := AuditStore(base, sink)
	ctx := context.WithValue(context.Background(), keyRequestID, "rid1")
	if err := st.AppendEvent(ctx, core.Event{Realm: "r", Type: "LOGIN", UserID: "u", ClientID: "c", IP: "1.2.3.4", Detail: "d"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendEvent(ctx, core.Event{Realm: "r", Type: "LOGIN_ERROR"}); err != nil {
		t.Fatal(err)
	}
	ev := sink.get()
	if len(ev) != 2 || ev[0].Severity != SeverityInfo || ev[1].Severity != SeverityWarning {
		t.Fatalf("events: %+v", ev)
	}
	if ev[0].UserID != "u" || ev[0].IP != "1.2.3.4" || ev[0].RequestID != "rid1" || ev[0].Time.IsZero() {
		t.Errorf("mapping: %+v", ev[0])
	}
	// Delegation untouched.
	if _, err := st.ListRealms(ctx); err != nil {
		t.Fatal(err)
	}
	if AuditStore(memstore.New(), nil) == nil {
		t.Error("nil sink returns the store")
	}
}

func TestWatchStoreSeriesCleanup(t *testing.T) {
	st := memstore.New()
	ctx := context.Background()
	for _, n := range []string{"a", "b"} {
		if err := st.CreateRealm(ctx, core.Realm{Name: n}); err != nil {
			t.Fatal(err)
		}
		if err := st.PutSigningKey(ctx, core.SigningKey{KID: n + "1", Realm: n, Active: true, CreatedAt: time.Now().Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	o, _ := newObs(t, nil, nil)
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { WatchStore(wctx, st, o, 20*time.Millisecond); close(done) }()
	waitFor(t, func() bool { return testutil.CollectAndCount(o.keyAge) == 2 })
	if v := testutil.ToFloat64(o.keyAge.WithLabelValues("a")); v < 3500 || v > 3700 {
		t.Errorf("age = %v", v)
	}
	if testutil.ToFloat64(o.storeUp) != 1 {
		t.Error("store_up")
	}
	if err := st.DeleteRealm(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return testutil.CollectAndCount(o.keyAge) == 1 })
	cancel()
	<-done
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}
