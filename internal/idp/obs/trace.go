// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyTrace
)

type traceCtx struct{ traceID, spanID string }

// RequestID returns the request id the middleware assigned, or "".
func RequestID(ctx context.Context) string {
	s, _ := ctx.Value(keyRequestID).(string)
	return s
}

// TraceID returns the W3C trace id of the current request, or "".
func TraceID(ctx context.Context) string {
	t, _ := ctx.Value(keyTrace).(traceCtx)
	return t.traceID
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool { return strings.Trim(s, "0") == "" }

// parseTraceparent strictly parses a version-00 traceparent header.
func parseTraceparent(h string) (traceID, parentID string, flags byte, ok bool) {
	if len(h) != 55 || h[2] != '-' || h[35] != '-' || h[52] != '-' || h[:2] != "00" {
		return "", "", 0, false
	}
	traceID, parentID, fl := h[3:35], h[36:52], h[53:55]
	if !isHex(traceID) || !isHex(parentID) || !isHex(fl) || allZero(traceID) || allZero(parentID) {
		return "", "", 0, false
	}
	b, _ := hex.DecodeString(fl)
	return traceID, parentID, b[0], true
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newSpanID() string {
	for {
		if s := randHex(8); !allZero(s) {
			return s
		}
	}
}

func newTraceID() string {
	for {
		if s := randHex(16); !allZero(s) {
			return s
		}
	}
}

// validRequestID accepts only <=64 chars of [A-Za-z0-9._-].
func validRequestID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// ---- OTLP/HTTP JSON exporter (hand-rolled: no OpenTelemetry SDK dependency) ----

type span struct {
	traceID, spanID, parentID string
	name                      string
	start, end                time.Time
	method, route, realm      string
	status                    int
}

type tracer struct {
	endpoint string
	headers  map[string]string
	service  string
	version  string
	ratio    float64
	client   *http.Client
	log      *slog.Logger

	queue chan span
	stop  chan struct{}
	done  chan struct{}
	once  sync.Once
}

const (
	traceQueueSize = 2048
	traceBatchSize = 128
)

func newTracerFromEnv(getenv func(string) string, version string, log *slog.Logger) *tracer {
	ep := strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
	if ep == "" {
		base := strings.TrimRight(strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_ENDPOINT")), "/")
		if base == "" {
			return nil
		}
		ep = base + "/v1/traces"
	}
	if getenv("OTEL_SDK_DISABLED") == "true" || getenv("OTEL_TRACES_EXPORTER") == "none" {
		return nil
	}
	ratio := 1.0
	if s := strings.TrimSpace(getenv("OTEL_TRACES_SAMPLER_ARG")); s != "" {
		if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 && f <= 1 {
			ratio = f
		}
	}
	svc := getenv("OTEL_SERVICE_NAME")
	if svc == "" {
		svc = "haven-idp"
	}
	hdr := map[string]string{}
	for _, kv := range strings.Split(getenv("OTEL_EXPORTER_OTLP_HEADERS"), ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && k != "" {
			hdr[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return startTracer(ep, hdr, svc, version, ratio, log)
}

func startTracer(endpoint string, headers map[string]string, service, version string, ratio float64, log *slog.Logger) *tracer {
	t := &tracer{
		endpoint: endpoint, headers: headers, service: service, version: version, ratio: ratio,
		client: &http.Client{Timeout: 5 * time.Second}, log: log,
		queue: make(chan span, traceQueueSize), stop: make(chan struct{}), done: make(chan struct{}),
	}
	go t.loop()
	return t
}

// sampled decides deterministically from the trace id so all services agree.
func (t *tracer) sampled(traceID string, parentFlags byte, hasParent bool) bool {
	if hasParent && parentFlags&1 == 1 {
		return true
	}
	if t.ratio >= 1 {
		return true
	}
	if t.ratio <= 0 {
		return false
	}
	b, _ := hex.DecodeString(traceID[16:])
	return float64(binary.BigEndian.Uint64(b))/float64(^uint64(0)) < t.ratio
}

// record never blocks: the span is dropped when the queue is full.
func (t *tracer) record(s span) {
	select {
	case t.queue <- s:
	default:
	}
}

func (t *tracer) loop() {
	defer close(t.done)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var batch []span
	flush := func() {
		if len(batch) > 0 {
			t.export(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case s := <-t.queue:
			batch = append(batch, s)
			if len(batch) >= traceBatchSize {
				flush()
			}
		case <-tick.C:
			flush()
		case <-t.stop:
			for {
				select {
				case s := <-t.queue:
					batch = append(batch, s)
					if len(batch) >= traceBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

type kv map[string]any

func strAttr(k, v string) kv { return kv{"key": k, "value": kv{"stringValue": v}} }
func intAttr(k string, v int) kv {
	return kv{"key": k, "value": kv{"intValue": strconv.Itoa(v)}}
}

func (t *tracer) payload(batch []span) []byte {
	spans := make([]kv, 0, len(batch))
	for _, s := range batch {
		attrs := []kv{
			strAttr("http.request.method", s.method), strAttr("http.route", s.route),
			intAttr("http.response.status_code", s.status),
		}
		if s.realm != "" {
			attrs = append(attrs, strAttr("haven.realm", s.realm))
		}
		code := 1
		if s.status >= 500 {
			code = 2
		}
		sp := kv{
			"traceId": s.traceID, "spanId": s.spanID, "name": s.name, "kind": 2,
			"startTimeUnixNano": strconv.FormatInt(s.start.UnixNano(), 10),
			"endTimeUnixNano":   strconv.FormatInt(s.end.UnixNano(), 10),
			"attributes":        attrs, "status": kv{"code": code},
		}
		if s.parentID != "" {
			sp["parentSpanId"] = s.parentID
		}
		spans = append(spans, sp)
	}
	b, _ := json.Marshal(kv{"resourceSpans": []kv{{
		"resource": kv{"attributes": []kv{strAttr("service.name", t.service), strAttr("service.version", t.version)}},
		"scopeSpans": []kv{{
			"scope": kv{"name": "haven-idp/obs"},
			"spans": spans,
		}},
	}}})
	return b
}

func (t *tracer) export(batch []span) {
	req, err := http.NewRequest(http.MethodPost, t.endpoint, bytes.NewReader(t.payload(batch)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		t.log.Warn("trace export failed", "error", err.Error())
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.log.Warn("trace export rejected", "status", resp.StatusCode)
	}
}

func (t *tracer) shutdown(ctx context.Context) error {
	t.once.Do(func() { close(t.stop) })
	select {
	case <-t.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
