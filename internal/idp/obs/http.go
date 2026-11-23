// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the real writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type flushWriter struct{ *statusWriter }

func (w flushWriter) Flush() {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	w.ResponseWriter.(http.Flusher).Flush()
}

type hijackWriter struct{ *statusWriter }

func (w hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}

type flushHijackWriter struct{ *statusWriter }

func (w flushHijackWriter) Flush() { flushWriter(w).Flush() }
func (w flushHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}

// wrapWriter exposes Flusher/Hijacker only when the inner writer has them.
func wrapWriter(w http.ResponseWriter) (*statusWriter, http.ResponseWriter) {
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	_, f := w.(http.Flusher)
	_, h := w.(http.Hijacker)
	switch {
	case f && h:
		return sw, flushHijackWriter{sw}
	case f:
		return sw, flushWriter{sw}
	case h:
		return sw, hijackWriter{sw}
	}
	return sw, sw
}

// realmFromPath extracts a plausible realm from /realms/{realm}/..., only when
// it passes the realm-name pattern.
func realmFromPath(r *http.Request, pattern string) string {
	if strings.Contains(pattern, "{realm}") {
		if v := r.PathValue("realm"); realmRe.MatchString(v) {
			return v
		}
		return ""
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/realms/"); ok && strings.HasPrefix(pattern, "/realms/") {
		seg, _, _ := strings.Cut(rest, "/")
		if realmRe.MatchString(seg) {
			return seg
		}
	}
	return ""
}

// Middleware wraps the server's ServeMux (the mux populates r.Pattern on the
// request pointer it is given, which the outer wrapper still holds). It
// assigns a request id and trace context, records metrics, writes one access
// log line per request and recovers panics.
func (o *Observer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rid := r.Header.Get("X-Request-Id")
		if !validRequestID(rid) {
			rid = randHex(16)
		}
		w.Header().Set("X-Request-Id", rid)

		traceID, parentID, flags, hasParent := parseTraceparent(r.Header.Get("Traceparent"))
		if !hasParent {
			traceID, parentID, flags = newTraceID(), "", 0
		}
		spanID := newSpanID()
		sample := o.tracer != nil && o.tracer.sampled(traceID, flags, hasParent)
		outFlags := "00"
		if sample {
			outFlags = "01"
		}
		w.Header().Set("Traceparent", "00-"+traceID+"-"+spanID+"-"+outFlags)

		ctx := context.WithValue(r.Context(), keyRequestID, rid)
		ctx = context.WithValue(ctx, keyTrace, traceCtx{traceID, spanID})
		r = r.WithContext(ctx)

		sw, ww := wrapWriter(w)
		o.inflight.Inc()
		abort := false
		func() {
			defer func() {
				if v := recover(); v != nil {
					if v == http.ErrAbortHandler {
						abort = true
						sw.status = http.StatusInternalServerError
						return
					}
					o.log.Error("panic serving request", "request_id", rid, "trace_id", traceID, "panic", sanitizePanic(v))
					if !sw.wrote {
						http.Error(sw, "internal server error", http.StatusInternalServerError)
					}
					sw.status = http.StatusInternalServerError
				}
			}()
			next.ServeHTTP(ww, r)
		}()
		o.inflight.Dec()

		route := r.Pattern // set in place by the ServeMux that served r
		if route == "" {
			route = "unmatched"
		}
		dur := time.Since(start)
		method := methodLabel(r.Method)
		o.httpReqs.WithLabelValues(route, method, strconv.Itoa(sw.status)).Inc()
		o.httpDur.WithLabelValues(route, method).Observe(dur.Seconds())

		realm := ""
		if route != "unmatched" {
			realm = realmFromPath(r, route)
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		attrs := []any{
			"method", method, "route", route, "status", sw.status,
			"duration_ms", float64(dur.Microseconds()) / 1000, "bytes", sw.bytes,
			"request_id", rid, "trace_id", traceID, "remote", host,
		}
		if realm != "" {
			attrs = append(attrs, "realm", realm)
		}
		o.log.Info("request", attrs...)

		if sample {
			o.tracer.record(span{
				traceID: traceID, spanID: spanID, parentID: parentID, name: route,
				start: start, end: start.Add(dur), method: method, route: route, realm: realm, status: sw.status,
			})
		}
		if abort {
			panic(http.ErrAbortHandler)
		}
	})
}

// methodLabel bounds the method label to standard verbs.
func methodLabel(m string) string {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return m
	}
	return "OTHER"
}

// sanitizePanic keeps the log line short and single-line; no stack is logged
// and nothing is sent to the client.
func sanitizePanic(v any) string {
	s := "panic"
	switch x := v.(type) {
	case error:
		s = x.Error()
	case string:
		s = x
	}
	s = strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
