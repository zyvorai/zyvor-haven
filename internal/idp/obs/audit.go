// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
)

// Audit stream limits.
const (
	// DefaultAuditQueue is the per-sink queue capacity in events.
	DefaultAuditQueue = 10000
	// MaxAuditDetail is the maximum Detail length in bytes.
	MaxAuditDetail = 512
	// auditBatchMax and auditLinger bound webhook batches.
	auditBatchMax = 100
	auditLinger   = 2 * time.Second
)

// AuditOptions configures NewAuditSink.
type AuditOptions struct {
	Logger        *slog.Logger          // optional; sink problems are logged here
	Registerer    prometheus.Registerer // optional; nil disables registration
	WebhookSecret string                // HMAC key for webhook: sinks (required for them)

	// test hooks
	queue       int
	stdout      io.Writer
	httpClient  *http.Client
	backoffBase time.Duration
	linger      time.Duration
}

// NewAuditSink builds a sink from a spec: "stdout", "file:/path",
// "webhook:https://host/path", or a comma-separated list of those (fan-out).
// "" and "none" yield a sink that discards events.
//
// Every sink has a bounded queue (10000 events) and one worker goroutine.
// Emit never blocks: when the queue is full the NEWEST event (the one being
// emitted) is dropped and counted in
// haven_idp_audit_events_total{result="dropped"}. The tamper-evidence chain
// still advances for a dropped event, so the loss shows up as a seq gap.
//
// Chain: each sink assigns Seq (1, 2, ...) and Prev = hex SHA-256 of the
// previous event's exact JSON bytes as that sink emitted them (the line for
// stdout/file, the array element for webhook). The first event of a process
// has Seq 1 and empty Prev; a restart begins a new chain. A multi sink keeps
// a chain per sink. See docs/observability.md and VerifyChain.
//
// Strings are stripped of control characters and Detail is truncated to 512
// bytes. Do not put secrets in events.
func NewAuditSink(spec string, opts AuditOptions) (AuditSink, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "none" {
		return nopSink{}, nil
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	m := newAuditMetrics(opts.Registerer)
	var sinks []AuditSink
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		var s AuditSink
		var err error
		switch {
		case part == "stdout":
			s, err = newStdoutSink(opts, m)
		case strings.HasPrefix(part, "file:"):
			s, err = newFileSink(strings.TrimPrefix(part, "file:"), opts, m)
		case strings.HasPrefix(part, "webhook:"):
			s, err = newWebhookSink(strings.TrimPrefix(part, "webhook:"), opts, m)
		default:
			err = fmt.Errorf("unknown audit sink %q (want stdout, file:/path, webhook:https://...)", part)
		}
		if err != nil {
			for _, o := range sinks {
				_ = o.Close(context.Background())
			}
			return nil, err
		}
		sinks = append(sinks, s)
	}
	if len(sinks) == 1 {
		return sinks[0], nil
	}
	return multiSink(sinks), nil
}

type nopSink struct{}

func (nopSink) Emit(AuditEvent)             {}
func (nopSink) Close(context.Context) error { return nil }

type multiSink []AuditSink

func (m multiSink) Emit(e AuditEvent) {
	for _, s := range m {
		s.Emit(e)
	}
}

func (m multiSink) Close(ctx context.Context) error {
	var errs []error
	for _, s := range m {
		errs = append(errs, s.Close(ctx))
	}
	return errors.Join(errs...)
}

// ---- metrics ----

type auditMetrics struct {
	events *prometheus.CounterVec
	queue  *prometheus.GaugeVec
}

func registerOnce[C prometheus.Collector](r prometheus.Registerer, c C) C {
	if r == nil {
		return c
	}
	if err := r.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if ex, ok := are.ExistingCollector.(C); ok {
				return ex
			}
		}
	}
	return c
}

func newAuditMetrics(r prometheus.Registerer) *auditMetrics {
	return &auditMetrics{
		events: registerOnce(r, prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "haven_idp_audit_events_total",
			Help: "Audit events by sink and result (sent, dropped, error).",
		}, []string{"sink", "result"})),
		queue: registerOnce(r, prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "haven_idp_audit_queue_length",
			Help: "Audit events waiting in the sink queue.",
		}, []string{"sink"})),
	}
}

// ---- chain ----

// chain assigns Seq and Prev and renders the canonical JSON. Not safe for
// concurrent use; the sink holds its mutex around it.
type chain struct {
	seq  uint64
	prev string
}

func (c *chain) seal(e AuditEvent) []byte {
	sanitizeEvent(&e)
	c.seq++
	e.Seq = c.seq
	e.Prev = c.prev
	b, err := json.Marshal(e)
	if err != nil { // cannot happen for this struct
		b = []byte(fmt.Sprintf(`{"type":"AUDIT_MARSHAL_ERROR","severity":"alert","seq":%d,"prev":%q}`, e.Seq, e.Prev))
	}
	sum := sha256.Sum256(b)
	c.prev = hex.EncodeToString(sum[:])
	return b
}

func sanitizeEvent(e *AuditEvent) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	for _, p := range []*string{&e.Realm, &e.Type, &e.Severity, &e.UserID, &e.ClientID, &e.IP, &e.Detail, &e.RequestID} {
		*p = stripControl(*p)
	}
	if len(e.Detail) > MaxAuditDetail {
		d := e.Detail[:MaxAuditDetail]
		for !utf8.ValidString(d) && len(d) > 0 {
			d = d[:len(d)-1]
		}
		e.Detail = d
	}
}

func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return -1
		}
		return r
	}, s)
}

// ---- generic bounded sink ----

type backend interface {
	// send delivers a batch. A non-nil error counts the batch as errors.
	send(ctx context.Context, lines [][]byte) error
	close() error
}

type sink struct {
	name     string
	m        *auditMetrics
	log      *slog.Logger
	be       backend
	maxBatch int
	linger   time.Duration

	mu     sync.Mutex // guards ch sends, closed and cn
	cn     chain
	closed bool
	ch     chan []byte

	wctx      context.Context
	abort     context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newSink(name string, opts AuditOptions, m *auditMetrics, be backend, maxBatch int, linger time.Duration) *sink {
	q := opts.queue
	if q <= 0 {
		q = DefaultAuditQueue
	}
	s := &sink{name: name, m: m, log: opts.Logger, be: be, maxBatch: maxBatch, linger: linger,
		ch: make(chan []byte, q), done: make(chan struct{})}
	s.wctx, s.abort = context.WithCancel(context.Background())
	for _, r := range []string{"sent", "dropped", "error"} {
		m.events.WithLabelValues(name, r).Add(0)
	}
	m.queue.WithLabelValues(name).Set(0)
	go s.run()
	return s
}

func (s *sink) count(result string, n int) {
	s.m.events.WithLabelValues(s.name, result).Add(float64(n))
}

// Emit never blocks. When the queue is full the new event is dropped.
func (s *sink) Emit(e AuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.count("dropped", 1)
		return
	}
	b := s.cn.seal(e)
	select {
	case s.ch <- b:
		s.m.queue.WithLabelValues(s.name).Set(float64(len(s.ch)))
	default:
		s.count("dropped", 1)
	}
}

func (s *sink) run() {
	defer close(s.done)
	for {
		line, ok := <-s.ch
		if !ok {
			return
		}
		batch := [][]byte{line}
		var timer *time.Timer
		var tc <-chan time.Time
		if s.linger > 0 {
			timer = time.NewTimer(s.linger)
			tc = timer.C
		}
	fill:
		for len(batch) < s.maxBatch {
			if s.linger > 0 {
				select {
				case l, ok := <-s.ch:
					if !ok {
						break fill
					}
					batch = append(batch, l)
				case <-tc:
					break fill
				}
			} else {
				select {
				case l, ok := <-s.ch:
					if !ok {
						break fill
					}
					batch = append(batch, l)
				default:
					break fill
				}
			}
		}
		if timer != nil {
			timer.Stop()
		}
		s.m.queue.WithLabelValues(s.name).Set(float64(len(s.ch)))
		if s.wctx.Err() != nil {
			s.count("dropped", len(batch))
			continue
		}
		if err := s.be.send(s.wctx, batch); err != nil {
			s.count("error", len(batch))
			s.log.Warn("audit sink delivery failed", "sink", s.name, "events", len(batch), "err", err)
		} else {
			s.count("sent", len(batch))
		}
	}
}

// Close stops accepting events, drains the queue within ctx and releases the
// backend (files are fsynced). Events still queued at the deadline are
// counted as dropped.
func (s *sink) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
	s.mu.Unlock()
	var err error
	select {
	case <-s.done:
	case <-ctx.Done():
		s.abort()
		<-s.done
		err = ctx.Err()
	}
	s.closeOnce.Do(func() { s.closeErr = s.be.close() })
	s.abort()
	return errors.Join(err, s.closeErr)
}
