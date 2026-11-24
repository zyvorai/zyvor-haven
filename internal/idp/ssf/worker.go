// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package ssf

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
	"github.com/zyvorai/haven/internal/idp/secretbox"
)

// Worker delivers outbox rows by push (RFC 8935). The destination is
// receiver-chosen, so every request is a potential SSRF: no redirects, no
// proxy, the IP is checked at dial time (safehttp). The outbox is durable and
// shared: several replicas can run workers, rows are leased while in flight.
type Worker struct {
	Store  core.Store // the UNDECORATED store
	Box    *secretbox.Box
	Logger *slog.Logger
	Clock  func() time.Time
	// AllowPrivate lifts the IP policy and permits http to loopback. Dev only.
	AllowPrivate bool
	RootCAs      *x509.CertPool // tests only

	Timeout     time.Duration // per attempt; default 5s
	Poll        time.Duration // default 1s
	Backoff     time.Duration // first retry delay; doubles; default 10s
	MaxBackoff  time.Duration // default 1h
	MaxAttempts int           // default 10
	Batch       int           // default 16
	Lease       time.Duration // default 2m

	client *http.Client
	wg     sync.WaitGroup
	once   sync.Once
}

func (w *Worker) init() {
	w.once.Do(func() {
		if w.Logger == nil {
			w.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		}
		if w.Clock == nil {
			w.Clock = time.Now
		}
		if w.Timeout <= 0 {
			w.Timeout = 5 * time.Second
		}
		if w.Poll <= 0 {
			w.Poll = time.Second
		}
		if w.Backoff <= 0 {
			w.Backoff = 10 * time.Second
		}
		if w.MaxBackoff <= 0 {
			w.MaxBackoff = time.Hour
		}
		if w.MaxAttempts <= 0 {
			w.MaxAttempts = 10
		}
		if w.Batch <= 0 {
			w.Batch = 16
		}
		if w.Lease <= 0 {
			w.Lease = 2 * time.Minute
		}
		w.client = safehttp.New(safehttp.Options{AllowPrivate: w.AllowPrivate, RootCAs: w.RootCAs, Timeout: w.Timeout}).HTTP
	})
}

// Drain waits for in-flight deliveries (graceful shutdown, tests).
func (w *Worker) Drain() { w.wg.Wait() }

// Run polls until ctx ends. It returns immediately when the store has no SSF
// support.
func (w *Worker) Run(ctx context.Context) {
	w.init()
	if _, ok := core.StoreAs[core.SSFStore](w.Store); !ok {
		return
	}
	t := time.NewTicker(w.Poll)
	defer t.Stop()
	prune := time.NewTicker(10 * time.Minute)
	defer prune.Stop()
	for {
		w.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-prune.C:
			w.Prune(ctx)
		case <-t.C:
		}
	}
}

// Prune deletes old outbox rows.
func (w *Worker) Prune(ctx context.Context) {
	w.init()
	ss, ok := core.StoreAs[core.SSFStore](w.Store)
	if !ok {
		return
	}
	now := w.Clock()
	if _, err := ss.PruneSSFOutbox(ctx, now.Add(-time.Hour), now.Add(-7*24*time.Hour), now.Add(-core.SSFOutboxRetention)); err != nil {
		w.Logger.Warn("ssf: prune failed")
	}
}

// Tick claims due rows and delivers them concurrently; it returns when this
// batch is done.
func (w *Worker) Tick(ctx context.Context) int {
	w.init()
	ss, ok := core.StoreAs[core.SSFStore](w.Store)
	if !ok {
		return 0
	}
	rows, err := ss.ClaimSSFOutbox(ctx, w.Clock(), w.Lease, w.Batch)
	if err != nil {
		if ctx.Err() == nil {
			w.Logger.Warn("ssf: claim failed")
		}
		return 0
	}
	var batch sync.WaitGroup
	for _, o := range rows {
		batch.Add(1)
		w.wg.Add(1)
		go func(o core.SSFOutbox) {
			defer batch.Done()
			defer w.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					w.Logger.Error("ssf: panic in delivery", "realm", o.Realm)
				}
			}()
			w.deliver(ss, o)
		}(o)
	}
	batch.Wait()
	return len(rows)
}

func (w *Worker) finish(ss core.SSFStore, o core.SSFOutbox, retry bool, outcome string) {
	state, next := core.SSFOutboxPending, time.Time{}
	attempt := o.Attempts + 1
	switch {
	case outcome == "ok":
		state = core.SSFOutboxDelivered
	case !retry || attempt >= w.MaxAttempts || w.Clock().Sub(o.CreatedAt) > core.SSFOutboxRetention:
		state = core.SSFOutboxDead
	default:
		d := w.Backoff
		for i := 1; i < attempt && d < w.MaxBackoff; i++ {
			d *= 2
		}
		if d > w.MaxBackoff {
			d = w.MaxBackoff
		}
		next = w.Clock().Add(d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ss.FinishSSFOutbox(ctx, o.ID, state, next, outcome); err != nil && !errors.Is(err, idp.ErrNotFound) {
		w.Logger.Warn("ssf: record outcome failed", "realm", o.Realm)
	}
	w.Logger.Info("ssf: delivery", "realm", o.Realm, "stream", o.StreamID, "event", o.EventType, "outcome", outcome, "state", state, "attempt", attempt)
}

func (w *Worker) deliver(ss core.SSFStore, o core.SSFOutbox) {
	ctx, cancel := context.WithTimeout(context.Background(), w.Timeout)
	st, err := ss.GetSSFStream(ctx, o.Realm, o.StreamID)
	cancel()
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			w.finish(ss, o, false, "stream_gone")
		} else {
			w.finish(ss, o, true, "store_error")
		}
		return
	}
	if err := ValidateEndpoint(st.EndpointURL, w.AllowPrivate); err != nil {
		w.finish(ss, o, false, "bad_endpoint")
		return
	}
	var auth string
	if st.SealedAuth != "" {
		if w.Box == nil {
			w.finish(ss, o, true, "secret_key_missing")
			return
		}
		b, err := w.Box.Open(st.SealedAuth, SealContext(st.Realm, st.ID))
		if err != nil {
			w.finish(ss, o, false, "auth_unreadable")
			return
		}
		auth = string(b)
	}
	outcome, retry := w.post(st.EndpointURL, auth, o.SET)
	w.finish(ss, o, retry, outcome)
}

// SealContext is the secretbox context binding a sealed authorization header
// to its stream.
func SealContext(realm, streamID string) string { return "ssf|" + realm + "|" + streamID }

// post makes one attempt and returns an outcome label (never carrying URL or
// body text) and whether the failure is worth retrying. RFC 8935: 202 means
// accepted; 400 means the receiver rejected this SET (do not resend it).
func (w *Worker) post(target, auth, set string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), w.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(set))
	if err != nil {
		return "bad_request", false
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "haven-idp-ssf")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		if errors.Is(err, safehttp.ErrBlocked) {
			return "blocked_address", false
		}
		return "network_error", true
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		return "ok", false
	case code >= 500 || code == http.StatusTooManyRequests || code == http.StatusRequestTimeout ||
		code == http.StatusUnauthorized || code == http.StatusForbidden:
		return fmt.Sprintf("status_%d", code), true
	default:
		return fmt.Sprintf("status_%d", code), false
	}
}
