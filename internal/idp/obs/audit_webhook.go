// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	webhookAttempts = 5
	webhookTimeout  = 10 * time.Second
	webhookMaxRead  = 4096
)

type webhookBackend struct {
	url     string
	secret  []byte
	client  *http.Client
	base    time.Duration
	timeout time.Duration
}

func newWebhookSink(raw string, opts AuditOptions, m *auditMetrics) (AuditSink, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("audit webhook: invalid url")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("audit webhook: https required (http only for loopback)")
	}
	if opts.WebhookSecret == "" {
		return nil, fmt.Errorf("audit webhook: HAVEN_IDP_AUDIT_WEBHOOK_SECRET is required")
	}
	cc := http.Client{}
	if opts.httpClient != nil {
		cc = *opts.httpClient
	}
	cc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base := opts.backoffBase
	if base <= 0 {
		base = 250 * time.Millisecond
	}
	linger := opts.linger
	if linger <= 0 {
		linger = auditLinger
	}
	be := &webhookBackend{url: u.String(), secret: []byte(opts.WebhookSecret), client: &cc, base: base, timeout: webhookTimeout}
	return newSink("webhook", opts, m, be, auditBatchMax, linger), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type permanentError struct{ error }

func (b *webhookBackend) send(ctx context.Context, lines [][]byte) error {
	body := append([]byte{'['}, bytes.Join(lines, []byte{','})...)
	body = append(body, ']')
	mac := hmac.New(sha256.New, b.secret)
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	idb := make([]byte, 16)
	_, _ = rand.Read(idb)
	id := hex.EncodeToString(idb)

	var last error
	for attempt := 0; attempt < webhookAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, b.backoff(attempt)); err != nil {
				return errors.Join(last, err)
			}
		}
		err := b.post(ctx, body, sig, id)
		if err == nil {
			return nil
		}
		var pe permanentError
		if errors.As(err, &pe) {
			return err
		}
		last = err
	}
	return fmt.Errorf("giving up after %d attempts: %w", webhookAttempts, last)
}

func (b *webhookBackend) post(ctx context.Context, body []byte, sig, id string) error {
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url, bytes.NewReader(body))
	if err != nil {
		return permanentError{err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Haven-Signature", sig)
	req.Header.Set("X-Haven-Delivery", id)
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, webhookMaxRead))
	_ = resp.Body.Close()
	switch c := resp.StatusCode; {
	case c >= 200 && c < 300:
		return nil
	case c == http.StatusTooManyRequests || c >= 500:
		return fmt.Errorf("webhook status %d", c)
	default: // 3xx (never followed) and other 4xx
		return permanentError{fmt.Errorf("webhook status %d", c)}
	}
}

// backoff is exponential with full jitter, capped at 10s.
func (b *webhookBackend) backoff(attempt int) time.Duration {
	d := b.base << (attempt - 1)
	if d > 10*time.Second || d <= 0 {
		d = 10 * time.Second
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)+1))
	if err != nil {
		return d
	}
	return time.Duration(n.Int64())
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *webhookBackend) close() error {
	b.client.CloseIdleConnections()
	return nil
}
