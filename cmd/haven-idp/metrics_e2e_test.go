// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/password"
)

func TestServeMetricsListenerEndToEnd(t *testing.T) {
	ready := make(chan string, 1)
	mready := make(chan string, 1)
	addr := listenFree(t)
	cfg := Config{
		Listen: addr, BaseURL: "http://" + addr, Memory: true, CSRFKey: "k",
		BootstrapRealm: "demo", BootstrapUser: "demo", BootstrapPassword: "a-long-enough-pw-1",
		AdminClientSecret: "admin-secret-admin-secret-admin-secret", PasswordParams: password.TestParams,
		MetricsListen:  "127.0.0.1:0",
		OnReady:        func(a string) { ready <- a },
		OnMetricsReady: func(a string) { mready <- a },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg) }()
	var maddr string
	select {
	case maddr = <-mready:
	case err := <-done:
		t.Fatalf("serve exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("metrics listener never became ready")
	}
	<-ready

	// Generate traffic, including a 404 with a hostile path.
	for _, p := range []string{"/healthz", "/readyz", "/hostile/path/alice?password=pw"} {
		r, err := http.Get(cfg.BaseURL + p)
		if err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("X-Request-Id") == "" || r.Header.Get("Traceparent") == "" {
			t.Errorf("%s: missing request id / traceparent", p)
		}
		_ = r.Body.Close()
	}

	resp, err := http.Get("http://" + maddr + "/metrics")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("scrape: %v %v", resp, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	out := string(b)
	for _, want := range []string{
		`haven_idp_http_requests_total{code="200",method="GET",route="/healthz"} 1`,
		`route="unmatched"`, "haven_idp_store_up 1", "haven_idp_signing_key_age_seconds{realm=\"demo\"}", "haven_idp_build_info",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
	for _, bad := range []string{"hostile", "alice", "password"} {
		if strings.Contains(out, bad) {
			t.Errorf("scrape leaks %q", bad)
		}
	}
	// The metrics listener serves only /metrics; the main one does not serve it.
	if r, err := http.Get("http://" + maddr + "/healthz"); err == nil {
		if r.StatusCode != 404 {
			t.Errorf("metrics listener served /healthz: %d", r.StatusCode)
		}
		_ = r.Body.Close()
	}
	if r, err := http.Get(cfg.BaseURL + "/metrics"); err == nil {
		if r.StatusCode == 200 {
			t.Error("main listener must not serve /metrics unless MetricsOnMain")
		}
		_ = r.Body.Close()
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not shut down")
	}
}
