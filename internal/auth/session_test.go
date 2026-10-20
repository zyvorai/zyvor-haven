// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

func TestLabDemoEnabledOptIn(t *testing.T) {
	t.Setenv("HAVEN_LAB_LOGIN", "")
	if LabDemoEnabled() {
		t.Fatal("empty HAVEN_LAB_LOGIN must disable lab demo")
	}
	for _, v := range []string{"1", "true", "YES"} {
		t.Setenv("HAVEN_LAB_LOGIN", v)
		if !LabDemoEnabled() {
			t.Fatalf("%q should enable lab demo", v)
		}
	}
	t.Setenv("HAVEN_LAB_LOGIN", "0")
	if LabDemoEnabled() {
		t.Fatal("0 must disable lab demo")
	}
}

func TestMatchLabDemo(t *testing.T) {
	t.Setenv("HAVEN_LAB_LOGIN", "")
	if MatchLabDemo("demo", "demo") {
		t.Fatal("lab match must fail when disabled")
	}
	t.Setenv("HAVEN_LAB_LOGIN", "1")
	if !MatchLabDemo("demo", "demo") {
		t.Fatal("expected demo/demo to match when enabled")
	}
	if MatchLabDemo("admin", "admin") {
		t.Fatal("non-demo creds must not match lab")
	}
}

func TestExpiredSessionsAreRemoved(t *testing.T) {
	s := NewStoreFromEnv()
	s.ttl = -time.Second
	sess := s.Issue("u", "operator", "local")
	if _, ok := s.Get(sess.Token); ok {
		t.Fatal("expired session must not be returned")
	}
	s.mu.RLock()
	n := len(s.active)
	s.mu.RUnlock()
	if n != 0 {
		t.Fatalf("expired session still stored: %d", n)
	}
	s.Issue("a", "operator", "local")
	s.Issue("b", "operator", "local")
	s.mu.RLock()
	n = len(s.active)
	s.mu.RUnlock()
	if n != 1 {
		t.Fatalf("Issue should sweep expired sessions, have %d", n)
	}
}
