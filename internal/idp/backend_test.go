// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import (
	"context"
	"testing"
)

type fakeProvider struct{ Provider }

func TestStaticBackend(t *testing.T) {
	p := &fakeProvider{}
	b := NewStaticBackend(p, "http://x", "svc")
	if b.Client() != Provider(p) {
		t.Fatal("client mismatch")
	}
	if u, usr := b.Config(); u != "http://x" || usr != "svc" {
		t.Fatalf("config %q %q", u, usr)
	}
	err := b.Reconfigure(context.Background(), "a", "b", "c")
	if err == nil || err.Error() != "backend is configured by the environment" {
		t.Fatalf("reconfigure: %v", err)
	}
}

func TestStaticBackendNil(t *testing.T) {
	b := NewStaticBackend(nil, "", "")
	if b.Client() != nil {
		t.Fatal("want true nil interface")
	}
}
