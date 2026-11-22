// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keycloak

import (
	"strings"
	"testing"
)

func TestConsoleRedirectURIs(t *testing.T) {
	uris := ConsoleRedirectURIs("http://212.8.248.187:30742")
	want := []string{
		"http://212.8.248.187:30742/*",
		"http://212.8.248.187:30742/api/v1/auth/oidc/callback",
	}
	for _, w := range want {
		found := false
		for _, u := range uris {
			if u == w {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %q in %#v", w, uris)
		}
	}
	for _, u := range uris {
		if strings.Contains(u, "://*") {
			t.Fatalf("host wildcard not allowed: %s", u)
		}
	}
}

func TestMergeStringListDropsHostWildcards(t *testing.T) {
	got := mergeStringList(
		[]any{"http://*/*", "https://*/*", "http://old:1/*"},
		[]string{"http://new:30742/*"},
	)
	for _, u := range got {
		if strings.Contains(u, "://*") {
			t.Fatalf("host wildcard leaked: %s", u)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %#v", got)
	}
}
