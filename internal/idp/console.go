// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import (
	"os"
	"strings"
)

// BootstrapRealm is the realm used for Haven console OIDC (default platform).
func BootstrapRealm() string {
	if v := strings.TrimSpace(os.Getenv("HAVEN_BOOTSTRAP_REALM")); v != "" {
		return v
	}
	return "platform"
}

// ConsoleClientID is the OIDC client id of the Haven console.
func ConsoleClientID() string {
	if v := strings.TrimSpace(os.Getenv("HAVEN_OIDC_CLIENT_ID")); v != "" {
		return v
	}
	return "haven-console"
}

// ConsoleRedirectURIs builds the redirect URIs for the console's public bases.
// Path wildcards (http://host:port/*) are allowed; host wildcards
// (http://*/*) are not.
func ConsoleRedirectURIs(consoleBases ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	defaults := []string{
		"http://localhost:30742",
		"http://localhost:8080",
		"http://127.0.0.1:30742",
		"http://127.0.0.1:8080",
	}
	bases := append([]string{}, consoleBases...)
	bases = append(bases, defaults...)
	for _, b := range bases {
		b = strings.TrimRight(strings.TrimSpace(b), "/")
		if b == "" {
			continue
		}
		add(b + "/*")
		add(b + "/api/v1/auth/oidc/callback")
	}
	return out
}
