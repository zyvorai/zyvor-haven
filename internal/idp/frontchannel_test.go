// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import (
	"strings"
	"testing"
)

func TestWebOrigin(t *testing.T) {
	for raw, want := range map[string]string{
		"https://App.Example/cb?x=1":    "https://app.example",
		"https://app.example:443/cb":    "https://app.example",
		"http://localhost:80/cb":        "http://localhost",
		"http://localhost:8080/cb":      "http://localhost:8080",
		"https://app.example:8443":      "https://app.example:8443",
		"https://127.0.0.1:9/x":         "https://127.0.0.1:9",
		"https://app.example:80/x":      "https://app.example:80",
		"https://xn--bcher-kva.example": "https://xn--bcher-kva.example",
	} {
		got, err := WebOrigin(raw)
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", raw, got, err, want)
		}
	}
	// Anything that could change the meaning of a policy, or that a source
	// expression cannot express, is refused.
	for _, raw := range []string{
		"https://a.example;script-src/x", "https://a.example,b.example/x", "https://*.example/x", "https://*/x",
		"https://a_b.example/x", "https://[::1]/x", "https://bücher.example/x", "https://a.example./x",
		"https://a.example:0/x", "https://a.example:70000/x", "https://user@a.example/x", "ftp://a.example/x",
		"data:text/html,x", "com.example.app:/cb", "//a.example/x", "https:///x", "https://'self'/x",
		"https://a.example%3b/x", "https://a=b.example/x", "https://" + strings.Repeat("a.", 140) + "example/x",
	} {
		if got, err := WebOrigin(raw); err == nil {
			t.Errorf("%s accepted as %q", raw, got)
		}
	}
}

func TestFrontchannelOrigin(t *testing.T) {
	redirects := []string{"com.example.app:/cb", "https://app.example/cb", "http://localhost:3000/cb"}
	for _, ok := range []string{"https://app.example/logout", "https://app.example:443/logout?x=1", "http://localhost:3000/fc",
		"HTTPS://APP.EXAMPLE/logout"} {
		if _, err := FrontchannelOrigin(ok, redirects); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for name, bad := range map[string]string{
		"other host":       "https://evil.example/logout",
		"other port":       "https://app.example:8443/logout",
		"other scheme":     "http://app.example/logout",
		"loopback port":    "http://localhost:3001/fc",
		"http not local":   "http://app.example/fc",
		"fragment":         "https://app.example/fc#x",
		"credentials":      "https://u:p@app.example/fc",
		"space":            "https://app.example/f c",
		"newline":          "https://app.example/fc\r\nX: y",
		"backslash":        `https://app.example\@evil.example/fc`,
		"empty":            "",
		"relative":         "/fc",
		"custom":           "com.example.app:/fc",
		"suffix lookalike": "https://app.example.evil.example/fc",
		"too long":         "https://app.example/" + strings.Repeat("a", MaxLogoutURILen),
	} {
		if o, err := FrontchannelOrigin(bad, redirects); err == nil {
			t.Errorf("%s accepted (%s)", name, o)
		}
	}
	if _, err := FrontchannelOrigin("https://app.example/fc", nil); err == nil {
		t.Error("accepted without any redirect URI")
	}
}
