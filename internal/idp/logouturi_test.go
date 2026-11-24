// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import (
	"strings"
	"testing"
)

func TestValidateLogoutURI(t *testing.T) {
	ok := []string{
		"https://app.example.com/logout",
		"https://app.example.com:8443/bc?x=1",
		"http://localhost/logout",
		"http://localhost:3000/logout",
		"http://127.0.0.1:8080/x",
		"http://[::1]:8080/x",
		"HTTPS://App.Example.com/x",
	}
	for _, u := range ok {
		if err := ValidateLogoutURI(u); err != nil {
			t.Errorf("%q rejected: %v", u, err)
		}
	}
	bad := []string{
		"", "http://app.example.com/logout", "http://10.0.0.1/x", "ftp://a.example.com/x",
		"javascript:alert(1)", "https://user:pw@app.example.com/x", "https:///x", "https://",
		"/relative", "https://app.example.com/x#frag", "https://app.example.com/x#",
		"https://app.example.com/\nx", "https://app.example.com/\x00", "https://app.exa mple.com/",
		"https://app.example.com/" + strings.Repeat("a", 2048),
	}
	for _, u := range bad {
		if err := ValidateLogoutURI(u); err == nil {
			t.Errorf("%.60q accepted", u)
		}
	}
}
