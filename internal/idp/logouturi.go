// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// MaxLogoutURILen bounds a back-channel logout URL.
const MaxLogoutURILen = 2048

// ValidateLogoutURI is the syntactic policy for a client's back-channel logout
// URL: at most 2048 characters, no control characters, parseable, no userinfo,
// a non-empty host, no fragment, https (http only for localhost or a loopback
// IP literal, for development). It never resolves DNS; the dial-time SSRF
// policy lives in the back-channel notifier. The empty string is not valid
// here: callers treat empty as "not configured" before calling.
func ValidateLogoutURI(raw string) error {
	if raw == "" {
		return errors.New("back-channel logout URL is empty")
	}
	if len(raw) > MaxLogoutURILen {
		return fmt.Errorf("back-channel logout URL exceeds %d characters", MaxLogoutURILen)
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return errors.New("back-channel logout URL contains control characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("back-channel logout URL is not a valid URL")
	}
	if u.User != nil {
		return errors.New("back-channel logout URL must not contain credentials")
	}
	if u.Hostname() == "" {
		return errors.New("back-channel logout URL needs a host")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("back-channel logout URL must not contain a fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return errors.New("back-channel logout URL must use https (http is allowed only for localhost or loopback addresses)")
		}
	default:
		return errors.New("back-channel logout URL must use https")
	}
	return nil
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
