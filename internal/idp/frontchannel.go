// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// cspHostRE is the host grammar a Content-Security-Policy source expression
// can express: DNS labels and IPv4 addresses. Nothing it accepts can end the
// directive or add a source (no spaces, ';', ',', quotes or wildcards).
var cspHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// WebOrigin returns the normalised scheme://host[:port] of an http(s) URL
// whose host can be written in a CSP source expression, or an error. Default
// ports are dropped.
func WebOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil {
		return "", errors.New("not a web URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", errors.New("not a web URL")
	}
	host := strings.ToLower(u.Hostname())
	if len(host) > 253 || !cspHostRE.MatchString(host) {
		return "", errors.New("the host cannot be used in a content security policy (use a DNS name or an IPv4 address)")
	}
	o := scheme + "://" + host
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid port")
		}
		if (scheme != "https" || n != 443) && (scheme != "http" || n != 80) {
			o += ":" + strconv.Itoa(n)
		}
	}
	return o, nil
}

// FrontchannelOrigin validates a client's frontchannel_logout_uri against its
// registered redirect URIs and returns the URI's origin. The URI follows the
// logout URL policy (https, or http for loopback; no credentials or fragment)
// and its scheme, host and port must equal those of a redirect URI (OIDC
// Front-Channel Logout 1.0, section 2).
func FrontchannelOrigin(uri string, redirectURIs []string) (string, error) {
	if ValidateLogoutURI(uri) != nil || strings.ContainsAny(uri, " \\") {
		return "", errors.New("it must be an https URL (http for loopback) without credentials, fragment, spaces or control characters")
	}
	o, err := WebOrigin(uri)
	if err != nil {
		return "", err
	}
	for _, r := range redirectURIs {
		if ro, err := WebOrigin(r); err == nil && ro == o {
			return o, nil
		}
	}
	return "", errors.New("it must have the same scheme, host and port as one of the client's redirect URIs")
}
