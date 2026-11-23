// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var realmNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Validate returns every problem in the spec (errors.Join), each naming its
// field path such as clients[2].redirectUris[0].
func (s *Spec) Validate() error {
	var errs []error
	add := func(path, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, a...)))
	}
	if s.APIVersion != APIVersion {
		add("apiVersion", "must be %q, got %q", APIVersion, s.APIVersion)
	}
	if s.Kind != KindRealm {
		add("kind", "must be %q, got %q", KindRealm, s.Kind)
	}
	if !realmNameRE.MatchString(s.Realm) {
		add("realm", "must match %s", realmNameRE)
	}
	st := s.Settings
	if st.TransportSecurity != nil {
		switch *st.TransportSecurity {
		case "none", "external", "all":
		default:
			add("settings.transportSecurity", "must be none, external or all, got %q", *st.TransportSecurity)
		}
	}
	if st.AccessTokenSeconds != nil && *st.AccessTokenSeconds <= 0 {
		add("settings.accessTokenSeconds", "must be positive")
	}
	if st.SessionIdleSeconds != nil && *st.SessionIdleSeconds <= 0 {
		add("settings.sessionIdleSeconds", "must be positive")
	}
	seen := map[string]int{}
	for i, r := range s.Roles {
		p := fmt.Sprintf("roles[%d].name", i)
		if r.Name == "" {
			add(p, "is required")
		} else if j, ok := seen[r.Name]; ok {
			add(p, "duplicate of roles[%d]", j)
		} else {
			seen[r.Name] = i
		}
	}
	seen = map[string]int{}
	for i, g := range s.Groups {
		p := fmt.Sprintf("groups[%d].name", i)
		if g.Name == "" {
			add(p, "is required")
		} else if j, ok := seen[g.Name]; ok {
			add(p, "duplicate of groups[%d]", j)
		} else {
			seen[g.Name] = i
		}
	}
	seen = map[string]int{}
	for i, c := range s.Clients {
		p := fmt.Sprintf("clients[%d]", i)
		if c.ClientID == "" {
			add(p+".clientId", "is required")
		} else if j, ok := seen[c.ClientID]; ok {
			add(p+".clientId", "duplicate of clients[%d]", j)
		} else {
			seen[c.ClientID] = i
		}
		if c.Public && c.ServiceAccount {
			add(p+".serviceAccount", "a service account client cannot be public")
		}
		if c.Public && c.RequirePKCE != nil && !*c.RequirePKCE {
			add(p+".requirePKCE", "PKCE cannot be disabled for a public client")
		}
		for j, u := range c.RedirectURIs {
			if msg := checkURL(u, true); msg != "" {
				add(fmt.Sprintf("%s.redirectUris[%d]", p, j), "%s", msg)
			}
		}
		for j, u := range c.Origins {
			if msg := checkURL(u, false); msg != "" {
				add(fmt.Sprintf("%s.origins[%d]", p, j), "%s", msg)
			}
		}
	}
	return errors.Join(errs...)
}

// checkURL returns a problem description, or "" when raw is acceptable: no
// wildcards, https, or http only for loopback hosts.
func checkURL(raw string, allowPath bool) string {
	if raw == "" {
		return "must not be empty"
	}
	if strings.Contains(raw, "*") {
		return "wildcards are not allowed"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "must be an absolute http(s) URL"
	}
	switch u.Scheme {
	case "https":
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			return "http is only allowed for loopback hosts; use https"
		}
	default:
		return "scheme must be https (or http for loopback)"
	}
	if !allowPath && ((u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "") {
		return "must be an origin without path, query or fragment"
	}
	return ""
}
