// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"strings"
	"unicode"
)

// The `groups` claim (Kubernetes and other relying parties; see
// docs/kubernetes-login.md). The identity server and the generator of
// Kubernetes RoleBindings must agree on the exact string a group becomes, so
// both use GroupClaimValue.
const (
	// GroupsScope is the scope a client requests to get the claim.
	GroupsScope = "groups"
	// ReservedGroupPrefix is Kubernetes' reserved namespace for users and
	// groups ("system:masters" is cluster-admin). haven-idp never emits a
	// group in it, whatever prefix the relying party adds or forgets to add.
	ReservedGroupPrefix = "system:"
)

// GroupClaimValue maps a group path ("/eng/dev") to its value in the `groups`
// claim ("eng/dev"): the path without its leading slash, which keeps it unique
// within a realm. It reports false for anything that must not be emitted: a
// string that is not a group path, an empty name, surrounding white space,
// control or invisible format characters, and names in the reserved "system:"
// namespace (compared case-insensitively).
func GroupClaimValue(path string) (string, bool) {
	v, ok := strings.CutPrefix(path, "/")
	if !ok || v == "" || strings.TrimSpace(v) != v || strings.HasPrefix(v, "/") || strings.HasSuffix(v, "/") {
		return "", false
	}
	if strings.IndexFunc(v, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar
	}) >= 0 {
		return "", false
	}
	if strings.HasPrefix(strings.ToLower(v), ReservedGroupPrefix) {
		return "", false
	}
	return v, true
}
