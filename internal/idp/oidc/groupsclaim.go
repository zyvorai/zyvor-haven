// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/zyvorai/haven/internal/idp/core"
)

// The `groups` claim in ID tokens (docs/kubernetes-login.md). It is emitted
// only when BOTH hold:
//
//   - the operator opted the client in (GroupsClaimPolicy, from
//     HAVEN_IDP_GROUPS_CLAIM_CLIENTS), and
//   - the grant carries the "groups" scope.
//
// Off by default: with no policy, no token ever carries the claim. Membership
// is read from the user at every issue, so a refresh reflects changes.

func init() {
	knownScopes = append(knownScopes, core.GroupsScope)
	// What the device approval and consent pages tell the user.
	scopeWords[core.GroupsScope] = "See which groups you belong to"
	scopeDesc[core.GroupsScope] = "read which groups you belong to"
	registerDiscovery(func(p *Provider, realm string, doc map[string]any) {
		if !p.cfg.GroupsClaim.anyIn(realm) {
			return
		}
		for key, v := range map[string]string{"scopes_supported": core.GroupsScope, "claims_supported": core.GroupsScope} {
			if l, ok := doc[key].([]string); ok && !slices.Contains(l, v) {
				doc[key] = append(slices.Clone(l), v)
			}
		}
	})
}

type groupsClient struct{ realm, clientID string }

// GroupsClaimPolicy lists the clients that may receive the `groups` claim.
// A nil policy allows none.
type GroupsClaimPolicy struct {
	clients map[groupsClient]bool
}

var (
	groupsRealmRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	groupsClientRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)
)

// ParseGroupsClaimClients parses "realm/clientId[,realm/clientId...]". An
// empty string returns (nil, nil): the feature stays off. A malformed entry is
// an error, so a typo stops the server instead of silently dropping access.
func ParseGroupsClaimClients(s string) (*GroupsClaimPolicy, error) {
	var pol *GroupsClaimPolicy
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		realm, id, ok := strings.Cut(e, "/")
		if !ok || !groupsRealmRE.MatchString(realm) || !groupsClientRE.MatchString(id) {
			return nil, fmt.Errorf("groups claim clients: %q is not realm/clientId", e)
		}
		if pol == nil {
			pol = &GroupsClaimPolicy{clients: map[groupsClient]bool{}}
		}
		pol.clients[groupsClient{realm, id}] = true
	}
	return pol, nil
}

// Allowed reports whether the client was opted in. Safe on a nil policy.
func (g *GroupsClaimPolicy) Allowed(realm, clientID string) bool {
	return g != nil && g.clients[groupsClient{realm, clientID}]
}

func (g *GroupsClaimPolicy) anyIn(realm string) bool {
	if g == nil {
		return false
	}
	for k := range g.clients {
		if k.realm == realm {
			return true
		}
	}
	return false
}

// addGroupsClaim puts `groups` into ID token claims when the client is opted
// in and the scope was granted. The claim is then always present (possibly
// empty), sorted and free of duplicates and reserved names.
func (p *Provider) addGroupsClaim(realm string, cl core.Client, u core.User, scopes []string, idc core.Claims) {
	if !slices.Contains(scopes, core.GroupsScope) || !p.cfg.GroupsClaim.Allowed(realm, cl.ClientID) {
		return
	}
	groups := []string{}
	for _, path := range u.Groups {
		if v, ok := core.GroupClaimValue(path); ok {
			groups = append(groups, v)
		}
	}
	slices.Sort(groups)
	idc[core.GroupsScope] = slices.Compact(groups)
}
