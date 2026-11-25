// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kubeauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
)

const pkceAttr = "pkce.code.challenge.method"

// ClientAPI is the part of the Admin API EnsureClient needs (idp.Provider and
// native.Client satisfy it).
type ClientAPI interface {
	ListClients(ctx context.Context, realm string) ([]idp.Client, error)
	CreateClient(ctx context.Context, realm string, c idp.Client) error
	UpdateClient(ctx context.Context, realm, id string, c idp.Client) error
}

// ClientSpec is the Kubernetes client: public, device flow, and the
// authorization code flow with PKCE when redirect URIs are given (for tools
// such as kubelogin).
type ClientSpec struct {
	ClientID  string
	Redirects []string
	// Update lets EnsureClient add what an existing public client is missing.
	Update bool
}

// Client actions.
const (
	ClientCreated   = "created"
	ClientUpdated   = "updated"
	ClientUnchanged = "unchanged"
)

// EnsureResult reports what EnsureClient did.
type EnsureResult struct {
	Action   string
	Changes  []string
	Warnings []string
}

// redirectWarnings flags redirect URIs of the client that leave the user's
// machine: whoever receives a code there gets tokens the cluster accepts.
func redirectWarnings(c idp.Client) []string {
	if !c.StandardFlowEnabled {
		return nil
	}
	var out []string
	for _, r := range c.RedirectURIs {
		if u, err := url.Parse(r); err != nil || !LoopbackHost(u.Hostname()) {
			out = append(out, "redirect URI "+printable(r, 200)+" is not on loopback: whoever receives codes there gets tokens the cluster accepts")
		}
	}
	return out
}

// ValidateRedirect allows https and loopback http redirect URIs, without
// wildcards, user info or fragment.
func ValidateRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Host == "" || u.User != nil || strings.ContainsAny(raw, "*# \t\r\n") ||
		(u.Scheme != "https" && (u.Scheme != "http" || !LoopbackHost(u.Hostname()))) {
		return fmt.Errorf("redirect URI %q must be https, or http on a loopback host, without wildcard or fragment", printable(raw, 200))
	}
	return nil
}

func (s ClientSpec) desired() idp.Client {
	return idp.Client{
		ClientID: s.ClientID, Name: "Kubernetes", Enabled: true, PublicClient: true, Protocol: "openid-connect",
		DeviceFlowEnabled: true, StandardFlowEnabled: len(s.Redirects) > 0, RedirectURIs: s.Redirects,
		Attributes: map[string]string{pkceAttr: "S256"},
	}
}

// EnsureClient creates the client, or checks that the existing one fits. It is
// idempotent. It never converts a confidential or service-account client and
// never enables a disabled one; it adds missing settings to a public client
// only with spec.Update, and never removes any.
func EnsureClient(ctx context.Context, api ClientAPI, realm string, spec ClientSpec) (EnsureResult, error) {
	if !clientIDRE.MatchString(spec.ClientID) {
		return EnsureResult{}, fmt.Errorf("invalid client id %q", spec.ClientID)
	}
	for _, r := range spec.Redirects {
		if err := ValidateRedirect(r); err != nil {
			return EnsureResult{}, err
		}
	}
	cur, err := findClient(ctx, api, realm, spec.ClientID)
	if err != nil {
		return EnsureResult{}, err
	}
	if cur == nil {
		err := api.CreateClient(ctx, realm, spec.desired())
		switch {
		case err == nil:
			return EnsureResult{Action: ClientCreated, Warnings: redirectWarnings(spec.desired())}, nil
		case !errors.Is(err, idp.ErrConflict):
			return EnsureResult{}, fmt.Errorf("create client %q: %w", spec.ClientID, err)
		}
		// Someone else created it meanwhile: judge what is there now.
		if cur, err = findClient(ctx, api, realm, spec.ClientID); err != nil {
			return EnsureResult{}, err
		}
		if cur == nil {
			return EnsureResult{}, fmt.Errorf("client %q: the server reports a conflict but does not list it", spec.ClientID)
		}
	}
	switch {
	case !cur.PublicClient || cur.ServiceAccountsEnabled || cur.BearerOnly:
		return EnsureResult{}, fmt.Errorf("client %q already exists and is confidential or a service account: it is not changed; pick another --client-id", spec.ClientID)
	case !cur.Enabled:
		return EnsureResult{}, fmt.Errorf("client %q already exists and is disabled: it is not enabled automatically", spec.ClientID)
	}
	next := *cur
	var changes []string
	if !next.DeviceFlowEnabled {
		next.DeviceFlowEnabled = true
		changes = append(changes, "enable the device flow")
	}
	next.RedirectURIs = slices.Clone(cur.RedirectURIs)
	for _, r := range spec.Redirects {
		if !slices.Contains(next.RedirectURIs, r) {
			next.RedirectURIs = append(next.RedirectURIs, r)
			changes = append(changes, "add redirect URI "+r)
		}
	}
	if len(spec.Redirects) > 0 && !next.StandardFlowEnabled {
		next.StandardFlowEnabled = true
		changes = append(changes, "enable the authorization code flow")
		if extra := len(cur.RedirectURIs); extra > 0 {
			changes = append(changes, fmt.Sprintf("(its %d redirect URIs already registered become usable too: review them)", extra))
		}
	}
	if next.StandardFlowEnabled && next.Attributes[pkceAttr] != "S256" {
		next.Attributes = map[string]string{pkceAttr: "S256"}
		changes = append(changes, "require PKCE S256")
	}
	if len(changes) == 0 {
		return EnsureResult{Action: ClientUnchanged, Warnings: redirectWarnings(next)}, nil
	}
	if !spec.Update {
		return EnsureResult{Changes: changes}, fmt.Errorf("client %q exists but differs (%s): pass --update-client to make these changes", spec.ClientID, strings.Join(changes, "; "))
	}
	if err := api.UpdateClient(ctx, realm, cur.ID, next); err != nil {
		return EnsureResult{}, fmt.Errorf("update client %q: %w", spec.ClientID, err)
	}
	return EnsureResult{Action: ClientUpdated, Changes: changes, Warnings: redirectWarnings(next)}, nil
}

func findClient(ctx context.Context, api ClientAPI, realm, clientID string) (*idp.Client, error) {
	all, err := api.ListClients(ctx, realm)
	if err != nil {
		return nil, fmt.Errorf("list clients of realm %q: %w", realm, err)
	}
	for i := range all {
		if all[i].ClientID == clientID {
			return &all[i], nil
		}
	}
	return nil, nil
}
