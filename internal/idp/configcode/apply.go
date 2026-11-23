// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
)

// applyError carries a message that has been scrubbed of secrets while still
// unwrapping to the provider's error for errors.Is/As.
type applyError struct {
	msg string
	err error
}

func (e *applyError) Error() string { return e.msg }
func (e *applyError) Unwrap() error { return e.err }

// Apply executes plan.Changes in order and stops at the first error, returning
// the result so far (never nil) alongside it. "Already exists" on create and
// "not found" on delete are treated as success (races). Roles and groups are
// never deleted (idp.Provider cannot), and built-in/admin clients are never
// deleted even if a plan names them.
func Apply(ctx context.Context, p idp.Provider, plan *Plan, desired *Spec) (*ApplyResult, error) {
	res := &ApplyResult{Applied: []Change{}, NewSecrets: map[string]string{}}
	d := normalized(desired)
	realm := plan.Realm
	clients := map[string]Client{}
	for _, c := range d.Clients {
		clients[c.ClientID] = c
	}
	roles := map[string]Role{}
	for _, r := range d.Roles {
		roles[r.Name] = r
	}
	redact := func(err error) error {
		msg := err.Error()
		for _, s := range res.NewSecrets {
			if s != "" {
				msg = strings.ReplaceAll(msg, s, "[redacted]")
			}
		}
		return &applyError{msg: msg, err: err}
	}
	for _, ch := range plan.Changes {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := applyOne(ctx, p, realm, ch, d, clients, roles, res); err != nil {
			return res, redact(fmt.Errorf("apply %s %s %q: %w", ch.Action, ch.Kind, ch.Name, err))
		}
		res.Applied = append(res.Applied, ch)
	}
	return res, nil
}

func applyOne(ctx context.Context, p idp.Provider, realm string, ch Change, d *Spec, clients map[string]Client, roles map[string]Role, res *ApplyResult) error {
	switch {
	case ch.Kind == KindOfRealm && ch.Action == ActionCreate:
		return ignoreConflict(p.CreateRealm(ctx, newRealm(d)))
	case ch.Kind == KindOfRealm && ch.Action == ActionUpdate:
		cur, err := p.GetRealm(ctx, realm)
		if err != nil {
			return err
		}
		if cur == nil {
			return idp.ErrNotFound
		}
		merged := *cur
		mergeRealm(&merged, d)
		return p.UpdateRealm(ctx, realm, merged)
	case ch.Kind == KindOfRole && ch.Action == ActionCreate:
		return ignoreConflict(p.CreateRole(ctx, realm, idp.Role{Name: ch.Name, Description: roles[ch.Name].Description}))
	case ch.Kind == KindOfGroup && ch.Action == ActionCreate:
		return ignoreConflict(p.CreateGroup(ctx, realm, idp.Group{Name: ch.Name}))
	case ch.Kind == KindOfClient && ch.Action == ActionCreate:
		c, ok := clients[ch.Name]
		if !ok {
			return fmt.Errorf("client %q is not in the desired spec", ch.Name)
		}
		return createClient(ctx, p, realm, c, res)
	case ch.Kind == KindOfClient && ch.Action == ActionUpdate:
		c, ok := clients[ch.Name]
		if !ok {
			return fmt.Errorf("client %q is not in the desired spec", ch.Name)
		}
		cur, err := findClient(ctx, p, realm, ch.Name)
		if err != nil {
			return err
		}
		if cur == nil {
			return idp.ErrNotFound
		}
		return p.UpdateClient(ctx, realm, cur.ID, mergeClient(*cur, c))
	case ch.Kind == KindOfClient && ch.Action == ActionDelete:
		if isUnmanagedClient(ch.Name) {
			return fmt.Errorf("refusing to delete protected client %q", ch.Name)
		}
		cur, err := findClient(ctx, p, realm, ch.Name)
		if err != nil {
			return err
		}
		if cur == nil {
			return nil
		}
		err = p.DeleteClient(ctx, realm, cur.ID)
		if errors.Is(err, idp.ErrNotFound) {
			return nil
		}
		return err
	}
	return fmt.Errorf("unsupported change %s %s", ch.Action, ch.Kind)
}

func ignoreConflict(err error) error {
	if errors.Is(err, idp.ErrConflict) {
		return nil
	}
	return err
}

func findClient(ctx context.Context, p idp.Provider, realm, clientID string) (*idp.Client, error) {
	list, err := p.ListClients(ctx, realm)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ClientID == clientID {
			return &list[i], nil
		}
	}
	return nil, nil
}

// newRealm builds the realm for creation: managed fields as given, brute-force
// protection on unless stated, other unmanaged hardening left for the backend's
// secure defaults.
func newRealm(d *Spec) idp.Realm {
	r := idp.Realm{Realm: d.Realm, Enabled: true, BruteForceProtected: true}
	mergeRealm(&r, d)
	return r
}

// mergeRealm overlays only the managed (non-nil) settings of d onto r.
func mergeRealm(r *idp.Realm, d *Spec) {
	if d.DisplayName != "" {
		r.DisplayName = d.DisplayName
	}
	if d.Enabled != nil {
		r.Enabled = *d.Enabled
	}
	s := d.Settings
	if s.SelfRegistration != nil {
		r.RegistrationAllowed = *s.SelfRegistration
	}
	if s.EmailVerificationRequired != nil {
		r.VerifyEmail = *s.EmailVerificationRequired
	}
	if s.BruteForceProtection != nil {
		r.BruteForceProtected = *s.BruteForceProtection
	}
	if s.TransportSecurity == nil && s.PasswordPolicy == nil && s.AccessTokenSeconds == nil &&
		s.SessionIdleSeconds == nil && s.AuthEvents == nil && s.AdminEvents == nil && s.RefreshTokenRotation == nil {
		return
	}
	h := idp.RealmHardening{}
	if r.RealmHardening != nil {
		h = *r.RealmHardening // copy: never mutate the caller's value
	}
	if s.TransportSecurity != nil {
		h.SSLRequired = cp(s.TransportSecurity)
	}
	if s.PasswordPolicy != nil {
		h.PasswordPolicy = cp(s.PasswordPolicy)
	}
	if s.AccessTokenSeconds != nil {
		h.AccessTokenLifespan = cp(s.AccessTokenSeconds)
	}
	if s.SessionIdleSeconds != nil {
		h.SSOSessionIdleTimeout = cp(s.SessionIdleSeconds)
	}
	if s.AuthEvents != nil {
		h.EventsEnabled = cp(s.AuthEvents)
	}
	if s.AdminEvents != nil {
		h.AdminEventsEnabled = cp(s.AdminEvents)
	}
	if s.RefreshTokenRotation != nil {
		h.RevokeRefreshToken = cp(s.RefreshTokenRotation)
	}
	r.RealmHardening = &h
}

func cp[T any](p *T) *T { v := *p; return &v }

// mergeClient overlays the declared fields of a normalized desired client on
// the live client, keeping everything the spec does not model.
func mergeClient(cur idp.Client, c Client) idp.Client {
	cur.Name = c.Name
	cur.Enabled = *c.Enabled
	cur.PublicClient = c.Public
	cur.ServiceAccountsEnabled = c.ServiceAccount
	cur.StandardFlowEnabled = *c.AuthCodeFlow
	cur.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	cur.WebOrigins = append([]string(nil), c.Origins...)
	attrs := make(map[string]string, len(cur.Attributes)+1)
	for k, v := range cur.Attributes {
		attrs[k] = v
	}
	if *c.RequirePKCE {
		attrs[pkceAttr] = "S256"
	} else {
		delete(attrs, pkceAttr)
	}
	if len(attrs) == 0 {
		attrs = nil
	}
	cur.Attributes = attrs
	cur.Secret = ""
	return cur
}

func createClient(ctx context.Context, p idp.Provider, realm string, c Client, res *ApplyResult) error {
	cl := mergeClient(idp.Client{ClientID: c.ClientID, Protocol: "openid-connect"}, c)
	if c.Public {
		return ignoreConflict(p.CreateClient(ctx, realm, cl))
	}
	if sc, ok := p.(idp.SecretCreator); ok {
		_, secret, err := sc.CreateClientWithSecret(ctx, realm, cl)
		if err != nil {
			return ignoreConflict(err)
		}
		if secret != "" {
			res.NewSecrets[c.ClientID] = secret
		}
		return nil
	}
	if err := p.CreateClient(ctx, realm, cl); err != nil {
		return ignoreConflict(err)
	}
	// Providers that can read secrets back (Keycloak): fetch it now. Failure
	// here is not fatal; the secret remains retrievable from the provider.
	if cur, err := findClient(ctx, p, realm, c.ClientID); err == nil && cur != nil {
		if s, err := p.GetClientSecret(ctx, realm, cur.ID); err == nil && s != nil && s.Value != "" {
			res.NewSecrets[c.ClientID] = s.Value
		}
	}
	return nil
}
