// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package bootstrap seeds a fresh haven-idp with a first realm, an admin user
// and the Haven console client. It is idempotent: existing objects are left
// untouched, so restarting never resets a changed password.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Options describes what to seed. Empty Realm disables bootstrapping.
type Options struct {
	Realm         string
	AdminUser     string
	AdminPassword string // never logged
	ConsoleClient string // client_id, default "haven-console"
	RedirectURIs  []string
	Origins       []string
}

// Result reports what was created so callers can log it (without secrets).
type Result struct {
	RealmCreated, UserCreated, ClientCreated bool
}

// Run seeds the store. A missing AdminPassword skips user creation.
func Run(ctx context.Context, st core.Store, h core.PasswordHasher, signer core.Signer, o Options) (Result, error) {
	var res Result
	if o.Realm == "" {
		return res, nil
	}
	realm := core.Realm{
		Name: o.Realm, DisplayName: "Private Cloud", Enabled: true,
		EmailVerificationRequired: false,
		BruteForceProtection:      true,
		TransportSecurity:         "external",
		PasswordPolicy:            "length(12)",
		AccessTokenTTL:            5 * time.Minute,
		RefreshTokenTTL:           30 * 24 * time.Hour,
		SessionIdleTTL:            30 * time.Minute,
		AuthEventsLogged:          true,
		AdminEventsLogged:         true,
		RefreshTokenRotation:      true,
	}
	switch err := st.CreateRealm(ctx, realm); {
	case err == nil:
		res.RealmCreated = true
	case errors.Is(err, idp.ErrConflict):
	default:
		return res, fmt.Errorf("create realm: %w", err)
	}
	if err := signer.EnsureKey(ctx, o.Realm); err != nil {
		return res, fmt.Errorf("ensure signing key: %w", err)
	}

	if o.AdminUser != "" && o.AdminPassword != "" {
		hash, err := h.Hash(o.AdminPassword)
		if err != nil {
			return res, fmt.Errorf("hash admin password: %w", err)
		}
		err = st.CreateUser(ctx, core.User{
			Realm: o.Realm, Username: o.AdminUser, Enabled: true, EmailVerified: true,
			PasswordHash: hash,
		})
		switch {
		case err == nil:
			res.UserCreated = true
		case errors.Is(err, idp.ErrConflict):
		default:
			return res, fmt.Errorf("create admin user: %w", err)
		}
	}

	if len(o.RedirectURIs) > 0 {
		id := o.ConsoleClient
		if id == "" {
			id = "haven-console"
		}
		err := st.CreateClient(ctx, core.Client{
			Realm: o.Realm, ClientID: id, Name: "Haven console", Enabled: true,
			Public: true, AuthCodeFlow: true, RequirePKCE: true,
			RedirectURIs: o.RedirectURIs, Origins: o.Origins,
		})
		switch {
		case err == nil:
			res.ClientCreated = true
		case errors.Is(err, idp.ErrConflict):
		default:
			return res, fmt.Errorf("create console client: %w", err)
		}
	}
	return res, nil
}
