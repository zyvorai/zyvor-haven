// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/zyvorai/haven/internal/keychain"
)

// Optional macOS Keychain sources for the two secrets worth keeping out of
// files. They are opt-in per secret:
//
//	HAVEN_IDP_SECRET_KEY_KEYCHAIN=<item>   HAVEN_IDP_SECRET_KEY comes from this Keychain item
//	HAVEN_IDP_DB_PASSWORD_KEYCHAIN=<item>  the PostgreSQL password is added to HAVEN_IDP_DSN
//
// <item> is the Keychain "service" name (the account is always "haven-idp");
// the value 1 selects the default names below. The item is created with
//
//	security add-generic-password -s haven-idp.secret-key -a haven-idp -w
//
// (-w last, so `security` prompts and the secret never reaches argv or shell
// history). When the item is configured and found it wins; when it is not
// (not macOS, item missing, Keychain locked) the env/file value is used and a
// warning without any secret is printed. Values are never logged.
const (
	keychainAccount       = "haven-idp"
	defaultSecretKeyItem  = "haven-idp.secret-key"
	defaultDBPasswordItem = "haven-idp.db-password"
	envSecretKeyKeychain  = "HAVEN_IDP_SECRET_KEY_KEYCHAIN"
	envDBPasswordKeychain = "HAVEN_IDP_DB_PASSWORD_KEYCHAIN"
)

// keychainReader is the part of *keychain.Client this file needs.
type keychainReader interface {
	Available() bool
	Get(ctx context.Context, service, account string) (string, error)
}

func keychainItem(v, def string) string {
	v = strings.TrimSpace(v)
	if v == "1" || strings.EqualFold(v, "true") {
		return def
	}
	return v
}

// applyKeychain overlays Keychain secrets onto cfg. It returns an error only
// for a value that exists but is unusable; a missing source falls back.
func applyKeychain(ctx context.Context, cfg *Config, getenv func(string) string, kc keychainReader, warn io.Writer) error {
	get := func(envName, def, what string) (string, bool) {
		item := keychainItem(getenv(envName), def)
		if item == "" {
			return "", false
		}
		if !kc.Available() {
			fmt.Fprintf(warn, "haven-idp: warning: %s is set but the macOS Keychain is not available; using the env/file value for the %s\n", envName, what)
			return "", false
		}
		v, err := kc.Get(ctx, item, keychainAccount)
		switch {
		case errors.Is(err, keychain.ErrNotFound):
			fmt.Fprintf(warn, "haven-idp: warning: Keychain item %q (account %q) not found; using the env/file value for the %s\n", item, keychainAccount, what)
			return "", false
		case err != nil:
			fmt.Fprintf(warn, "haven-idp: warning: cannot read Keychain item %q (%v); using the env/file value for the %s\n", item, err, what)
			return "", false
		}
		v = strings.TrimSpace(v)
		if v == "" {
			fmt.Fprintf(warn, "haven-idp: warning: Keychain item %q is empty; using the env/file value for the %s\n", item, what)
			return "", false
		}
		return v, true
	}
	if v, ok := get(envSecretKeyKeychain, defaultSecretKeyItem, "secret key"); ok {
		cfg.SecretKey = v
	}
	if v, ok := get(envDBPasswordKeychain, defaultDBPasswordItem, "database password"); ok {
		if cfg.DSN == "" {
			return fmt.Errorf("%s needs HAVEN_IDP_DSN (without the password) to be set", envDBPasswordKeychain)
		}
		dsn, err := dsnWithPassword(cfg.DSN, v)
		if err != nil {
			return err
		}
		cfg.DSN = dsn
	}
	return nil
}

// dsnWithPassword adds pw to a PostgreSQL DSN. A password already present in
// the DSN is kept: an explicit value wins over the injected one.
func dsnWithPassword(dsn, pw string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", errors.New("HAVEN_IDP_DSN is not a valid URL") // never echo: it may hold a password
		}
		if u.User != nil {
			if _, has := u.User.Password(); has {
				return dsn, nil
			}
			u.User = url.UserPassword(u.User.Username(), pw)
		} else {
			u.User = url.UserPassword("", pw)
		}
		return u.String(), nil
	}
	if strings.Contains(dsn, "://") {
		return "", errors.New("HAVEN_IDP_DSN must be a postgres:// URL or key=value pairs")
	}
	for _, f := range strings.Fields(dsn) {
		if strings.HasPrefix(f, "password=") {
			return dsn, nil
		}
	}
	esc := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(pw)
	return strings.TrimSpace(dsn) + " password='" + esc + "'", nil
}

// osKeychain is replaced by tests.
var osKeychain keychainReader = keychain.New()

func applyOSKeychain(cfg *Config) error {
	return applyKeychain(context.Background(), cfg, os.Getenv, osKeychain, os.Stderr)
}
