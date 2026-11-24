// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

// secretKeyFile holds the dev secretbox key inside the persistence directory.
// It must persist with the data: TOTP seeds and federation secrets in
// state.json are sealed with it and would be unreadable after a restart under
// a new per-process key.
const secretKeyFile = "secret.key"

// preparePersist validates the --persist directory (created 0700; an existing
// one must not be open to other users) and returns its absolute path and the
// secretbox key stored there, creating it (0600) on first use.
func preparePersist(dir string) (abs, key string, err error) {
	if abs, err = filepath.Abs(dir); err != nil {
		return "", "", err
	}
	if abs, err = memstore.EnsurePrivateDir(abs); err != nil {
		return "", "", fmt.Errorf("--persist %s: %w", dir, err)
	}
	kp := filepath.Join(abs, secretKeyFile)
	fi, err := os.Lstat(kp)
	switch {
	case err == nil:
		if !fi.Mode().IsRegular() {
			return "", "", fmt.Errorf("%s is not a regular file", kp)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return "", "", fmt.Errorf("%s is readable by other users (chmod 600 it)", kp)
		}
		b, err := os.ReadFile(kp) // #nosec G304 -- inside the operator-chosen persist dir
		if err != nil {
			return "", "", err
		}
		key = strings.TrimSpace(string(b))
		if _, err := secretbox.ParseKeys(key); err != nil {
			return "", "", fmt.Errorf("%s: %w", kp, err)
		}
		return abs, key, nil
	case errors.Is(err, os.ErrNotExist):
		key = secretbox.GenerateKey()
		if err := memstore.WriteFileAtomic(kp, []byte(key+"\n")); err != nil {
			return "", "", err
		}
		return abs, key, nil
	default:
		return "", "", err
	}
}

// syncDevPassword makes the persisted test user's password match the dev
// credentials (they differ after --reset-creds, or when state.json came from
// another machine). Only the dev test user is touched.
func syncDevPassword(ctx context.Context, st core.Store, h core.PasswordHasher, realm, user, pw string) error {
	u, err := st.GetUserByUsername(ctx, realm, user)
	if errors.Is(err, idp.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if ok, _ := h.Verify(pw, u.PasswordHash); ok {
		return nil
	}
	hash, err := h.Hash(pw)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	return st.UpdateUser(ctx, u)
}
