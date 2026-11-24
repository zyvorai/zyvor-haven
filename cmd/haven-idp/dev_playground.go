// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/zyvorai/haven/internal/idp/devui"
)

// The playground is part of `haven-idp dev` only: serve never mounts it.
func init() {
	playgroundHandler = func(issuer, clientID string) http.Handler {
		return devui.New(devui.Config{Issuer: issuer, ClientID: clientID, AdminSecret: devAdminSecret})
	}
}

// devAdminSecret reads the dev admin secret from the same 0600 file `dev`
// wrote at startup, so the add-an-app backend can hold it server-side without
// the playground (or dev.go) ever handing it to the browser.
func devAdminSecret() (string, error) {
	path, err := devCredsPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path) // #nosec G304 -- fixed per-user path
	if err != nil {
		return "", err
	}
	var c devCreds
	if err := json.Unmarshal(b, &c); err != nil || c.AdminSecret == "" {
		return "", errors.New("no admin secret in dev credentials")
	}
	return c.AdminSecret, nil
}
