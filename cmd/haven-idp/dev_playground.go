// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"net/http"

	"github.com/zyvorai/haven/internal/idp/devui"
)

// The playground is part of `haven-idp dev` only: serve never mounts it.
func init() {
	playgroundHandler = func(issuer, clientID string) http.Handler {
		return devui.New(devui.Config{Issuer: issuer, ClientID: clientID})
	}
}
