// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import "net/http"

// extraRoutes is the Admin API feature registry: a feature adds its routes
// from an init() in its own file with registerRoutes, instead of editing
// routes() (which would collide with every other feature in a merge).
var extraRoutes []func(a *api, m *http.ServeMux)

func registerRoutes(f func(a *api, m *http.ServeMux)) { extraRoutes = append(extraRoutes, f) }
