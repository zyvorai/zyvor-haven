// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/obs"
	"github.com/zyvorai/haven/internal/idp/oidc"
)

// withObs hands the Observer to the protocol handlers. Either config may be nil.
func withObs(o *obs.Observer, oc *oidc.Config, ac *admin.Config) {
	if oc != nil {
		oc.Obs = o
	}
	if ac != nil {
		ac.Obs = o
	}
}
