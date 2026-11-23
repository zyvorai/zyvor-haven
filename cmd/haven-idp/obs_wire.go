// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/obs"
	"github.com/zyvorai/haven/internal/idp/oidc"
)

// withObs hands the Observer to the protocol handlers. Either config may be nil.
//
// LEAD: once oidc.Config and admin.Config have `Obs obs.Recorder`, un-comment
// the two assignments below (and delete the blank-identifier lines).
func withObs(o *obs.Observer, oc *oidc.Config, ac *admin.Config) {
	_, _, _ = o, oc, ac
	// if oc != nil {
	// 	oc.Obs = o
	// }
	// if ac != nil {
	// 	ac.Obs = o
	// }
}
