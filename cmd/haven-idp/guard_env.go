// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"os"

	"github.com/zyvorai/haven/internal/idp/admin"
)

// guardConfigFromEnv reads the Guard admission gate settings
// (HAVEN_IDP_GUARD, _THRESHOLD, _WAIVERS, _NO_OVERRIDE; see docs/guard-gate.md).
func guardConfigFromEnv() admin.GuardConfig {
	return admin.GuardConfig{
		Mode:       os.Getenv("HAVEN_IDP_GUARD"),
		Threshold:  os.Getenv("HAVEN_IDP_GUARD_THRESHOLD"),
		WaiverFile: os.Getenv("HAVEN_IDP_GUARD_WAIVERS"),
		NoOverride: os.Getenv("HAVEN_IDP_GUARD_NO_OVERRIDE") == "1",
	}
}
