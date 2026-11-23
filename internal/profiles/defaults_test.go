// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package profiles

import (
	"testing"

	"github.com/zyvorai/haven/api/v1alpha1"
)

func TestIdPDefaultsPerProfile(t *testing.T) {
	for profile, want := range map[v1alpha1.PlaneProfile]int{
		v1alpha1.ProfileDev: 1, v1alpha1.ProfileStaging: 2, v1alpha1.ProfileProduction: 3, "": 1,
	} {
		spec := v1alpha1.IdentityPlaneSpec{Profile: profile}
		got := Merge(&spec)
		if got.IdP.Replicas != want {
			t.Errorf("%q replicas = %d, want %d", profile, got.IdP.Replicas, want)
		}
		if got.IdP.Resources.Requests.Cpu().IsZero() || got.IdP.Resources.Limits.Memory().IsZero() {
			t.Errorf("%q has no resource defaults", profile)
		}
		if got.Keycloak.Instances != want {
			t.Errorf("%q keycloak default changed: %d", profile, got.Keycloak.Instances)
		}
	}
	spec := v1alpha1.IdentityPlaneSpec{Profile: v1alpha1.ProfileProduction}
	spec.IdP.Replicas = 5
	if Merge(&spec).IdP.Replicas != 5 {
		t.Error("explicit replicas must win")
	}
}
