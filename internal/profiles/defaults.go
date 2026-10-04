// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"github.com/zyvorai/haven/api/v1alpha1"
)

type Defaults struct {
	DBInstances    int
	KCInstances    int
	Storage        string
	NetworkPolicy  bool
	BackupRequired bool
	PoolSize       int
}

var table = map[v1alpha1.PlaneProfile]Defaults{
	v1alpha1.ProfileDev: {
		DBInstances:    1,
		KCInstances:    1,
		Storage:        "8Gi",
		NetworkPolicy:  false,
		BackupRequired: false,
		PoolSize:       8,
	},
	v1alpha1.ProfileStaging: {
		DBInstances:    2,
		KCInstances:    2,
		Storage:        "20Gi",
		NetworkPolicy:  true,
		BackupRequired: true,
		PoolSize:       16,
	},
	v1alpha1.ProfileProduction: {
		DBInstances:    3,
		KCInstances:    3,
		Storage:        "50Gi",
		NetworkPolicy:  true,
		BackupRequired: true,
		PoolSize:       30,
	},
}

func For(profile v1alpha1.PlaneProfile) Defaults {
	if d, ok := table[profile]; ok {
		return d
	}
	return table[v1alpha1.ProfileDev]
}

func Merge(spec *v1alpha1.IdentityPlaneSpec) v1alpha1.IdentityPlaneSpec {
	out := *spec
	d := For(out.Profile)
	if out.Profile == "" {
		out.Profile = v1alpha1.ProfileDev
	}
	if out.Database.Instances == 0 {
		out.Database.Instances = d.DBInstances
	}
	if out.Database.Storage == "" {
		out.Database.Storage = d.Storage
	}
	if out.Database.Vendor == "" {
		out.Database.Vendor = "postgres"
	}
	if out.Keycloak.Instances == 0 {
		out.Keycloak.Instances = d.KCInstances
	}
	if out.Expose.Class == "" {
		out.Expose.Class = "ingress"
	}
	if out.Expose.NetworkPolicy == nil {
		np := d.NetworkPolicy
		out.Expose.NetworkPolicy = &np
	}
	if out.Bootstrap.FirstRealm == "" {
		out.Bootstrap.FirstRealm = "platform"
	}
	return out
}
