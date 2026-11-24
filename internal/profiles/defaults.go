// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package profiles

import (
	"github.com/zyvorai/haven/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

type Defaults struct {
	DBInstances    int
	Storage        string
	NetworkPolicy  bool
	BackupRequired bool
	IdPReplicas    int
}

var table = map[v1alpha1.PlaneProfile]Defaults{
	v1alpha1.ProfileDev: {
		DBInstances:    1,
		Storage:        "8Gi",
		NetworkPolicy:  false,
		BackupRequired: false,
		IdPReplicas:    1,
	},
	v1alpha1.ProfileStaging: {
		DBInstances:    2,
		Storage:        "20Gi",
		NetworkPolicy:  true,
		BackupRequired: true,
		IdPReplicas:    2,
	},
	v1alpha1.ProfileProduction: {
		DBInstances:    3,
		Storage:        "50Gi",
		NetworkPolicy:  true,
		BackupRequired: true,
		IdPReplicas:    3,
	},
}

func For(profile v1alpha1.PlaneProfile) Defaults {
	if d, ok := table[profile]; ok {
		return d
	}
	return table[v1alpha1.ProfileDev]
}

// IdPResources returns small/medium/large requests and limits for haven-idp.
func IdPResources(profile v1alpha1.PlaneProfile) corev1.ResourceRequirements {
	q := resource.MustParse
	switch profile {
	case v1alpha1.ProfileProduction:
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: q("500m"), corev1.ResourceMemory: q("512Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: q("2"), corev1.ResourceMemory: q("1Gi")},
		}
	case v1alpha1.ProfileStaging:
		return corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: q("250m"), corev1.ResourceMemory: q("256Mi")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: q("1"), corev1.ResourceMemory: q("512Mi")},
		}
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{corev1.ResourceCPU: q("100m"), corev1.ResourceMemory: q("128Mi")},
		Limits:   corev1.ResourceList{corev1.ResourceCPU: q("500m"), corev1.ResourceMemory: q("256Mi")},
	}
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
	if out.IdP.Replicas == 0 {
		out.IdP.Replicas = d.IdPReplicas
	}
	if len(out.IdP.Resources.Requests) == 0 && len(out.IdP.Resources.Limits) == 0 {
		out.IdP.Resources = IdPResources(out.Profile)
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
