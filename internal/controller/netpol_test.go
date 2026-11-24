// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"context"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
)

func boolPtr(b bool) *bool { return &b }

const dbPolicy = "platform-db-ingress"

func TestDBNetworkPolicyFollowsTheProfileAndTheSetting(t *testing.T) {
	// staging switches it on by default.
	e := newEnv(t, false, plane(nil))
	e.reconcile()
	var np networkingv1.NetworkPolicy
	e.mustGet(&np, dbPolicy)
	if len(np.OwnerReferences) != 1 || np.OwnerReferences[0].Kind != "IdentityPlane" || np.OwnerReferences[0].Name != "platform" {
		t.Fatalf("policy must be owned by the plane (garbage collected with it): %+v", np.OwnerReferences)
	}
	if got := np.Spec.PodSelector.MatchLabels["cnpg.io/cluster"]; got != "platform-db" {
		t.Errorf("selects %q, want the plane's database pods", got)
	}
	if len(np.Spec.PolicyTypes) != 1 || np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress || len(np.Spec.Egress) != 0 {
		t.Errorf("must be ingress-only (federation, back-channel logout and SMTP need egress): %+v", np.Spec)
	}

	// dev leaves it off by default.
	dev := newEnv(t, false, plane(func(p *havenv1.IdentityPlane) { p.Spec.Profile = havenv1.ProfileDev }))
	dev.reconcile()
	if err := dev.get(&networkingv1.NetworkPolicy{}, dbPolicy); err == nil {
		t.Error("dev profile created a NetworkPolicy by default")
	}

	// An explicit false beats the profile default.
	off := newEnv(t, false, plane(func(p *havenv1.IdentityPlane) { p.Spec.Expose.NetworkPolicy = boolPtr(false) }))
	off.reconcile()
	if err := off.get(&networkingv1.NetworkPolicy{}, dbPolicy); err == nil {
		t.Error("expose.networkPolicy=false was ignored")
	}

	// And an explicit true switches it on in dev.
	on := newEnv(t, false, plane(func(p *havenv1.IdentityPlane) {
		p.Spec.Profile = havenv1.ProfileDev
		p.Spec.Expose.NetworkPolicy = boolPtr(true)
	}))
	on.reconcile()
	on.mustGet(&networkingv1.NetworkPolicy{}, dbPolicy)
}

func TestDBNetworkPolicyIsRemovedWhenSwitchedOff(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	e.reconcile()
	e.mustGet(&networkingv1.NetworkPolicy{}, dbPolicy)

	e.setSpec(func(p *havenv1.IdentityPlane) { p.Spec.Expose.NetworkPolicy = boolPtr(false) })
	e.reconcile()
	if err := e.get(&networkingv1.NetworkPolicy{}, dbPolicy); err == nil {
		t.Fatal("the policy stayed after expose.networkPolicy was switched off")
	}

	e.setSpec(func(p *havenv1.IdentityPlane) { p.Spec.Expose.NetworkPolicy = boolPtr(true) })
	e.reconcile()
	e.mustGet(&networkingv1.NetworkPolicy{}, dbPolicy)
}

// A policy of the same name that this controller did not create is somebody
// else's: switching the setting off must not delete it.
func TestDBNetworkPolicyNeverDeletesAForeignOne(t *testing.T) {
	foreign := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: dbPolicy, Namespace: testNS},
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}},
	}
	e := newEnv(t, false, plane(func(p *havenv1.IdentityPlane) { p.Spec.Expose.NetworkPolicy = boolPtr(false) }), foreign)
	e.reconcile()
	var got networkingv1.NetworkPolicy
	e.mustGet(&got, dbPolicy)
	if len(got.OwnerReferences) != 0 {
		t.Errorf("the controller adopted somebody else's policy: %+v", got.OwnerReferences)
	}
}

// Drift: somebody edits the policy (for example opens it up); the controller puts it back.
func TestDBNetworkPolicyDriftIsCorrected(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	e.reconcile()
	var np networkingv1.NetworkPolicy
	e.mustGet(&np, dbPolicy)
	want := len(np.Spec.Ingress)
	np.Spec.Ingress = append(np.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{}) // an allow-all rule
	if err := e.c.Update(context.Background(), &np); err != nil {
		t.Fatal(err)
	}
	e.reconcile()
	e.mustGet(&np, dbPolicy)
	if len(np.Spec.Ingress) != want {
		t.Fatalf("drift not corrected: %d ingress rules, want %d", len(np.Spec.Ingress), want)
	}
}
