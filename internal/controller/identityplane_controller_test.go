// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDBPasswordRandomForNewPlaneAndStableAfter(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	plane := &havenv1.IdentityPlane{ObjectMeta: metav1.ObjectMeta{Name: "id", Namespace: "haven"}}
	ctx := context.Background()

	r := &IdentityPlaneReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	a, err := r.dbPassword(ctx, plane)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := r.dbPassword(ctx, plane)
	if len(a) < 32 || a == b || a == "change-me-dev-only" {
		t.Fatalf("expected distinct random passwords for a new plane, got %q and %q", a, b)
	}

	kcOnly := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "id-keycloak-db", Namespace: "haven"},
		Data:       map[string][]byte{"password": []byte("from-keycloak")},
	}
	r = &IdentityPlaneReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(kcOnly).Build()}
	if got, _ := r.dbPassword(ctx, plane); got != "from-keycloak" {
		t.Fatalf("expected password reused from the Keycloak secret, got %q", got)
	}

	app := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "id-db-app", Namespace: "haven"},
		Data:       map[string][]byte{"password": []byte("from-app")},
	}
	r = &IdentityPlaneReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(app, kcOnly).Build()}
	if got, _ := r.dbPassword(ctx, plane); got != "from-app" {
		t.Fatalf("expected the CNPG app secret to win, got %q", got)
	}
}

func TestHavenSchemeRegistersIdentityPlane(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := havenv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"IdentityPlane", "IdentityPlaneList"} {
		if !scheme.Recognizes(havenv1.GroupVersion.WithKind(kind)) {
			t.Fatalf("scheme does not recognize %s", kind)
		}
	}
}
