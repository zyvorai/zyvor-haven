// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"context"
	"sort"
	"strings"
	"testing"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/render"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const testNS = "identity"

type env struct {
	t      *testing.T
	r      *IdentityPlaneReconciler
	c      client.Client
	writes []string
}

func newEnv(t *testing.T, hasKC bool, objs ...client.Object) *env {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := havenv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t}
	record := func(op string, obj client.Object) {
		if _, ok := obj.(*havenv1.IdentityPlane); ok {
			return
		}
		e.writes = append(e.writes, op+" "+obj.GetObjectKind().GroupVersionKind().Kind+"/"+obj.GetName())
	}
	e.c = fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&havenv1.IdentityPlane{}).
		WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, o ...client.CreateOption) error {
				record("create", obj)
				return c.Create(ctx, obj, o...)
			},
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, o ...client.UpdateOption) error {
				record("update", obj)
				return c.Update(ctx, obj, o...)
			},
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, o ...client.PatchOption) error {
				record("patch", obj)
				return c.Patch(ctx, obj, p, o...)
			},
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, o ...client.DeleteOption) error {
				record("delete", obj)
				return c.Delete(ctx, obj, o...)
			},
		}).Build()
	yes, no := true, false
	kc := &no
	if hasKC {
		kc = &yes
	}
	e.r = &IdentityPlaneReconciler{Client: e.c, Scheme: scheme, cnpgOK: &yes, kcOK: kc, certOK: &no}
	return e
}

func plane(mod func(*havenv1.IdentityPlane)) *havenv1.IdentityPlane {
	p := &havenv1.IdentityPlane{
		ObjectMeta: metav1.ObjectMeta{Name: "platform", Namespace: testNS, UID: "uid-1"},
		Spec:       havenv1.IdentityPlaneSpec{Hostname: "id.example.com", Profile: havenv1.ProfileStaging},
	}
	if mod != nil {
		mod(p)
	}
	return p
}

// reconcile runs until the finalizer is in place and one full pass has run.
func (e *env) reconcile() {
	e.t.Helper()
	for i := 0; i < 2; i++ {
		if _, err := e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "platform", Namespace: testNS}}); err != nil {
			e.t.Fatalf("reconcile: %v", err)
		}
	}
}

func (e *env) get(obj client.Object, name string) error {
	return e.c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: testNS}, obj)
}

func (e *env) mustGet(obj client.Object, name string) {
	e.t.Helper()
	if err := e.get(obj, name); err != nil {
		e.t.Fatalf("get %s: %v", name, err)
	}
}

func (e *env) plane() *havenv1.IdentityPlane {
	e.t.Helper()
	var p havenv1.IdentityPlane
	e.mustGet(&p, "platform")
	return &p
}

func (e *env) setSpec(mod func(*havenv1.IdentityPlane)) {
	e.t.Helper()
	p := e.plane()
	mod(p)
	if err := e.c.Update(context.Background(), p); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) cnpgHealthy() {
	e.t.Helper()
	var db unstructured.Unstructured
	db.SetGroupVersionKind(cnpgGVK)
	e.mustGet(&db, "platform-db")
	_ = unstructured.SetNestedField(db.Object, "Cluster in healthy state", "status", "phase")
	if err := e.c.Update(context.Background(), &db); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) deploy() *appsv1.Deployment {
	var d appsv1.Deployment
	e.mustGet(&d, "platform-idp")
	return &d
}

func (e *env) setReady(n int32) {
	e.t.Helper()
	d := e.deploy()
	d.Status.ReadyReplicas = n
	d.Status.ObservedGeneration = d.Generation
	if err := e.c.Status().Update(context.Background(), d); err != nil {
		e.t.Fatal(err)
	}
}

func cond(p *havenv1.IdentityPlane, typ string) *metav1.Condition {
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == typ {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

func TestResolveEngineTable(t *testing.T) {
	owned := func(kind string) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(kcGVK)
		if kind == "cnpg" {
			u.SetGroupVersionKind(cnpgGVK)
			u.SetName("platform-db")
			_ = unstructured.SetNestedField(u.Object, "keycloak", "spec", "bootstrap", "initdb", "owner")
		} else {
			u.SetName("platform")
		}
		u.SetNamespace(testNS)
		u.SetOwnerReferences([]metav1.OwnerReference{{
			APIVersion: havenv1.GroupVersion.String(), Kind: "IdentityPlane", Name: "platform", UID: "uid-1", Controller: ptr(true),
		}})
		return u
	}
	foreign := owned("kc")
	foreign.SetOwnerReferences(nil)

	cases := []struct {
		name  string
		hasKC bool
		spec  havenv1.PlaneEngine
		objs  []client.Object
		want  havenv1.PlaneEngine
	}{
		{"fresh plane is native", true, "", nil, havenv1.EngineNative},
		{"explicit keycloak wins", false, havenv1.EngineKeycloak, nil, havenv1.EngineKeycloak},
		{"explicit native wins over existing CR", true, havenv1.EngineNative, []client.Object{owned("kc")}, havenv1.EngineNative},
		{"owned keycloak CR keeps keycloak", true, "", []client.Object{owned("kc")}, havenv1.EngineKeycloak},
		{"keycloak CR not owned by the plane is ignored", true, "", []client.Object{foreign}, havenv1.EngineNative},
		{"keycloak operator absent but keycloak-bootstrapped DB keeps keycloak", false, "", []client.Object{owned("cnpg")}, havenv1.EngineKeycloak},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.hasKC, tc.objs...)
			got, err := e.r.resolveEngine(context.Background(), plane(func(p *havenv1.IdentityPlane) { p.Spec.Engine = tc.spec }))
			if err != nil || got != tc.want {
				t.Fatalf("got %q err %v, want %q", got, err, tc.want)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestNewPlaneCreatesExactlyTheNativeObjects(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	e.reconcile()

	want := []string{
		"create Secret/platform-db-app", "create Secret/platform-idp-db", "create Cluster/platform-db",
		"create Secret/platform-idp", "create ServiceAccount/platform-idp", "create Service/platform-idp",
		"create Deployment/platform-idp", "create PodDisruptionBudget/platform-idp",
	}
	got := append([]string(nil), e.writes...)
	for i := range got {
		// typed objects from the interceptor may lack a Kind; normalise by name only
		got[i] = strings.TrimSpace(got[i])
	}
	if !sameSet(normalise(got), normalise(want)) {
		t.Fatalf("writes\n got %v\nwant %v", got, want)
	}

	d := e.deploy()
	if *d.Spec.Replicas != 2 {
		t.Fatalf("staging should default to 2 replicas, got %d", *d.Spec.Replicas)
	}
	if !metav1.IsControlledBy(d, e.plane()) {
		t.Fatal("deployment is not owned by the plane")
	}
	var idpSecret corev1.Secret
	e.mustGet(&idpSecret, "platform-idp")
	for _, k := range render.IdPSecretKeys {
		if len(idpSecret.Data[k]) < 32 {
			t.Fatalf("secret key %s not generated", k)
		}
	}
	var dbs, app corev1.Secret
	e.mustGet(&dbs, "platform-idp-db")
	e.mustGet(&app, "platform-db-app")
	if string(dbs.Data["password"]) != app.StringData["password"] || app.StringData["password"] == "" {
		t.Fatal("db password must be shared by <plane>-db-app and <plane>-idp-db")
	}
	if !strings.Contains(string(dbs.Data["dsn"]), "@platform-db-rw.identity.svc:5432/haven_idp") {
		t.Fatal("dsn does not point at the CNPG service")
	}
	var db unstructured.Unstructured
	db.SetGroupVersionKind(cnpgGVK)
	e.mustGet(&db, "platform-db")
	owner, _, _ := unstructured.NestedString(db.Object, "spec", "bootstrap", "initdb", "owner")
	if owner != "haven_idp" {
		t.Fatalf("cnpg owner %q", owner)
	}
	if e.plane().Status.Endpoints.IdP != "https://id.example.com" {
		t.Fatalf("endpoints %+v", e.plane().Status.Endpoints)
	}
	// No keycloak objects.
	var kc unstructured.Unstructured
	kc.SetGroupVersionKind(kcGVK)
	if err := e.get(&kc, "platform"); err == nil {
		t.Fatal("keycloak CR must not exist for a native plane")
	}
}

func normalise(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		op, rest, _ := strings.Cut(s, " ")
		_, name, _ := strings.Cut(rest, "/")
		out[i] = op + " " + name
	}
	sort.Strings(out)
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSecondReconcileIsANoOp(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	e.reconcile()
	e.cnpgHealthy()
	e.setReady(2)
	e.reconcile()

	var before corev1.Secret
	e.mustGet(&before, "platform-idp")
	var dbBefore corev1.Secret
	e.mustGet(&dbBefore, "platform-idp-db")
	planeBefore := e.plane()

	e.writes = nil
	e.reconcile()
	if len(e.writes) != 0 {
		t.Fatalf("idle reconcile wrote: %v", e.writes)
	}
	var after, dbAfter corev1.Secret
	e.mustGet(&after, "platform-idp")
	e.mustGet(&dbAfter, "platform-idp-db")
	for k, v := range before.Data {
		if string(after.Data[k]) != string(v) {
			t.Fatalf("secret key %s changed", k)
		}
	}
	if string(dbAfter.Data["dsn"]) != string(dbBefore.Data["dsn"]) {
		t.Fatal("db secret changed")
	}
	if planeBefore.ResourceVersion != e.plane().ResourceVersion {
		t.Fatal("idle reconcile rewrote plane status")
	}
}

func TestExistingKeycloakPlaneStaysOnKeycloak(t *testing.T) {
	kc := &unstructured.Unstructured{}
	kc.SetGroupVersionKind(kcGVK)
	kc.SetName("platform")
	kc.SetNamespace(testNS)
	kc.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: havenv1.GroupVersion.String(), Kind: "IdentityPlane", Name: "platform", UID: "uid-1", Controller: ptr(true),
	}})
	e := newEnv(t, true, plane(nil), kc)
	e.reconcile()

	var d appsv1.Deployment
	if err := e.get(&d, "platform-idp"); !errors.IsNotFound(err) {
		t.Fatalf("no native deployment expected, err=%v", err)
	}
	var sec corev1.Secret
	e.mustGet(&sec, "platform-db-app")
	if string(sec.Data["username"]) != "" { // stringData is untouched by the fake client
		t.Fatal("unexpected data")
	}
	var db unstructured.Unstructured
	db.SetGroupVersionKind(cnpgGVK)
	e.mustGet(&db, "platform-db")
	if owner, _, _ := unstructured.NestedString(db.Object, "spec", "bootstrap", "initdb", "owner"); owner != "keycloak" {
		t.Fatalf("owner %q", owner)
	}
	var kdb corev1.Secret
	e.mustGet(&kdb, "platform-keycloak-db")
	p := e.plane()
	if p.Status.Endpoints.Keycloak == "" || p.Status.Endpoints.IdP != "" || cond(p, "KeycloakReady") == nil || cond(p, "IdentityProviderReady") != nil {
		t.Fatalf("keycloak projection changed: %+v", p.Status)
	}
}

func TestMissingIdPSecretKeyIsAddedWithoutTouchingOthers(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	e.reconcile()
	var s corev1.Secret
	e.mustGet(&s, "platform-idp")
	csrf, pass := string(s.Data["csrf-key"]), string(s.Data["admin-password"])
	delete(s.Data, "admin-client-secret")
	if err := e.c.Update(context.Background(), &s); err != nil {
		t.Fatal(err)
	}
	e.reconcile()
	var got corev1.Secret
	e.mustGet(&got, "platform-idp")
	if len(got.Data["admin-client-secret"]) < 32 {
		t.Fatal("missing key not added")
	}
	if string(got.Data["csrf-key"]) != csrf || string(got.Data["admin-password"]) != pass {
		t.Fatal("existing keys were rewritten")
	}
}

func TestReplicasChangeRollsAndManagesPDB(t *testing.T) {
	e := newEnv(t, false, plane(func(p *havenv1.IdentityPlane) { p.Spec.Profile = havenv1.ProfileDev }))
	e.reconcile()
	var pdb policyv1.PodDisruptionBudget
	if err := e.get(&pdb, "platform-idp"); !errors.IsNotFound(err) {
		t.Fatalf("dev (1 replica) must not have a PDB: %v", err)
	}
	before := e.deploy()
	selector := before.Spec.Selector.MatchLabels

	e.setSpec(func(p *havenv1.IdentityPlane) { p.Spec.IdP.Replicas = 3 })
	e.reconcile()
	d := e.deploy()
	if *d.Spec.Replicas != 3 || d.Spec.Template.Spec.Affinity == nil {
		t.Fatalf("replicas/affinity not updated: %d", *d.Spec.Replicas)
	}
	e.mustGet(&pdb, "platform-idp")
	if pdb.Spec.MaxUnavailable.IntValue() != 1 {
		t.Fatal("pdb maxUnavailable")
	}
	for k, v := range selector {
		if d.Spec.Selector.MatchLabels[k] != v {
			t.Fatal("selector must be preserved")
		}
	}

	e.setSpec(func(p *havenv1.IdentityPlane) { p.Spec.IdP.Replicas = 1 })
	e.reconcile()
	if *e.deploy().Spec.Replicas != 1 {
		t.Fatal("scale down")
	}
	if err := e.get(&pdb, "platform-idp"); !errors.IsNotFound(err) {
		t.Fatalf("stale PDB must be deleted: %v", err)
	}
}

func TestUnsetReplicasLeavesOtherWritersAlone(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	e.reconcile()
	d := e.deploy()
	d.Spec.Replicas = ptr(int32(5)) // an HPA
	if err := e.c.Update(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	e.reconcile()
	if *e.deploy().Spec.Replicas != 5 {
		t.Fatal("controller fought the autoscaler")
	}
}

func TestConfigChangeRollsPods(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	e.reconcile()
	h1 := e.deploy().Spec.Template.Annotations[render.AnnotationConfigHash]
	e.setSpec(func(p *havenv1.IdentityPlane) { p.Spec.Hostname = "new.example.com" })
	e.reconcile()
	if h2 := e.deploy().Spec.Template.Annotations[render.AnnotationConfigHash]; h1 == "" || h1 == h2 {
		t.Fatalf("hash did not change: %q %q", h1, h2)
	}
}

func TestSuspendScalesToZeroAndResumes(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	e.reconcile()
	e.setSpec(func(p *havenv1.IdentityPlane) { p.Spec.Suspend = true })
	e.reconcile()
	if *e.deploy().Spec.Replicas != 0 {
		t.Fatal("suspend must scale to 0")
	}
	p := e.plane()
	if c := cond(p, "IdentityProviderReady"); c == nil || c.Reason != "Suspended" || p.Status.Phase != havenv1.PhaseSuspending {
		t.Fatalf("suspend status: %+v %s", c, p.Status.Phase)
	}
	e.setSpec(func(p *havenv1.IdentityPlane) { p.Spec.Suspend = false })
	e.reconcile()
	if *e.deploy().Spec.Replicas != 2 {
		t.Fatalf("resume should return to the profile default, got %d", *e.deploy().Spec.Replicas)
	}
}

func TestStatusZeroOfNThenNofN(t *testing.T) {
	e := newEnv(t, false, plane(func(p *havenv1.IdentityPlane) { p.Spec.IdP.Replicas = 3 }))
	e.reconcile()
	if p := e.plane(); p.Status.Phase != havenv1.PhaseProvisioningDatabase || cond(p, "IdentityProviderReady").Reason != "DatabaseNotReady" {
		t.Fatalf("db not ready yet: %s %+v", p.Status.Phase, cond(p, "IdentityProviderReady"))
	}
	e.cnpgHealthy()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "platform-idp-abc", Namespace: testNS, Labels: render.IdPSelectorLabels("platform")},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: "haven-idp", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}},
		}}},
	}
	if err := e.c.Create(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	e.reconcile()
	p := e.plane()
	c := cond(p, "IdentityProviderReady")
	if c.Status != metav1.ConditionFalse || c.Reason != "ImagePullBackOff" || c.Message != "0/3 ready: ImagePullBackOff" {
		t.Fatalf("0/3 condition: %+v", c)
	}
	if p.Status.Phase != havenv1.PhaseProvisioningIdP || p.Status.IdP.Instances != 3 || p.Status.IdP.Ready != 0 {
		t.Fatalf("0/3 status: %s %+v", p.Status.Phase, p.Status.IdP)
	}

	e.setReady(3)
	e.reconcile()
	p = e.plane()
	c = cond(p, "IdentityProviderReady")
	if c.Status != metav1.ConditionTrue || c.Message != "3/3 ready" {
		t.Fatalf("3/3 condition: %+v", c)
	}
	if p.Status.Phase != havenv1.PhaseReady || p.Status.IdP.Ready != 3 {
		t.Fatalf("3/3 status: %s %+v", p.Status.Phase, p.Status.IdP)
	}

	// One pod lost after being Ready: still serving, so Degraded.
	e.setReady(2)
	e.reconcile()
	if p := e.plane(); p.Status.Phase != havenv1.PhaseDegraded || cond(p, "IdentityProviderReady").Status != metav1.ConditionTrue {
		t.Fatalf("2/3 status: %s", p.Status.Phase)
	}
}

func TestNativeRequiresCNPG(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	no := false
	e.r.cnpgOK = &no
	e.reconcile()
	p := e.plane()
	if c := cond(p, "DatabaseReady"); c == nil || c.Status != metav1.ConditionFalse || c.Reason != "CNPGMissing" {
		t.Fatalf("condition: %+v", c)
	}
	var d appsv1.Deployment
	if err := e.get(&d, "platform-idp"); !errors.IsNotFound(err) {
		t.Fatal("must not deploy without a database")
	}
}

func TestNoSecretValuesInEnvLiterals(t *testing.T) {
	e := newEnv(t, false, plane(nil))
	e.reconcile()
	var s, db corev1.Secret
	e.mustGet(&s, "platform-idp")
	e.mustGet(&db, "platform-idp-db")
	envs := e.deploy().Spec.Template.Spec.Containers[0].Env
	for _, secret := range []*corev1.Secret{&s, &db} {
		for k, v := range secret.Data {
			if render.IdPEnvLeaks(envs, string(v)) {
				t.Fatalf("value of %s appears in a pod env literal", k)
			}
		}
	}
}
