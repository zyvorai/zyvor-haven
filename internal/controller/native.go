// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/profiles"
	"github.com/zyvorai/haven/internal/render"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// resolveEngine implements the engine selection in render/IDP_CONTRACT.md: an
// explicit spec.engine wins; otherwise a plane that already owns a Keycloak CR
// (or a CNPG cluster bootstrapped for Keycloak) stays on keycloak so it is
// never switched silently; everything else is native.
func (r *IdentityPlaneReconciler) resolveEngine(ctx context.Context, plane *havenv1.IdentityPlane) (havenv1.PlaneEngine, error) {
	if plane.Spec.Engine != "" {
		return plane.Spec.Engine, nil
	}
	if r.hasGVK(kcGVK) {
		var kc unstructured.Unstructured
		kc.SetGroupVersionKind(kcGVK)
		err := r.Get(ctx, types.NamespacedName{Name: render.KeycloakName(plane.Name), Namespace: plane.Namespace}, &kc)
		if err == nil && metav1.IsControlledBy(&kc, plane) {
			return havenv1.EngineKeycloak, nil
		}
		if err != nil && !errors.IsNotFound(err) {
			return "", err
		}
	}
	if r.hasGVK(cnpgGVK) {
		var db unstructured.Unstructured
		db.SetGroupVersionKind(cnpgGVK)
		err := r.Get(ctx, types.NamespacedName{Name: render.DBClusterName(plane.Name), Namespace: plane.Namespace}, &db)
		if err == nil && metav1.IsControlledBy(&db, plane) {
			owner, _, _ := unstructured.NestedString(db.Object, "spec", "bootstrap", "initdb", "owner")
			if owner == "keycloak" {
				return havenv1.EngineKeycloak, nil
			}
		}
		if err != nil && !errors.IsNotFound(err) {
			return "", err
		}
	}
	return havenv1.EngineNative, nil
}

func (r *IdentityPlaneReconciler) idpDefaultImage() string {
	if r.IdPImage != "" {
		return r.IdPImage
	}
	return os.Getenv("HAVEN_IDP_IMAGE")
}

func (r *IdentityPlaneReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *IdentityPlaneReconciler) reconcileNative(ctx context.Context, orig *havenv1.IdentityPlane, hasCNPG, hasCert bool) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	plane := orig.DeepCopy()
	plane.Spec.Engine = havenv1.EngineNative
	spec := profiles.Merge(&plane.Spec)

	var reconcileErr error
	note := func(what string, err error) {
		if err != nil {
			logger.Error(err, what)
			if reconcileErr == nil {
				reconcileErr = fmt.Errorf("%s: %w", what, err)
			}
		}
	}

	if hasCNPG {
		pw, err := r.dbPassword(ctx, plane)
		note("db password", err)
		if err == nil {
			note("db app secret", r.ensureUnstructured(ctx, plane, render.DBAppSecret(plane, pw)))
			note("idp db secret", r.ensureSecret(ctx, plane, render.IdPDBSecret(plane, pw)))
		}
		note("cnpg cluster", r.ensureUnstructured(ctx, plane, render.CNPGCluster(plane)))
		if hasCert {
			if cert := render.Certificate(plane); cert != nil {
				note("certificate", r.ensureUnstructured(ctx, plane, cert))
			}
		}
		note("idp secret", r.ensureIdPSecret(ctx, plane))
		note("idp workload", r.ensureIdPWorkload(ctx, plane, &spec))
	}

	status := r.projectNativeStatus(ctx, orig, plane, spec, hasCNPG, hasCert)
	status.ObservedGeneration = orig.Generation
	status.Endpoints = render.Endpoints(plane)
	carryTransitionTimes(orig.Status.Conditions, status.Conditions)

	if !apiequality.Semantic.DeepEqual(orig.Status, status) {
		orig.Status = status
		if err := r.Status().Update(ctx, orig); err != nil {
			return ctrl.Result{}, err
		}
	}
	if reconcileErr != nil {
		return ctrl.Result{}, reconcileErr
	}
	requeue := 60 * time.Second
	if status.Phase != havenv1.PhaseReady {
		requeue = 20 * time.Second
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ensureIdPSecret creates <plane>-idp with generated values and later only adds
// keys that are missing; existing values are never read back or rewritten.
func (r *IdentityPlaneReconciler) ensureIdPSecret(ctx context.Context, plane *havenv1.IdentityPlane) error {
	var existing corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: render.IdPName(plane.Name), Namespace: plane.Namespace}, &existing)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	values := map[string]string{}
	for _, k := range render.IdPSecretKeys {
		if len(existing.Data[k]) > 0 {
			continue
		}
		v, gerr := randomToken()
		if gerr != nil {
			return gerr
		}
		values[k] = v
	}
	if len(values) == 0 {
		return nil
	}
	return r.ensureSecret(ctx, plane, render.IdPSecret(plane, values))
}

// ensureSecret is create-only: a missing Secret is created owned by the plane;
// an existing one only receives keys of desired that it lacks.
func (r *IdentityPlaneReconciler) ensureSecret(ctx context.Context, plane *havenv1.IdentityPlane, desired *corev1.Secret) error {
	var existing corev1.Secret
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	if errors.IsNotFound(err) {
		if err := controllerutil.SetControllerReference(plane, desired, r.Scheme); err != nil {
			return err
		}
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	patch := client.MergeFrom(existing.DeepCopy())
	changed := false
	for k, v := range desired.Data {
		if len(existing.Data[k]) == 0 {
			if existing.Data == nil {
				existing.Data = map[string][]byte{}
			}
			existing.Data[k] = v
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return r.Patch(ctx, &existing, patch)
}

func (r *IdentityPlaneReconciler) ensureIdPWorkload(ctx context.Context, plane *havenv1.IdentityPlane, spec *havenv1.IdentityPlaneSpec) error {
	owner := func(obj client.Object) error { return controllerutil.SetControllerReference(plane, obj, r.Scheme) }

	sa := render.IdPServiceAccount(plane)
	saObj := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa.Name, Namespace: sa.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, saObj, func() error {
		saObj.Labels = mergeLabels(saObj.Labels, sa.Labels)
		saObj.AutomountServiceAccountToken = sa.AutomountServiceAccountToken
		return owner(saObj)
	}); err != nil {
		return err
	}

	svc := render.IdPService(plane)
	svcObj := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: svc.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, svcObj, func() error {
		svcObj.Labels = mergeLabels(svcObj.Labels, svc.Labels)
		svcObj.Spec.Type = svc.Spec.Type
		svcObj.Spec.Selector = svc.Spec.Selector
		svcObj.Spec.Ports = svc.Spec.Ports // ClusterIP is left as allocated
		return owner(svcObj)
	}); err != nil {
		return err
	}

	// Replicas: suspend wins; an explicit spec.idp.replicas wins next; when
	// unset, a running Deployment keeps whatever another writer (an HPA) chose.
	replicas := int32(spec.IdP.Replicas)
	var current appsv1.Deployment
	getErr := r.Get(ctx, types.NamespacedName{Name: render.IdPName(plane.Name), Namespace: plane.Namespace}, &current)
	if getErr != nil && !errors.IsNotFound(getErr) {
		return getErr
	}
	switch {
	case plane.Spec.Suspend:
		replicas = 0
	case plane.Spec.IdP.Replicas == 0 && getErr == nil && current.Spec.Replicas != nil && *current.Spec.Replicas > 0:
		replicas = *current.Spec.Replicas
	}

	desired := render.IdPDeployment(plane, render.IdPImage(spec, r.idpDefaultImage()), replicas)
	depObj := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: desired.Name, Namespace: desired.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, depObj, func() error {
		depObj.Labels = mergeLabels(depObj.Labels, desired.Labels)
		if depObj.CreationTimestamp.IsZero() {
			depObj.Spec.Selector = desired.Spec.Selector // immutable after create
		}
		depObj.Spec.Replicas = desired.Spec.Replicas
		depObj.Spec.Strategy = desired.Spec.Strategy
		depObj.Spec.Template = desired.Spec.Template
		return owner(depObj)
	}); err != nil {
		return err
	}

	if pdb := render.IdPPodDisruptionBudget(plane, replicas); pdb != nil && !plane.Spec.Suspend {
		pdbObj := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: pdb.Name, Namespace: pdb.Namespace}}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, pdbObj, func() error {
			pdbObj.Labels = mergeLabels(pdbObj.Labels, pdb.Labels)
			pdbObj.Spec = pdb.Spec
			return owner(pdbObj)
		})
		return err
	}
	var stale policyv1.PodDisruptionBudget
	err := r.Get(ctx, types.NamespacedName{Name: render.IdPName(plane.Name), Namespace: plane.Namespace}, &stale)
	if err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(&stale, plane) {
		return nil
	}
	return client.IgnoreNotFound(r.Delete(ctx, &stale))
}

func mergeLabels(have, want map[string]string) map[string]string {
	if have == nil {
		have = map[string]string{}
	}
	for k, v := range want {
		have[k] = v
	}
	return have
}

func (r *IdentityPlaneReconciler) projectNativeStatus(
	ctx context.Context,
	orig, plane *havenv1.IdentityPlane,
	spec havenv1.IdentityPlaneSpec,
	hasCNPG, hasCert bool,
) havenv1.IdentityPlaneStatus {
	st := orig.Status
	st.Conditions = nil
	st.Keycloak = havenv1.KeycloakStatus{}

	if !hasCNPG {
		st.Phase = havenv1.PhaseProvisioningDatabase
		st.Conditions = append(st.Conditions,
			render.Condition("DatabaseReady", "False", "CNPGMissing", "CloudNativePG CRDs (postgresql.cnpg.io) not found; the native engine requires CNPG"),
			render.Condition("IdentityProviderReady", "False", "DatabaseNotReady", "waiting for the database"),
		)
		return st
	}

	dbReady := r.projectCNPG(ctx, plane, spec, &st)

	certOK := true
	switch {
	case hasCert:
		r.projectCert(ctx, plane, spec, &st)
		for _, c := range st.Conditions {
			if c.Type == "CertificateReady" && c.Status != metav1.ConditionTrue {
				certOK = false
			}
		}
	case spec.Expose.TLS.SecretName != "":
		st.TLS.SecretName = spec.Expose.TLS.SecretName
		st.Conditions = append(st.Conditions, render.Condition("CertificateReady", "True", "ExternalSecret", spec.Expose.TLS.SecretName))
	default:
		st.Conditions = append(st.Conditions, render.Condition("CertificateReady", "True", "HTTPMode", "TLS not configured"))
	}

	var dep appsv1.Deployment
	err := r.Get(ctx, types.NamespacedName{Name: render.IdPName(plane.Name), Namespace: plane.Namespace}, &dep)
	if err != nil {
		st.IdP = havenv1.IdPStatus{}
		st.Conditions = append(st.Conditions, render.Condition("IdentityProviderReady", "False", "DeploymentMissing", errMessage(err)))
		st.Phase = havenv1.PhaseProvisioningDatabase
		if dbReady {
			st.Phase = havenv1.PhaseProvisioningIdP
		}
		return st
	}

	want := 0
	if dep.Spec.Replicas != nil {
		want = int(*dep.Spec.Replicas)
	}
	ready := int(dep.Status.ReadyReplicas)
	st.IdP = havenv1.IdPStatus{Instances: want, Ready: ready, Version: imageTag(dep)}
	current := dep.Status.ObservedGeneration >= dep.Generation

	switch {
	case plane.Spec.Suspend:
		st.Conditions = append(st.Conditions, render.Condition("IdentityProviderReady", "False", "Suspended",
			fmt.Sprintf("suspended; %d replicas running", ready)))
		st.Phase = havenv1.PhaseSuspending
		return st
	case !dbReady:
		st.Conditions = append(st.Conditions, render.Condition("IdentityProviderReady", "False", "DatabaseNotReady", "waiting for the database"))
		st.Phase = havenv1.PhaseProvisioningDatabase
		return st
	}

	idpReady := ready >= 1 && current
	if idpReady {
		st.Conditions = append(st.Conditions, render.Condition("IdentityProviderReady", "True", "DeploymentAvailable",
			fmt.Sprintf("%d/%d ready", ready, want)))
	} else {
		reason, msg := r.idpNotReady(ctx, plane, &dep, ready, want, current)
		st.Conditions = append(st.Conditions, render.Condition("IdentityProviderReady", "False", reason, msg))
	}

	wasUp := orig.Status.Phase == havenv1.PhaseReady || orig.Status.Phase == havenv1.PhaseDegraded
	switch {
	case ready >= want && idpReady && certOK:
		st.Phase = havenv1.PhaseReady
	case !idpReady && !wasUp:
		st.Phase = havenv1.PhaseProvisioningIdP
	case idpReady && !wasUp && ready < want:
		st.Phase = havenv1.PhaseProvisioningIdP
	default:
		st.Phase = havenv1.PhaseDegraded
	}
	return st
}

// idpNotReady explains why the Deployment is not available, preferring the
// waiting reason of a pod (ImagePullBackOff, CrashLoopBackOff, ...).
func (r *IdentityPlaneReconciler) idpNotReady(ctx context.Context, plane *havenv1.IdentityPlane, dep *appsv1.Deployment, ready, want int, current bool) (string, string) {
	base := fmt.Sprintf("%d/%d ready", ready, want)
	if !current {
		return "Progressing", base + ": rollout in progress"
	}
	var pods corev1.PodList
	if err := r.reader().List(ctx, &pods, client.InNamespace(plane.Namespace),
		client.MatchingLabels(render.IdPSelectorLabels(plane.Name))); err == nil {
		reasons := map[string]bool{}
		for _, p := range pods.Items {
			for _, cs := range p.Status.ContainerStatuses {
				if cs.Ready {
					continue
				}
				if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
					reasons[cs.State.Waiting.Reason] = true
				} else if cs.State.Terminated != nil && cs.State.Terminated.Reason != "" {
					reasons[cs.State.Terminated.Reason] = true
				}
			}
		}
		if len(reasons) > 0 {
			list := make([]string, 0, len(reasons))
			for k := range reasons {
				list = append(list, k)
			}
			sort.Strings(list)
			return list[0], base + ": " + strings.Join(list, ", ")
		}
	}
	for _, c := range dep.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionFalse {
			return c.Reason, base + ": " + c.Message
		}
	}
	for _, c := range dep.Status.Conditions {
		if c.Type == appsv1.DeploymentAvailable && c.Status == corev1.ConditionFalse {
			return "NoReadyReplicas", base + ": " + c.Message
		}
	}
	return "NoReadyReplicas", base
}

func errMessage(err error) string {
	if errors.IsNotFound(err) {
		return "Deployment not created yet"
	}
	return err.Error()
}

func imageTag(dep appsv1.Deployment) string {
	for _, c := range dep.Spec.Template.Spec.Containers {
		if i := strings.LastIndex(c.Image, ":"); i >= 0 && !strings.Contains(c.Image[i:], "/") {
			return c.Image[i+1:]
		}
	}
	return ""
}

// carryTransitionTimes keeps LastTransitionTime stable while a condition's
// status is unchanged, so an idle plane produces no status writes.
func carryTransitionTimes(old, cur []metav1.Condition) {
	for i := range cur {
		for _, o := range old {
			if o.Type == cur[i].Type && o.Status == cur[i].Status {
				cur[i].LastTransitionTime = o.LastTransitionTime
			}
		}
	}
}
