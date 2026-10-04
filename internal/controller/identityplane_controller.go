// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/profiles"
	"github.com/zyvorai/haven/internal/render"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const finalizerName = "identity.haven.dev/finalizer"

var (
	cnpgGVK = schema.GroupVersionKind{Group: "postgresql.cnpg.io", Version: "v1", Kind: "Cluster"}
	kcGVK   = schema.GroupVersionKind{Group: "k8s.keycloak.org", Version: "v2beta1", Kind: "Keycloak"}
	certGVK = schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"}
	bakGVK  = schema.GroupVersionKind{Group: "postgresql.cnpg.io", Version: "v1", Kind: "Backup"}
)

type IdentityPlaneReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Discovery discovery.DiscoveryInterface

	cnpgOK *bool
	kcOK   *bool
	certOK *bool
}

func (r *IdentityPlaneReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var plane havenv1.IdentityPlane
	if err := r.Get(ctx, req.NamespacedName, &plane); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !plane.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &plane)
	}

	if !controllerutil.ContainsFinalizer(&plane, finalizerName) {
		controllerutil.AddFinalizer(&plane, finalizerName)
		if err := r.Update(ctx, &plane); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	if err := r.ensureNamespace(ctx, plane.Namespace); err != nil {
		logger.Info("namespace ensure skipped", "err", err.Error())
	}

	spec := profiles.Merge(&plane.Spec)
	hasCNPG := r.hasGVK(cnpgGVK)
	hasKC := r.hasGVK(kcGVK)
	hasCert := r.hasGVK(certGVK)

	// Always ensure JDBC secrets (plain Secrets) for when operators arrive later.
	if dbPassword, err := r.dbPassword(ctx, &plane); err != nil {
		logger.Error(err, "db password")
	} else {
		if err := r.ensureUnstructured(ctx, &plane, render.DBAppSecret(&plane, dbPassword)); err != nil {
			logger.Error(err, "db app secret")
		}
		if err := r.ensureUnstructured(ctx, &plane, render.KeycloakDBSecret(&plane, dbPassword)); err != nil {
			logger.Error(err, "keycloak db secret")
		}
	}

	if hasCNPG {
		if err := r.ensureUnstructured(ctx, &plane, render.CNPGCluster(&plane)); err != nil {
			logger.Error(err, "cnpg cluster")
		}
	}
	if hasCert {
		if cert := render.Certificate(&plane); cert != nil {
			if err := r.ensureUnstructured(ctx, &plane, cert); err != nil {
				logger.Error(err, "certificate")
			}
		}
	}
	if hasKC {
		if err := r.ensureUnstructured(ctx, &plane, render.KeycloakCR(&plane)); err != nil {
			logger.Error(err, "keycloak")
		}
	}

	status := r.projectStatus(ctx, &plane, spec, hasCNPG, hasKC, hasCert)
	status.ObservedGeneration = plane.Generation
	status.Endpoints = render.Endpoints(&plane)

	plane.Status = status
	if err := r.Status().Update(ctx, &plane); err != nil {
		return ctrl.Result{}, err
	}

	requeue := 60 * time.Second
	if status.Phase != havenv1.PhaseReady {
		requeue = 20 * time.Second
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *IdentityPlaneReconciler) hasGVK(gvk schema.GroupVersionKind) bool {
	switch gvk.Kind {
	case "Cluster":
		if r.cnpgOK != nil {
			return *r.cnpgOK
		}
	case "Keycloak":
		if r.kcOK != nil {
			return *r.kcOK
		}
	case "Certificate":
		if r.certOK != nil {
			return *r.certOK
		}
	}
	ok := false
	if r.Discovery != nil {
		_, err := r.Discovery.ServerResourcesForGroupVersion(gvk.GroupVersion().String())
		ok = err == nil
		// Confirm kind exists
		if ok {
			lists, err := r.Discovery.ServerResourcesForGroupVersion(gvk.GroupVersion().String())
			if err == nil {
				found := false
				for _, res := range lists.APIResources {
					if res.Kind == gvk.Kind {
						found = true
						break
					}
				}
				ok = found
			}
		}
	}
	switch gvk.Kind {
	case "Cluster":
		r.cnpgOK = &ok
	case "Keycloak":
		r.kcOK = &ok
	case "Certificate":
		r.certOK = &ok
	}
	return ok
}

func (r *IdentityPlaneReconciler) ensureNamespace(ctx context.Context, ns string) error {
	var namespace corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: ns}, &namespace); err != nil {
		return err
	}
	patch := client.MergeFrom(namespace.DeepCopy())
	labels := namespace.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	for k, v := range render.NamespaceLabels() {
		labels[k] = v
	}
	namespace.SetLabels(labels)
	return r.Patch(ctx, &namespace, patch)
}

// dbPassword returns the password already stored in either JDBC secret, so
// the pair stays consistent across reconciles, or a fresh random one for a
// new plane. ensureUnstructured never overwrites an existing secret.
func (r *IdentityPlaneReconciler) dbPassword(ctx context.Context, plane *havenv1.IdentityPlane) (string, error) {
	for _, name := range []string{render.DBClusterName(plane.Name) + "-app", render.KeycloakName(plane.Name) + "-keycloak-db"} {
		var sec corev1.Secret
		err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: plane.Namespace}, &sec)
		if err == nil && len(sec.Data["password"]) > 0 {
			return string(sec.Data["password"]), nil
		}
		if err != nil && !errors.IsNotFound(err) {
			return "", err
		}
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (r *IdentityPlaneReconciler) ensureUnstructured(ctx context.Context, plane *havenv1.IdentityPlane, desired *unstructured.Unstructured) error {
	if desired == nil {
		return nil
	}
	key := types.NamespacedName{Name: desired.GetName(), Namespace: desired.GetNamespace()}

	var existing unstructured.Unstructured
	existing.SetGroupVersionKind(desired.GroupVersionKind())
	err := r.Get(ctx, key, &existing)
	if errors.IsNotFound(err) {
		if err := controllerutil.SetControllerReference(plane, desired, r.Scheme); err != nil {
			return err
		}
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}

	// Adopt pre-existing compose-path resources without overwriting their spec.
	if !metav1.IsControlledBy(&existing, plane) {
		patch := client.MergeFrom(existing.DeepCopy())
		if err := controllerutil.SetControllerReference(plane, &existing, r.Scheme); err != nil {
			return err
		}
		labels := existing.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		for k, v := range desired.GetLabels() {
			labels[k] = v
		}
		existing.SetLabels(labels)
		return r.Patch(ctx, &existing, patch)
	}
	return nil
}

func (r *IdentityPlaneReconciler) projectStatus(
	ctx context.Context,
	plane *havenv1.IdentityPlane,
	spec havenv1.IdentityPlaneSpec,
	hasCNPG, hasKC, hasCert bool,
) havenv1.IdentityPlaneStatus {
	st := plane.Status
	st.Conditions = nil

	if !hasCNPG && !hasKC {
		// External mode: Keycloak/Postgres run outside Haven operators (e.g. argus Deployment).
		st.Database.Phase = "external"
		st.Database.Instances = spec.Database.Instances
		st.Database.Ready = spec.Database.Instances
		st.Database.Primary = "external"
		st.Keycloak.Instances = spec.Keycloak.Instances
		st.Keycloak.Ready = spec.Keycloak.Instances
		st.Keycloak.Version = spec.Keycloak.Version
		st.Conditions = append(st.Conditions,
			render.Condition("DatabaseReady", "True", "ExternalDatabase", "CNPG operator not installed — database managed outside plane"),
			render.Condition("KeycloakReady", "True", "ExternalKeycloak", "Keycloak operator not installed — use Haven Settings to connect"),
			render.Condition("BackupConfigured", "False", "OperatorsMissing", "no backups yet"),
			render.Condition("OperatorsInstalled", "False", "OperatorsMissing", "postgresql.cnpg.io and k8s.keycloak.org CRDs not found"),
		)
		if hasCert {
			r.projectCert(ctx, plane, spec, &st)
		} else {
			st.Conditions = append(st.Conditions,
				render.Condition("CertificateReady", "True", "HTTPMode", "TLS not configured (dev / external)"),
			)
		}
		st.Phase = havenv1.PhaseReady
		return st
	}

	dbReady := false
	if hasCNPG {
		dbName := render.DBClusterName(plane.Name)
		var db unstructured.Unstructured
		db.SetGroupVersionKind(cnpgGVK)
		dbErr := r.Get(ctx, types.NamespacedName{Name: dbName, Namespace: plane.Namespace}, &db)
		if dbErr == nil {
			phase, _, _ := unstructured.NestedString(db.Object, "status", "phase")
			st.Database.Phase = phase
			ready, _, _ := unstructured.NestedInt64(db.Object, "status", "readyInstances")
			instances, _, _ := unstructured.NestedInt64(db.Object, "spec", "instances")
			st.Database.Ready = int(ready)
			st.Database.Instances = int(instances)
			if st.Database.Instances == 0 {
				st.Database.Instances = spec.Database.Instances
			}
			primary, _, _ := unstructured.NestedString(db.Object, "status", "currentPrimary")
			st.Database.Primary = primary
			if primary == "" {
				st.Database.Primary = dbName + "-rw." + plane.Namespace + ".svc"
			}
			replicas := st.Database.Instances - 1
			if replicas < 0 {
				replicas = 0
			}
			st.Database.Replicas = replicas
			dbReady = strings.Contains(strings.ToLower(phase), "healthy") || phase == "Cluster in healthy state"
			st.Conditions = append(st.Conditions, render.Condition("DatabaseReady",
				boolStatus(dbReady), "DatabasePhase", phase))
		} else {
			st.Conditions = append(st.Conditions, render.Condition("DatabaseReady",
				"False", "DatabaseMissing", dbErr.Error()))
		}

		lastBackup, backupOK := r.latestBackup(ctx, plane.Namespace, dbName)
		st.Database.LastBackup = lastBackup
		st.Conditions = append(st.Conditions, render.Condition("BackupConfigured",
			boolStatus(backupOK || spec.Database.Backup.Destination != ""), "BackupStatus",
			backupMessage(lastBackup, spec.Database.Backup.Destination)))
	} else {
		st.Database.Phase = "external"
		st.Conditions = append(st.Conditions,
			render.Condition("DatabaseReady", "True", "ExternalDatabase", "CNPG CRD missing"),
			render.Condition("BackupConfigured", "False", "BackupStatus", "no backups yet"),
		)
		dbReady = true
	}

	kcReady := false
	if hasKC {
		kcName := render.KeycloakName(plane.Name)
		var kc unstructured.Unstructured
		kc.SetGroupVersionKind(kcGVK)
		kcErr := r.Get(ctx, types.NamespacedName{Name: kcName, Namespace: plane.Namespace}, &kc)
		if kcErr == nil {
			instances, _, _ := unstructured.NestedInt64(kc.Object, "spec", "instances")
			ready, _, _ := unstructured.NestedInt64(kc.Object, "status", "readyInstances")
			if ready == 0 {
				ready, _, _ = unstructured.NestedInt64(kc.Object, "status", "instances")
			}
			st.Keycloak.Instances = int(instances)
			st.Keycloak.Ready = int(ready)
			st.Keycloak.Version = spec.Keycloak.Version
			kcReady = int(ready) >= int(instances) && int(instances) > 0
			st.Conditions = append(st.Conditions, render.Condition("KeycloakReady",
				boolStatus(kcReady), "KeycloakInstances", fmt.Sprintf("%d/%d ready", ready, instances)))
		} else {
			st.Conditions = append(st.Conditions, render.Condition("KeycloakReady",
				"False", "KeycloakMissing", kcErr.Error()))
		}
	} else {
		st.Keycloak.Instances = spec.Keycloak.Instances
		st.Keycloak.Ready = spec.Keycloak.Instances
		st.Conditions = append(st.Conditions,
			render.Condition("KeycloakReady", "True", "ExternalKeycloak", "Keycloak operator CRD missing"),
		)
		kcReady = true
	}

	certOK := true
	if hasCert {
		r.projectCert(ctx, plane, spec, &st)
		for _, c := range st.Conditions {
			if c.Type == "CertificateReady" && c.Status != metav1.ConditionTrue {
				certOK = false
			}
		}
	} else if spec.Expose.TLS.SecretName != "" {
		st.TLS.SecretName = spec.Expose.TLS.SecretName
		st.Conditions = append(st.Conditions, render.Condition("CertificateReady",
			"True", "ExternalSecret", spec.Expose.TLS.SecretName))
	} else {
		st.Conditions = append(st.Conditions, render.Condition("CertificateReady",
			"True", "HTTPMode", "TLS not configured"))
	}

	st.Phase = derivePhase(dbReady, kcReady, certOK)
	return st
}

func (r *IdentityPlaneReconciler) projectCert(ctx context.Context, plane *havenv1.IdentityPlane, spec havenv1.IdentityPlaneSpec, st *havenv1.IdentityPlaneStatus) {
	certName := render.CertName(plane.Name)
	if spec.Expose.TLS.IssuerRef != nil && spec.Expose.TLS.IssuerRef.Name != "" {
		var cert unstructured.Unstructured
		cert.SetGroupVersionKind(certGVK)
		if err := r.Get(ctx, types.NamespacedName{Name: certName, Namespace: plane.Namespace}, &cert); err == nil {
			notAfter, _, _ := unstructured.NestedString(cert.Object, "status", "notAfter")
			st.TLS.SecretName = certName
			st.TLS.ExpiresAt = notAfter
			certOK := true
			if t, err := time.Parse(time.RFC3339, notAfter); err == nil {
				st.TLS.DaysRemaining = int(time.Until(t).Hours() / 24)
				certOK = st.TLS.DaysRemaining > 14
			}
			st.Conditions = append(st.Conditions, render.Condition("CertificateReady",
				boolStatus(certOK), "CertificateExpiry", notAfter))
		} else {
			st.Conditions = append(st.Conditions, render.Condition("CertificateReady",
				"False", "CertificateMissing", err.Error()))
		}
	} else if spec.Expose.TLS.SecretName != "" {
		st.TLS.SecretName = spec.Expose.TLS.SecretName
		st.Conditions = append(st.Conditions, render.Condition("CertificateReady",
			"True", "ExternalSecret", spec.Expose.TLS.SecretName))
	} else {
		st.Conditions = append(st.Conditions, render.Condition("CertificateReady",
			"True", "HTTPMode", "TLS not configured"))
	}
}

func derivePhase(dbReady, kcReady, certOK bool) havenv1.PlanePhase {
	if !dbReady {
		return havenv1.PhaseProvisioningDatabase
	}
	if !kcReady {
		return havenv1.PhaseProvisioningKeycloak
	}
	if !certOK {
		return havenv1.PhaseDegraded
	}
	return havenv1.PhaseReady
}

func (r *IdentityPlaneReconciler) latestBackup(ctx context.Context, ns, cluster string) (string, bool) {
	var list unstructured.UnstructuredList
	list.SetGroupVersionKind(schema.GroupVersionKind{Group: bakGVK.Group, Version: bakGVK.Version, Kind: "BackupList"})
	if err := r.List(ctx, &list, client.InNamespace(ns)); err != nil {
		return "", false
	}

	type item struct {
		name string
		at   time.Time
	}
	var items []item
	for _, b := range list.Items {
		cn, _, _ := unstructured.NestedString(b.Object, "spec", "cluster", "name")
		if cn != cluster {
			continue
		}
		phase, _, _ := unstructured.NestedString(b.Object, "status", "phase")
		if phase != "completed" {
			continue
		}
		st, _, _ := unstructured.NestedString(b.Object, "status", "startedAt")
		if st == "" {
			st, _, _ = unstructured.NestedString(b.Object, "status", "endTime")
		}
		t, err := time.Parse(time.RFC3339, st)
		if err != nil {
			continue
		}
		items = append(items, item{name: b.GetName(), at: t})
	}
	if len(items) == 0 {
		return "", false
	}
	sort.Slice(items, func(i, j int) bool { return items[i].at.After(items[j].at) })
	return items[0].at.UTC().Format(time.RFC3339), true
}

func (r *IdentityPlaneReconciler) finalize(ctx context.Context, plane *havenv1.IdentityPlane) (ctrl.Result, error) {
	if plane.Spec.ReclaimPolicy == "Delete" {
		for _, gvk := range []schema.GroupVersionKind{cnpgGVK, kcGVK, certGVK} {
			if !r.hasGVK(gvk) {
				continue
			}
			var list unstructured.UnstructuredList
			list.SetGroupVersionKind(schema.GroupVersionKind{Group: gvk.Group, Version: gvk.Version, Kind: gvk.Kind + "List"})
			if err := r.List(ctx, &list, client.InNamespace(plane.Namespace)); err != nil {
				continue
			}
			for i := range list.Items {
				obj := &list.Items[i]
				if metav1.IsControlledBy(obj, plane) {
					_ = r.Delete(ctx, obj)
				}
			}
		}
	}
	controllerutil.RemoveFinalizer(plane, finalizerName)
	return ctrl.Result{}, r.Update(ctx, plane)
}

func boolStatus(ok bool) string {
	if ok {
		return "True"
	}
	return "False"
}

func backupMessage(last, dest string) string {
	if last != "" {
		return "last backup " + last
	}
	if dest != "" {
		return "backup destination configured"
	}
	return "no backups yet"
}

func (r *IdentityPlaneReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if cfg := mgr.GetConfig(); cfg != nil {
		if d, err := discovery.NewDiscoveryClientForConfig(cfg); err == nil {
			r.Discovery = d
		}
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&havenv1.IdentityPlane{}).
		Complete(r)
}
