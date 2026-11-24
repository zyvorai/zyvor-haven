// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sort"
	"strings"
	"time"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/render"
	appsv1 "k8s.io/api/apps/v1"
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
	certGVK = schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"}
	bakGVK  = schema.GroupVersionKind{Group: "postgresql.cnpg.io", Version: "v1", Kind: "Backup"}
)

type IdentityPlaneReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Discovery discovery.DiscoveryInterface

	// APIReader serves uncached reads (pods); defaults to the manager's API reader.
	APIReader client.Reader
	// IdPImage is the default haven-idp image; empty reads HAVEN_IDP_IMAGE.
	IdPImage string
	// CNPGNamespace is where the CloudNativePG operator runs; the database
	// NetworkPolicy lets it in. Empty means render.DefaultCNPGNamespace.
	CNPGNamespace string

	cnpgOK *bool
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

	return r.reconcileNative(ctx, &plane, r.hasGVK(cnpgGVK), r.hasGVK(certGVK))
}

func (r *IdentityPlaneReconciler) hasGVK(gvk schema.GroupVersionKind) bool {
	switch gvk.Kind {
	case "Cluster":
		if r.cnpgOK != nil {
			return *r.cnpgOK
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
	names := []string{render.DBClusterName(plane.Name) + "-app", render.IdPDBSecretName(plane.Name)}
	for _, name := range names {
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

// projectCNPG fills the database status and the DatabaseReady/BackupConfigured
// conditions from the CNPG Cluster and reports whether it is healthy.
func (r *IdentityPlaneReconciler) projectCNPG(
	ctx context.Context,
	plane *havenv1.IdentityPlane,
	spec havenv1.IdentityPlaneSpec,
	st *havenv1.IdentityPlaneStatus,
) (dbReady bool) {
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
	return dbReady
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
		for _, gvk := range []schema.GroupVersionKind{cnpgGVK, certGVK} {
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
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&havenv1.IdentityPlane{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Complete(r)
}
