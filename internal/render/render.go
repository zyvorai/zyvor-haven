// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package render

import (
	"fmt"

	"github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/profiles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	labelManaged = "haven.identity/managed"
	labelPlane   = "haven.identity/plane"
	labelPartOf  = "app.kubernetes.io/part-of"
)

func planeLabels(name string) map[string]string {
	return map[string]string{
		labelManaged: "true",
		labelPlane:   name,
		labelPartOf:  "haven",
	}
}

func DBClusterName(plane string) string       { return plane + "-db" }
func CertName(plane string) string            { return plane + "-tls" }
func ScheduledBackupName(plane string) string { return plane + "-db-scheduled" }

func DBHost(plane, ns string) string {
	return fmt.Sprintf("%s-rw.%s.svc", DBClusterName(plane), ns)
}

func CNPGCluster(plane *v1alpha1.IdentityPlane) *unstructured.Unstructured {
	spec := profiles.Merge(&plane.Spec)
	name := DBClusterName(plane.Name)
	ns := plane.Namespace

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "postgresql.cnpg.io", Version: "v1", Kind: "Cluster",
	})
	obj.SetName(name)
	obj.SetNamespace(ns)
	obj.SetLabels(planeLabels(plane.Name))

	clusterSpec := map[string]interface{}{
		"instances":             int64(spec.Database.Instances),
		"imageName":             "ghcr.io/cloudnative-pg/postgresql:16.15",
		"enableSuperuserAccess": false,
		"bootstrap": map[string]interface{}{
			"initdb": map[string]interface{}{
				"database": IdPDBName,
				"owner":    IdPDBName,
				"secret": map[string]interface{}{
					"name": name + "-app",
				},
			},
		},
		"storage": map[string]interface{}{
			"size": spec.Database.Storage,
		},
		"postgresql": map[string]interface{}{
			"parameters": map[string]interface{}{
				"max_connections": "100",
			},
		},
	}
	if spec.Database.StorageClass != "" {
		clusterSpec["storage"].(map[string]interface{})["storageClass"] = spec.Database.StorageClass
	}
	if spec.Database.ImageName != "" {
		clusterSpec["imageName"] = spec.Database.ImageName
	}

	obj.Object["spec"] = clusterSpec
	return obj
}

func Certificate(plane *v1alpha1.IdentityPlane) *unstructured.Unstructured {
	spec := profiles.Merge(&plane.Spec)
	if spec.Expose.TLS.IssuerRef == nil || spec.Expose.TLS.IssuerRef.Name == "" {
		return nil
	}
	if spec.Expose.TLS.SecretName != "" {
		return nil
	}

	name := CertName(plane.Name)
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "cert-manager.io", Version: "v1", Kind: "Certificate",
	})
	obj.SetName(name)
	obj.SetNamespace(plane.Namespace)
	obj.SetLabels(planeLabels(plane.Name))

	issuerKind := spec.Expose.TLS.IssuerRef.Kind
	if issuerKind == "" {
		issuerKind = "ClusterIssuer"
	}
	issuerGroup := spec.Expose.TLS.IssuerRef.Group
	if issuerGroup == "" {
		issuerGroup = "cert-manager.io"
	}

	obj.Object["spec"] = map[string]interface{}{
		"secretName": name,
		"dnsNames":   []interface{}{spec.Hostname},
		"issuerRef": map[string]interface{}{
			"kind":  issuerKind,
			"name":  spec.Expose.TLS.IssuerRef.Name,
			"group": issuerGroup,
		},
	}
	return obj
}

// DBAppSecret is the CNPG bootstrap owner secret; its password must match the
// one in the <plane>-idp-db Secret so haven-idp can log in to the database.
func DBAppSecret(plane *v1alpha1.IdentityPlane, password string) *unstructured.Unstructured {
	name := DBClusterName(plane.Name) + "-app"
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Secret"})
	obj.SetName(name)
	obj.SetNamespace(plane.Namespace)
	obj.SetLabels(planeLabels(plane.Name))
	obj.Object["type"] = "kubernetes.io/basic-auth"
	obj.Object["stringData"] = map[string]interface{}{
		"username": IdPDBName,
		"password": password,
	}
	return obj
}

func NamespaceLabels() map[string]string {
	return map[string]string{labelManaged: "true", labelPartOf: "haven"}
}

func Endpoints(plane *v1alpha1.IdentityPlane) v1alpha1.EndpointsStatus {
	spec := profiles.Merge(&plane.Spec)
	host := spec.Hostname
	console := spec.ConsoleHostname
	if console == "" {
		console = "haven." + host
	}
	realm := spec.Bootstrap.FirstRealm
	return v1alpha1.EndpointsStatus{
		IdP:     "https://" + host,
		Issuer:  fmt.Sprintf("https://%s/realms/%s", host, realm),
		Console: "https://" + console,
	}
}

func Condition(typ, status, reason, msg string) metav1.Condition {
	return metav1.Condition{
		Type:               typ,
		Status:             metav1.ConditionStatus(status),
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: metav1.Now(),
	}
}
