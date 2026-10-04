// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

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
func KeycloakName(plane string) string        { return plane }
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
		"instances":             spec.Database.Instances,
		"imageName":             "ghcr.io/cloudnative-pg/postgresql:16.15",
		"enableSuperuserAccess": false,
		"bootstrap": map[string]interface{}{
			"initdb": map[string]interface{}{
				"database": "keycloak",
				"owner":    "keycloak",
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

func KeycloakCR(plane *v1alpha1.IdentityPlane) *unstructured.Unstructured {
	spec := profiles.Merge(&plane.Spec)
	name := KeycloakName(plane.Name)
	ns := plane.Namespace
	dbSecret := name + "-keycloak-db"

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "k8s.keycloak.org", Version: "v2beta1", Kind: "Keycloak",
	})
	obj.SetName(name)
	obj.SetNamespace(ns)
	obj.SetLabels(planeLabels(plane.Name))

	kcSpec := map[string]interface{}{
		"instances": spec.Keycloak.Instances,
		"db": map[string]interface{}{
			"vendor":   "postgres",
			"host":     DBHost(plane.Name, ns),
			"database": "keycloak",
			"usernameSecret": map[string]interface{}{
				"name": dbSecret, "key": "username",
			},
			"passwordSecret": map[string]interface{}{
				"name": dbSecret, "key": "password",
			},
			"poolInitialSize": profiles.For(spec.Profile).PoolSize,
			"poolMinSize":     profiles.For(spec.Profile).PoolSize,
			"poolMaxSize":     profiles.For(spec.Profile).PoolSize,
		},
		"http": map[string]interface{}{"httpEnabled": true},
		"hostname": map[string]interface{}{
			"hostname": spec.Hostname,
			"strict":   false,
		},
		"ingress": map[string]interface{}{"enabled": false},
		"proxy":   map[string]interface{}{"headers": "xforwarded"},
		"additionalOptions": []interface{}{
			map[string]interface{}{"name": "metrics-enabled", "value": "true"},
			map[string]interface{}{"name": "health-enabled", "value": "true"},
		},
	}
	if len(spec.Keycloak.Features) > 0 {
		kcSpec["features"] = map[string]interface{}{"enabled": toIface(spec.Keycloak.Features)}
	}
	if spec.Keycloak.Version != "" {
		kcSpec["image"] = "quay.io/keycloak/keycloak:" + spec.Keycloak.Version
	}

	obj.Object["spec"] = kcSpec
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

// DBAppSecret is the CNPG bootstrap owner secret; password must match
// KeycloakDBSecret so Keycloak can log in to the database it creates.
func DBAppSecret(plane *v1alpha1.IdentityPlane, password string) *unstructured.Unstructured {
	name := DBClusterName(plane.Name) + "-app"
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Secret"})
	obj.SetName(name)
	obj.SetNamespace(plane.Namespace)
	obj.SetLabels(planeLabels(plane.Name))
	obj.Object["type"] = "kubernetes.io/basic-auth"
	obj.Object["stringData"] = map[string]interface{}{
		"username": "keycloak",
		"password": password,
	}
	return obj
}

// KeycloakDBSecret holds the JDBC credentials the Keycloak CR references.
func KeycloakDBSecret(plane *v1alpha1.IdentityPlane, password string) *unstructured.Unstructured {
	name := KeycloakName(plane.Name) + "-keycloak-db"
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Secret"})
	obj.SetName(name)
	obj.SetNamespace(plane.Namespace)
	obj.SetLabels(planeLabels(plane.Name))
	obj.Object["type"] = "Opaque"
	obj.Object["stringData"] = map[string]interface{}{
		"username": "keycloak",
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
		Keycloak: "https://" + host,
		Console:  "https://" + console,
		Account:  fmt.Sprintf("https://%s/realms/%s/account", host, realm),
		Admin:    "https://" + host + "/admin",
	}
}

func toIface(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
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
