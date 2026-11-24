// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	networkingv1 "k8s.io/api/networking/v1"
	"net/url"
	"sort"
	"strings"

	"github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/profiles"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// See IDP_CONTRACT.md for the names, labels, env and security context below.
const (
	IdPPortHTTP    = 8081
	IdPPortMetrics = 9100
	IdPRunAsUser   = 65532
	IdPImageRepo   = "ghcr.io/zyvorai/haven-idp"
	IdPDefaultTag  = "latest"
	IdPDBName      = "haven_idp"

	AnnotationConfigHash = "haven.identity/config-hash"

	SecretKeyCSRF        = "csrf-key"
	SecretKeySecret      = "secret-key" // HAVEN_IDP_SECRET_KEY: encrypts TOTP seeds and upstream IdP secrets
	SecretKeyAdminPass   = "admin-password"
	SecretKeyAdminClient = "admin-client-secret"
	DBSecretKeyUsername  = "username"
	DBSecretKeyPassword  = "password"
	DBSecretKeyDSN       = "dsn"

	labelName             = "app.kubernetes.io/name"
	labelInstance         = "app.kubernetes.io/instance"
	labelComponent        = "app.kubernetes.io/component"
	idpAppName            = "haven-idp"
	idpContainerName      = "haven-idp"
	bootstrapAdminUser    = "admin"
	consoleCallbackSuffix = "/api/v1/auth/oidc/callback"
)

// IdPSecretKeys lists every key the <plane>-idp Secret must carry.
var IdPSecretKeys = []string{SecretKeyCSRF, SecretKeySecret, SecretKeyAdminPass, SecretKeyAdminClient}

func IdPName(plane string) string         { return plane + "-idp" }
func IdPDBSecretName(plane string) string { return plane + "-idp-db" }

// IsNative reports whether the (already resolved) plane runs the native engine.
func IsNative(plane *v1alpha1.IdentityPlane) bool {
	return plane.Spec.Engine == v1alpha1.EngineNative
}

// DBName is the database and owner role the CNPG cluster bootstraps.
func DBName(plane *v1alpha1.IdentityPlane) string {
	if IsNative(plane) {
		return IdPDBName
	}
	return "keycloak"
}

// IdPSelectorLabels are the immutable Deployment/Service selector labels.
func IdPSelectorLabels(plane string) map[string]string {
	return map[string]string{labelName: idpAppName, labelInstance: plane}
}

// IdPLabels are the labels carried by every native-engine object.
func IdPLabels(plane string) map[string]string {
	l := planeLabels(plane)
	l[labelName] = idpAppName
	l[labelInstance] = plane
	l[labelComponent] = "identity"
	return l
}

// IdPImage resolves the image: spec.idp.image, then ghcr.io/zyvorai/haven-idp:<version>,
// then the operator default (HAVEN_IDP_IMAGE), then :latest.
func IdPImage(spec *v1alpha1.IdentityPlaneSpec, operatorDefault string) string {
	switch {
	case spec.IdP.Image != "":
		return spec.IdP.Image
	case spec.IdP.Version != "":
		return IdPImageRepo + ":" + spec.IdP.Version
	case operatorDefault != "":
		return operatorDefault
	}
	return IdPImageRepo + ":" + IdPDefaultTag
}

func consoleHost(spec *v1alpha1.IdentityPlaneSpec) string {
	if spec.ConsoleHostname != "" {
		return spec.ConsoleHostname
	}
	return "haven." + spec.Hostname
}

// idpPlainEnv is the non-secret configuration.
func idpPlainEnv(spec *v1alpha1.IdentityPlaneSpec) map[string]string {
	return map[string]string{
		"HAVEN_IDP_BASE_URL":          "https://" + spec.Hostname,
		"HAVEN_IDP_LISTEN":            fmt.Sprintf(":%d", IdPPortHTTP),
		"HAVEN_IDP_TRUST_PROXY":       "1",
		"HAVEN_IDP_BOOTSTRAP_REALM":   spec.Bootstrap.FirstRealm,
		"HAVEN_IDP_BOOTSTRAP_USER":    bootstrapAdminUser,
		"HAVEN_IDP_CONSOLE_REDIRECTS": "https://" + consoleHost(spec) + consoleCallbackSuffix,
		"HAVEN_IDP_METRICS_LISTEN":    fmt.Sprintf(":%d", IdPPortMetrics),
		"HAVEN_IDP_AUDIT":             "stdout",
	}
}

// IdPConfigHash hashes the non-secret configuration so a change rolls the pods.
func IdPConfigHash(spec *v1alpha1.IdentityPlaneSpec) string {
	env := idpPlainEnv(spec)
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%s\n", k, env[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func secretEnv(name, secret, key string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{
		SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: secret}, Key: key,
		},
	}}
}

// idpEnv lists the container env in contract order.
func idpEnv(plane string, spec *v1alpha1.IdentityPlaneSpec) []corev1.EnvVar {
	p := idpPlainEnv(spec)
	plain := func(n string) corev1.EnvVar { return corev1.EnvVar{Name: n, Value: p[n]} }
	app, db := IdPName(plane), IdPDBSecretName(plane)
	return []corev1.EnvVar{
		plain("HAVEN_IDP_BASE_URL"),
		plain("HAVEN_IDP_LISTEN"),
		secretEnv("HAVEN_IDP_DSN", db, DBSecretKeyDSN),
		secretEnv("HAVEN_IDP_CSRF_KEY", app, SecretKeyCSRF),
		secretEnv("HAVEN_IDP_SECRET_KEY", app, SecretKeySecret),
		plain("HAVEN_IDP_TRUST_PROXY"),
		plain("HAVEN_IDP_BOOTSTRAP_REALM"),
		plain("HAVEN_IDP_BOOTSTRAP_USER"),
		secretEnv("HAVEN_IDP_BOOTSTRAP_PASSWORD", app, SecretKeyAdminPass),
		secretEnv("HAVEN_IDP_ADMIN_CLIENT_SECRET", app, SecretKeyAdminClient),
		plain("HAVEN_IDP_CONSOLE_REDIRECTS"),
		plain("HAVEN_IDP_METRICS_LISTEN"),
		plain("HAVEN_IDP_AUDIT"),
	}
}

func idpMeta(plane *v1alpha1.IdentityPlane) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      IdPName(plane.Name),
		Namespace: plane.Namespace,
		Labels:    IdPLabels(plane.Name),
	}
}

// IdPDeployment renders the haven-idp Deployment. image is the resolved image
// and replicas the effective replica count (0 when suspended).
func IdPDeployment(plane *v1alpha1.IdentityPlane, image string, replicas int32) *appsv1.Deployment {
	spec := profiles.Merge(&plane.Spec)
	labels := IdPLabels(plane.Name)
	selector := IdPSelectorLabels(plane.Name)

	f := false
	t := true
	grace := int64(30)
	user := int64(IdPRunAsUser)
	maxUnavail := intstr.FromInt32(0)
	maxSurge := intstr.FromInt32(1)

	probe := func(path string, initial, period, failure int32) *corev1.Probe {
		return &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
				Path: path, Port: intstr.FromString("http"),
			}},
			InitialDelaySeconds: initial, PeriodSeconds: period, TimeoutSeconds: 3, FailureThreshold: failure,
		}
	}

	podSpec := corev1.PodSpec{
		ServiceAccountName:            IdPName(plane.Name),
		AutomountServiceAccountToken:  &f,
		TerminationGracePeriodSeconds: &grace,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   &t,
			RunAsUser:      &user,
			RunAsGroup:     &user,
			FSGroup:        &user,
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{{
			Name:  idpContainerName,
			Image: image,
			Args:  []string{"serve"},
			Ports: []corev1.ContainerPort{
				{Name: "http", ContainerPort: IdPPortHTTP, Protocol: corev1.ProtocolTCP},
				{Name: "metrics", ContainerPort: IdPPortMetrics, Protocol: corev1.ProtocolTCP},
			},
			Env:            idpEnv(plane.Name, &spec),
			Resources:      spec.IdP.Resources,
			LivenessProbe:  probe("/healthz", 10, 10, 3),
			ReadinessProbe: probe("/readyz", 5, 5, 3),
			SecurityContext: &corev1.SecurityContext{
				RunAsNonRoot:             &t,
				RunAsUser:                &user,
				ReadOnlyRootFilesystem:   &t,
				AllowPrivilegeEscalation: &f,
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			VolumeMounts: []corev1.VolumeMount{{Name: "tmp", MountPath: "/tmp"}},
		}},
		Volumes: []corev1.Volume{{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
	}
	if replicas > 1 {
		podSpec.Affinity = &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
				Weight: 100,
				PodAffinityTerm: corev1.PodAffinityTerm{
					LabelSelector: &metav1.LabelSelector{MatchLabels: selector},
					TopologyKey:   "kubernetes.io/hostname",
				},
			}},
		}}
		podSpec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{
			MaxSkew:           1,
			TopologyKey:       "kubernetes.io/hostname",
			WhenUnsatisfiable: corev1.ScheduleAnyway,
			LabelSelector:     &metav1.LabelSelector{MatchLabels: selector},
		}}
	}

	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: idpMeta(plane),
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &maxUnavail, MaxSurge: &maxSurge,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels,
					Annotations: map[string]string{AnnotationConfigHash: IdPConfigHash(&spec)},
				},
				Spec: podSpec,
			},
		},
	}
}

func IdPService(plane *v1alpha1.IdentityPlane) *corev1.Service {
	return &corev1.Service{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: idpMeta(plane),
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: IdPSelectorLabels(plane.Name),
			Ports: []corev1.ServicePort{
				{Name: "http", Port: IdPPortHTTP, TargetPort: intstr.FromString("http"), Protocol: corev1.ProtocolTCP},
				{Name: "metrics", Port: IdPPortMetrics, TargetPort: intstr.FromString("metrics"), Protocol: corev1.ProtocolTCP},
			},
		},
	}
}

func IdPServiceAccount(plane *v1alpha1.IdentityPlane) *corev1.ServiceAccount {
	f := false
	return &corev1.ServiceAccount{
		TypeMeta:                     metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
		ObjectMeta:                   idpMeta(plane),
		AutomountServiceAccountToken: &f,
	}
}

// IdPPodDisruptionBudget returns nil when replicas <= 1.
func IdPPodDisruptionBudget(plane *v1alpha1.IdentityPlane, replicas int32) *policyv1.PodDisruptionBudget {
	if replicas <= 1 {
		return nil
	}
	one := intstr.FromInt32(1)
	return &policyv1.PodDisruptionBudget{
		TypeMeta:   metav1.TypeMeta{APIVersion: "policy/v1", Kind: "PodDisruptionBudget"},
		ObjectMeta: idpMeta(plane),
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &one,
			Selector:       &metav1.LabelSelector{MatchLabels: IdPSelectorLabels(plane.Name)},
		},
	}
}

// IdPSecret is the app Secret; values holds the generated csrf-key,
// admin-password and admin-client-secret (any subset).
func IdPSecret(plane *v1alpha1.IdentityPlane, values map[string]string) *corev1.Secret {
	data := make(map[string][]byte, len(values))
	for k, v := range values {
		data[k] = []byte(v)
	}
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: idpMeta(plane),
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
}

// IdPDSN builds the connection string from the database password.
func IdPDSN(plane *v1alpha1.IdentityPlane, password string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=require",
		IdPDBName, url.QueryEscape(password), DBHost(plane.Name, plane.Namespace), IdPDBName)
}

// IdPDBSecret is the database Secret read by haven-idp (username, password, dsn).
func IdPDBSecret(plane *v1alpha1.IdentityPlane, password string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name: IdPDBSecretName(plane.Name), Namespace: plane.Namespace, Labels: IdPLabels(plane.Name),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			DBSecretKeyUsername: []byte(IdPDBName),
			DBSecretKeyPassword: []byte(password),
			DBSecretKeyDSN:      []byte(IdPDSN(plane, password)),
		},
	}
}

// IdPEnvLeaks reports whether secret occurs in any literal env value.
func IdPEnvLeaks(env []corev1.EnvVar, secret string) bool {
	for _, e := range env {
		if e.Value != "" && strings.Contains(e.Value, secret) {
			return true
		}
	}
	return false
}

// DefaultCNPGNamespace is where the CloudNativePG operator runs unless the
// controller is told otherwise (HAVEN_CNPG_NAMESPACE).
const DefaultCNPGNamespace = "cnpg-system"

// DBNetworkPolicyName is the name of the database NetworkPolicy.
func DBNetworkPolicyName(plane string) string { return DBClusterName(plane) + "-ingress" }

// DBNetworkPolicy restricts who may open connections to the plane's PostgreSQL
// pods. It is INGRESS ONLY on purpose: haven-idp itself must keep reaching the
// outside (federation upstreams, back-channel logout, SMTP), so no egress rule is
// ever generated.
//
// Allowed sources, and nothing else:
//   - the plane's haven-idp pods (5432);
//   - the other members of the same CNPG cluster (5432 replication, 8000 status);
//   - the CloudNativePG operator's namespace (5432 and 8000: the operator reads
//     instance status and manages the cluster).
//
// Nil when the plane has network policies switched off.
func DBNetworkPolicy(plane *v1alpha1.IdentityPlane, operatorNamespace string) *networkingv1.NetworkPolicy {
	if operatorNamespace == "" {
		operatorNamespace = DefaultCNPGNamespace
	}
	tcp := corev1.ProtocolTCP
	port := func(n int32) networkingv1.NetworkPolicyPort {
		p := intstr.FromInt32(n)
		return networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &p}
	}
	cluster := map[string]string{"cnpg.io/cluster": DBClusterName(plane.Name)}
	return &networkingv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: DBNetworkPolicyName(plane.Name), Namespace: plane.Namespace, Labels: planeLabels(plane.Name)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: cluster},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From:  []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: IdPSelectorLabels(plane.Name)}}},
					Ports: []networkingv1.NetworkPolicyPort{port(5432)},
				},
				{
					From:  []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: cluster}}},
					Ports: []networkingv1.NetworkPolicyPort{port(5432), port(8000)},
				},
				{
					From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"kubernetes.io/metadata.name": operatorNamespace}}}},
					Ports: []networkingv1.NetworkPolicyPort{port(5432), port(8000)},
				},
			},
		},
	}
}
