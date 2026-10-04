// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	Group   = "identity.haven.dev"
	Version = "v1alpha1"
)

var (
	GroupVersion  = schema.GroupVersion{Group: Group, Version: Version}
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

type PlaneProfile string

const (
	ProfileDev        PlaneProfile = "dev"
	ProfileStaging    PlaneProfile = "staging"
	ProfileProduction PlaneProfile = "production"
)

type PlanePhase string

const (
	PhasePending              PlanePhase = "Pending"
	PhaseProvisioningDatabase PlanePhase = "ProvisioningDatabase"
	PhaseProvisioningKeycloak PlanePhase = "ProvisioningKeycloak"
	PhaseBootstrapping        PlanePhase = "Bootstrapping"
	PhaseReady                PlanePhase = "Ready"
	PhaseDegraded             PlanePhase = "Degraded"
	PhaseFailed               PlanePhase = "Failed"
	PhaseSuspending           PlanePhase = "Suspending"
)

type DatabaseSpec struct {
	Vendor       string     `json:"vendor,omitempty"`
	Instances    int        `json:"instances,omitempty"`
	Storage      string     `json:"storage,omitempty"`
	StorageClass string     `json:"storageClass,omitempty"`
	ImageName    string     `json:"imageName,omitempty"`
	Backup       BackupSpec `json:"backup,omitempty"`
}

type BackupSpec struct {
	Destination       string `json:"destination,omitempty"`
	Schedule          string `json:"schedule,omitempty"`
	Retention         string `json:"retention,omitempty"`
	EndpointURL       string `json:"endpointURL,omitempty"`
	CredentialsSecret string `json:"credentialsSecret,omitempty"`
}

type KeycloakSpec struct {
	Instances int                    `json:"instances,omitempty"`
	Version   string                 `json:"version,omitempty"`
	Image     string                 `json:"image,omitempty"`
	Features  []string               `json:"features,omitempty"`
	Resources map[string]interface{} `json:"resources,omitempty"`
	Raw       map[string]interface{} `json:"raw,omitempty"`
}

type TLSSpec struct {
	IssuerRef  *IssuerRef `json:"issuerRef,omitempty"`
	SecretName string     `json:"secretName,omitempty"`
}

type IssuerRef struct {
	Kind  string `json:"kind,omitempty"`
	Name  string `json:"name,omitempty"`
	Group string `json:"group,omitempty"`
}

type ExposeSpec struct {
	Class            string  `json:"class,omitempty"`
	IngressClassName string  `json:"ingressClassName,omitempty"`
	GatewayName      string  `json:"gatewayName,omitempty"`
	NetworkPolicy    *bool   `json:"networkPolicy,omitempty"`
	TLS              TLSSpec `json:"tls,omitempty"`
}

type BootstrapClientSpec struct {
	Name      string   `json:"name"`
	Type      string   `json:"type,omitempty"`
	Redirects []string `json:"redirects,omitempty"`
	Audiences []string `json:"audiences,omitempty"`
}

type BootstrapSpec struct {
	AdminEmail string                `json:"adminEmail,omitempty"`
	FirstRealm string                `json:"firstRealm,omitempty"`
	Clients    []BootstrapClientSpec `json:"clients,omitempty"`
}

type ObservabilitySpec struct {
	Metrics bool `json:"metrics,omitempty"`
	Tracing bool `json:"tracing,omitempty"`
}

type IdentityPlaneSpec struct {
	Profile         PlaneProfile      `json:"profile,omitempty"`
	Hostname        string            `json:"hostname"`
	ConsoleHostname string            `json:"consoleHostname,omitempty"`
	ReclaimPolicy   string            `json:"reclaimPolicy,omitempty"`
	Suspend         bool              `json:"suspend,omitempty"`
	Database        DatabaseSpec      `json:"database,omitempty"`
	Keycloak        KeycloakSpec      `json:"keycloak,omitempty"`
	Expose          ExposeSpec        `json:"expose,omitempty"`
	Bootstrap       BootstrapSpec     `json:"bootstrap,omitempty"`
	Observability   ObservabilitySpec `json:"observability,omitempty"`
}

type EndpointsStatus struct {
	Keycloak string `json:"keycloak,omitempty"`
	Console  string `json:"console,omitempty"`
	Account  string `json:"account,omitempty"`
	Admin    string `json:"admin,omitempty"`
}

type DatabaseStatus struct {
	Primary    string `json:"primary,omitempty"`
	Replicas   int    `json:"replicas,omitempty"`
	LastBackup string `json:"lastBackup,omitempty"`
	Phase      string `json:"phase,omitempty"`
	Ready      int    `json:"ready,omitempty"`
	Instances  int    `json:"instances,omitempty"`
}

type KeycloakStatus struct {
	Instances int    `json:"instances,omitempty"`
	Ready     int    `json:"ready,omitempty"`
	Version   string `json:"version,omitempty"`
}

type TLSStatus struct {
	ExpiresAt     string `json:"expiresAt,omitempty"`
	DaysRemaining int    `json:"daysRemaining,omitempty"`
	SecretName    string `json:"secretName,omitempty"`
}

type IdentityPlaneStatus struct {
	Phase              PlanePhase         `json:"phase,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Endpoints          EndpointsStatus    `json:"endpoints,omitempty"`
	Database           DatabaseStatus     `json:"database,omitempty"`
	Keycloak           KeycloakStatus     `json:"keycloak,omitempty"`
	TLS                TLSStatus          `json:"tls,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=iplane

type IdentityPlane struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              IdentityPlaneSpec   `json:"spec,omitempty"`
	Status            IdentityPlaneStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type IdentityPlaneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IdentityPlane `json:"items"`
}

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &IdentityPlane{}, &IdentityPlaneList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
