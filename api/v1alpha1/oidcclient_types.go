// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DeletionPolicy decides what happens to the IdP client when the OIDCClient
// is deleted.
type DeletionPolicy string

const (
	DeletionDelete DeletionPolicy = "Delete"
	DeletionRetain DeletionPolicy = "Retain"
)

// PlaneRef points at the IdentityPlane that hosts the client.
type PlaneRef struct {
	Name string `json:"name"`
	// Namespace defaults to the OIDCClient's namespace. A different namespace
	// is honoured only when the plane lists the client's namespace in the
	// annotation haven.zyvor.dev/allow-oidcclients-from.
	Namespace string `json:"namespace,omitempty"`
}

// OIDCClientFlows selects the grants the client may use.
type OIDCClientFlows struct {
	// AuthorizationCode defaults to true unless the client is a pure service
	// account (serviceAccount true and no redirectUris).
	AuthorizationCode *bool `json:"authorizationCode,omitempty"`
	// ClientCredentials enables the service account; it is the same switch as
	// spec.serviceAccount.
	ClientCredentials *bool `json:"clientCredentials,omitempty"`
}

// OIDCClientSecretKeys names the keys written to the Secret.
type OIDCClientSecretKeys struct {
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
}

// OIDCClientSecretRef is where the generated client secret is written.
type OIDCClientSecretRef struct {
	// Name defaults to <metadata.name>-oidc.
	Name string               `json:"name,omitempty"`
	Keys OIDCClientSecretKeys `json:"keys,omitempty"`
}

type OIDCClientSpec struct {
	PlaneRef PlaneRef `json:"planeRef"`
	// Realm defaults to the plane's first realm.
	Realm string `json:"realm,omitempty"`
	// ClientID defaults to metadata.name.
	ClientID     string   `json:"clientId,omitempty"`
	DisplayName  string   `json:"displayName,omitempty"`
	Public       bool     `json:"public,omitempty"`
	RedirectURIs []string `json:"redirectUris,omitempty"`
	WebOrigins   []string `json:"webOrigins,omitempty"`
	// PKCE defaults to true. Only S256 exists; false is rejected for public
	// clients.
	PKCE           *bool            `json:"pkce,omitempty"`
	ServiceAccount bool             `json:"serviceAccount,omitempty"`
	Flows          *OIDCClientFlows `json:"flows,omitempty"`
	// BackchannelLogoutURL is accepted and validated but NOT yet sent to the
	// IdP (the Admin API client type has no such field in this release).
	BackchannelLogoutURL string `json:"backchannelLogoutUrl,omitempty"`
	// SecretRef is used for confidential clients only.
	SecretRef *OIDCClientSecretRef `json:"secretRef,omitempty"`
	// DeletionPolicy defaults to Delete.
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

type OIDCClientStatus struct {
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	ClientUUID         string             `json:"clientUuid,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Issuer             string             `json:"issuer,omitempty"`
	SecretName         string             `json:"secretName,omitempty"`
	LastSyncTime       *metav1.Time       `json:"lastSyncTime,omitempty"`
	// Plane, Realm and ClientID record what was created so a later edit of
	// those immutable fields is reported instead of orphaning the client.
	Plane    string `json:"plane,omitempty"`
	Realm    string `json:"realm,omitempty"`
	ClientID string `json:"clientId,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=oidc

type OIDCClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OIDCClientSpec   `json:"spec,omitempty"`
	Status            OIDCClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type OIDCClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCClient `json:"items"`
}
