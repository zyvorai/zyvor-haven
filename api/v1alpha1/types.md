# API types (Go sketch)

The controller is intended to be a kubebuilder project. Types match `config/crd`.

```go
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type PlaneProfile string

const (
    ProfileDev        PlaneProfile = "dev"
    ProfileStaging    PlaneProfile = "staging"
    ProfileProduction PlaneProfile = "production"
)

type IdentityPlaneSpec struct {
    Profile         PlaneProfile     `json:"profile,omitempty"`
    Hostname        string           `json:"hostname"`
    ConsoleHostname string           `json:"consoleHostname,omitempty"`
    Database        DatabaseSpec     `json:"database,omitempty"`
    Keycloak        KeycloakSpec     `json:"keycloak,omitempty"`
    Expose          ExposeSpec       `json:"expose,omitempty"`
    Bootstrap       BootstrapSpec    `json:"bootstrap,omitempty"`
    Observability   ObservabilitySpec `json:"observability,omitempty"`
}

type IdentityPlaneStatus struct {
    Phase              string             `json:"phase,omitempty"`
    ObservedGeneration int64              `json:"observedGeneration,omitempty"`
    Endpoints          EndpointsStatus    `json:"endpoints,omitempty"`
    Database           DatabaseStatus     `json:"database,omitempty"`
    Keycloak           KeycloakStatus     `json:"keycloak,omitempty"`
    Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// Reconcile is ordered and idempotent:
//
//  1. Ensure namespace label haven.identity/managed=true
//  2. Render CNPG Cluster from spec.database + profile defaults
//  3. Wait Cluster ready; project CA ConfigMap + JDBC Secret
//  4. Ensure TLS Certificate or consume spec.expose.tls.secretName
//  5. Render Keycloak CR; wait instances ready
//  6. Ensure bootstrap RealmBundle + OidcClients
//  7. Ensure console Deployment bound to haven-console client
//  8. Update status.phase and endpoints
//
// Owned objects use controller references so GC works.
// Deletion of IdentityPlane is blocked by a finalizer until
// spec.reclaimPolicy is set (v1: orphan DB by default).
```

Profile defaults live in `internal/profiles/defaults.go`:

| Field | dev | staging | production |
|---|---|---|---|
| database.instances | 1 | 2 | 3 |
| keycloak.instances | 1 | 2 | 3 |
| database.storage | 8Gi | 20Gi | 50Gi |
| expose.networkPolicy | false | true | true |
| keycloak pool | 8 | 16 | 30 |
| backup | off | daily | daily + require destination |
