---
hero:
  eyebrow: ARCHITECTURE
  title: Haven architecture
---

Technical design: CRDs, reconciliation, profiles, and trust boundaries. For operations, start with [Getting started](getting-started.md) or the [Runbook](runbook.md).

## Goal

Make Keycloak + PostgreSQL deployable and operable as a **private-cloud product**, with UX quality comparable to [Zyvor Zeus OS](https://zyvor.dev): one console, one intent object, day-2 operations that do not require reading three operators' docs.

## System context

```
┌─────────────────────────────────────────────────────────────────┐
│                        Private cloud                            │
│  Zeus OS / platform console / GitOps / haven CLI                │
│                              │                                  │
│                              ▼                                  │
│                    IdentityPlane (CR)                           │
│                              │                                  │
│                     Haven controller                            │
│          ┌───────────────────┼───────────────────┐              │
│          ▼                   ▼                   ▼              │
│   postgresql.cnpg.io    k8s.keycloak.org    cert-manager        │
│   Cluster               Keycloak            Certificate         │
│          │                   │                   │              │
│          ▼                   ▼                   ▼              │
│   Postgres HA           Keycloak pods        TLS secret         │
│   backups / PITR        realms / clients     Gateway / Ingress  │
└─────────────────────────────────────────────────────────────────┘
```

Haven is a **composition operator**. It does not replace Keycloak. It owns the *plane*: database, identity server, exposure, bootstrap, backup coupling, and the console that talks to both.

## Custom resources

### IdentityPlane

The root object. One plane ≈ one Keycloak cluster + one PostgreSQL cluster + how the world reaches them.

```yaml
apiVersion: identity.haven.dev/v1alpha1
kind: IdentityPlane
metadata:
  name: platform
  namespace: identity
spec:
  profile: production          # dev | staging | production
  hostname: auth.cloud.internal
  consoleHostname: haven.cloud.internal
  database:
    vendor: postgres           # only postgres in v1
    instances: 3
    storage: 50Gi
    storageClass: ceph-block
    backup:
      destination: s3://haven-backups/platform
      schedule: "0 2 * * *"
      retention: 14d
  keycloak:
    instances: 3
    version: "26.3.3"
    features: [persistent-user-sessions, opentelemetry]
    resources:
      requests: { cpu: "1", memory: 1250Mi }
      limits:   { cpu: "4", memory: 2250Mi }
  expose:
    class: gateway             # ingress | gateway | none
    tls:
      issuerRef: { kind: ClusterIssuer, name: private-ca }
    networkPolicy: true
  bootstrap:
    adminEmail: platform@cloud.internal
    firstRealm: platform
    clients:
      - name: zeus-os
        type: public
        redirects: ["https://zeus.cloud.internal/*"]
      - name: kubernetes
        type: confidential
        audiences: ["https://kubernetes.default.svc"]
status:
  phase: Ready
  endpoints:
    keycloak: https://auth.cloud.internal
    console: https://haven.cloud.internal
    account: https://auth.cloud.internal/realms/platform/account
  database:
    primary: platform-db-rw.identity.svc
    replicas: 2
    lastBackup: "2026-08-27T02:00:11Z"
  conditions:
    - type: DatabaseReady
      status: "True"
    - type: KeycloakReady
      status: "True"
    - type: EndpointReady
      status: "True"
```

### RealmBundle

Declarative realm (users optional, clients, roles, IdPs, theme). Applied via Keycloak Realm Import CR plus a small Haven overlay for things the import job does not cover (client secrets stored as K8s secrets, rotation).

### OidcClient

A client that belongs to a realm and must exist for platform SSO. Controller ensures the client in Keycloak and writes a Secret the workload can mount (`client-id`, `client-secret`, `issuer`).

## Reconciliation order

1. Namespace + NetworkPolicies (default-deny + DNS + CNPG + Keycloak + ingress controller).
2. CloudNativePG `Cluster` + `ScheduledBackup` + bootstrap roles (`keycloak` app user, `haven` ops user).
3. Wait `Cluster.status.phase == Cluster in healthy state`.
4. Copy CA of the Postgres cluster into a ConfigMap in the Keycloak namespace; create JDBC user secret.
5. Issue TLS cert for hostname (cert-manager).
6. Apply `Keycloak` CR: vendor postgres, TLS verify-server, pool sizes from profile, instances, metrics.
7. Wait Keycloak StatefulSet/Deployment ready; read `-initial-admin` secret.
8. Apply `RealmBundle` for `bootstrap.firstRealm` + platform `OidcClient` list.
9. Deploy Haven console (OAuth against that realm).
10. Mark `Ready`. Subsequent reconciles are drift-correct only.

Failure at any step is a Condition with a human reason, surfaced on the Command Deck — not a crash-loop of YAML.

## Profiles

| | `dev` | `staging` | `production` |
|---|---|---|---|
| Postgres instances | 1 | 2 | 3 |
| Keycloak instances | 1 | 2 | 3 |
| Storage | 8Gi | 20Gi | 50Gi+ |
| TLS | self-signed / nip.io | cert-manager | private CA or public |
| Backups | off | daily | daily + PITR |
| NetworkPolicy | optional | on | on |
| Pool size | 8 | 16 | 30 |
| PDB / anti-affinity | off | on | on |

Profiles are starting points. Every field is overridable.

## Why CloudNativePG

Keycloak's own HA guides use CloudNativePG. It gives:

- Primary + streaming replicas without Patroni sidecar folklore
- Operator-driven failover
- Native backups / WAL archiving / PITR
- TLS between Keycloak and Postgres (`db-tls-mode: verify-server`)
- Status on the Kubernetes API — Haven can project it into the console

Haven never talks SQL as the source of truth. It talks the CNPG API.

## Why the official Keycloak Operator

- `Keycloak` and `KeycloakRealmImport` CRDs (`k8s.keycloak.org/v2beta1` from Operator 26.6+; `v2alpha1` still served)
- Rolling updates, health, ServiceMonitor
- Version-aligned images
- Multi-AZ scheduling in recent releases

Haven generates those CRs. Advanced Keycloak knobs (`additionalOptions`, custom image, cache) pass through `spec.keycloak.raw` so we do not invent a parallel config language.

## Trust and exposure

```
browser ──TLS──► Gateway / Ingress ──► Keycloak service :8443
                      │
                      └──► Haven console :8080  (OIDC to Keycloak)

Keycloak pods ──TLS──► CNPG rw service :5432
```

- Passthrough TLS preferred in production so Keycloak sees the client cert path cleanly.
- `proxy.headers: xforwarded` when edge-terminating.
- NetworkPolicy: only ingress controller and Haven console may reach Keycloak HTTP; only Keycloak and Haven may reach Postgres.

## Observability

When Prometheus Operator CRDs exist, Haven asks both operators to emit ServiceMonitors:

- Keycloak: `metrics-enabled`, user event metrics
- CNPG: PodMonitor (field `monitoring.enablePodMonitor` is deprecated in 1.27.1 — prefer a hand-written PodMonitor)
- Haven controller: reconcile latency, plane phase, backup age

The Command Deck graphs those as Orbit cards: **login RPS**, **DB lag**, **session cache hit**, **backup age**, **certificate days-to-expiry**.

## Multi-cluster / multi-site (v2)

Not in v1 controller, designed in:

- One IdentityPlane per site
- Shared logical realm via Keycloak multi-site HA guides (stateless feature + shared DB *or* active-passive CNPG replica cluster)
- Haven status aggregates both sites for the console

v1 is single-cluster, multi-AZ.

## Security model

- Controller SA can create CNPG/Keycloak/Certificate objects only in namespaces labeled `haven.identity/managed=true`.
- Bootstrap admin password is a Secret; console shows it **once**.
- Realm mutations from the UI create a `RealmBundle` diff and, in production profile, an Approval.
- No Keycloak master password in Git. Ever.
- `spec.reclaimPolicy` defaults to `Orphan`. Deleting an IdentityPlane must not drop PostgreSQL.

## Non-goals (v1)

- Replacing the Keycloak Admin Console for every last SPI
- Managing LDAP servers
- Being a general Postgres platform
- Multi-Keycloak-version on one cluster (upstream operator limitation)
