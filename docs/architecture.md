---
hero:
  eyebrow: ARCHITECTURE
  title: Haven architecture
---

Technical design: CRDs, reconciliation, profiles, and trust boundaries. For operations, start with [Getting started](getting-started.md) or the [Runbook](runbook.md).

## Goal

Make an identity server and its PostgreSQL database deployable and operable as a **private-cloud product**, with UX quality comparable to [Zyvor Zeus OS](https://zyvor.dev): one console, one intent object, day-2 operations that do not require reading several operators' docs.

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
│   postgresql.cnpg.io    Deployment          cert-manager        │
│   Cluster               platform-idp        Certificate         │
│          │                   │                   │              │
│          ▼                   ▼                   ▼              │
│   Postgres HA           haven-idp pods       TLS secret         │
│   backups / PITR        realms / clients     Gateway / Ingress  │
└─────────────────────────────────────────────────────────────────┘
```

Haven is a **composition operator** around its own identity server, `haven-idp`. It owns the *plane*: database, identity server, exposure, bootstrap, backup coupling, and the console that talks to both. The server itself is described in [own-idp-roadmap.md](own-idp-roadmap.md); the exact object names and environment the controller renders are fixed by `internal/render/IDP_CONTRACT.md`.

## Custom resources

### IdentityPlane

The root object. One plane is one `haven-idp` Deployment + one PostgreSQL cluster + how the world reaches them.

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
    vendor: postgres           # only postgres
    instances: 3
    storage: 50Gi
    storageClass: ceph-block
    backup:
      destination: s3://haven-backups/platform
      schedule: "0 0 2 * * *"
      retention: 14d
  idp:
    replicas: 3                # defaults from the profile
    # image: ghcr.io/zyvorai/haven-idp:0.1.0   # defaults to HAVEN_IDP_IMAGE
  expose:
    class: gateway             # ingress | gateway | none
    tls:
      issuerRef: { kind: ClusterIssuer, name: private-ca }
    networkPolicy: true
  bootstrap:
    adminEmail: platform@cloud.internal
    firstRealm: platform
  observability:
    metrics: true
    tracing: true
status:
  phase: Ready
  conditions:
    - type: DatabaseReady
      status: "True"
    - type: CertificateReady
      status: "True"
    - type: IdentityProviderReady
      status: "True"
```

Status also carries `endpoints` (idp, issuer, console), `database` (primary, replicas, last backup), `idp` (instances, ready, version) and `tls`. Phases are `Pending`, `ProvisioningDatabase`, `ProvisioningIdP`, `Bootstrapping`, `Ready`, `Degraded`, `Failed` and `Suspending`.

### OIDCClient

A client that belongs to a realm and must exist for platform SSO. The controller creates the client in `haven-idp` and writes a Secret the workload can mount (`client-id`, `client-secret`, `issuer`). See [OIDCClient CRD](oidcclient-crd.md) and [Ingress registration](ingress-registration.md).

There is no RealmBundle type. Declare realm settings, roles and groups with [config as code](config-as-code.md).

## Reconciliation order

1. Resolve the profile defaults (replicas, storage, resources, NetworkPolicy).
2. Generate the database password and the secrets `platform-db-app`, `platform-idp-db` and `platform-idp` (each value is created once and **never overwritten** on later reconciles).
3. CloudNativePG `Cluster` `platform-db` (database and owner `haven_idp`), plus the backup settings from `spec.database.backup`.
4. Issue the TLS certificate for the hostname (cert-manager), or consume `spec.expose.tls.secretName`.
5. Deployment, Service, ServiceAccount and (for more than one replica) a PodDisruptionBudget, all named `<plane>-idp`. Schema migrations run inside `haven-idp` at start-up under an advisory lock, so there is no migration Job.
6. The database NetworkPolicy: only the plane's `haven-idp` pods, the cluster's own members and the CloudNativePG operator namespace may reach Postgres.
7. Project status: conditions `DatabaseReady`, `CertificateReady`, `IdentityProviderReady`, and the phase. Subsequent reconciles are drift-correct only, requeued every 60 seconds once Ready (20 seconds before).

Failure at any step is a Condition with a human reason (for example `CNPGMissing`, `DatabaseNotReady`, `DeploymentMissing`, or the pod's waiting reason such as `ImagePullBackOff`), surfaced on the Command Deck, not a crash-loop of YAML. `spec.suspend` scales `haven-idp` to zero and leaves the database alone.

## Profiles

| | `dev` | `staging` | `production` |
|---|---|---|---|
| Postgres instances | 1 | 2 | 3 |
| `haven-idp` replicas | 1 | 2 | 3 |
| Storage | 8Gi | 20Gi | 50Gi |
| TLS | self-signed / nip.io | cert-manager | private CA or public |
| Backups | off | required | required |
| NetworkPolicy | off | on | on |
| PDB / anti-affinity | off (1 replica) | on | on |

Profiles are starting points. Every field is overridable.

## Why CloudNativePG

It gives:

- Primary + streaming replicas without Patroni sidecar folklore
- Operator-driven failover
- Native backups / WAL archiving / PITR
- TLS between `haven-idp` and Postgres (the DSN uses `sslmode=require`)
- Status on the Kubernetes API, which Haven projects into the console

`haven-idp` keeps all of its state in Postgres, so a CNPG backup is a `haven-idp` backup, and its replicas stay stateless. Haven's controller never treats SQL as the source of truth for the plane; it talks the CNPG API.

## Trust and exposure

```
browser ──TLS──► Gateway / Ingress ──► haven-idp service :8081
                      │
                      └──► Haven console :8080  (OIDC to haven-idp)

haven-idp pods ──TLS──► CNPG rw service :5432
Prometheus ──► haven-idp :9100 (metrics)
```

- `haven-idp` always sits behind the ingress/gateway, so the controller sets `HAVEN_IDP_TRUST_PROXY=1`.
- The pod runs as non-root (uid 65532) with a read-only root filesystem, all capabilities dropped, a `RuntimeDefault` seccomp profile and no service-account token mounted.
- NetworkPolicy (production overlay): ingress to `haven-idp` only from the gateway namespace and the console, plus Prometheus on the metrics port; only `haven-idp`, the cluster members and the operator may reach Postgres.

## Observability

`haven-idp` serves Prometheus metrics on a separate port (9100), writes a hash-chained audit stream as JSON lines to stdout, and supports W3C tracing with OTLP export. Dashboards, alert rules and a `ServiceMonitor` live in `deploy/observability/`; see [observability.md](observability.md). The Command Deck graphs plane state from the IdentityPlane status.

## Multi-cluster / multi-site (v2)

Not built, designed in:

- One IdentityPlane per site
- Shared logical realm across sites with active-passive CNPG replica clusters
- Haven status aggregates both sites for the console

Today a plane is single-cluster, multi-AZ.

## Security model

- The controller's ClusterRole is scoped to what the plane needs (Deployments, Services, Secrets, CNPG clusters, certificates); see `internal/controller/RBAC.md`.
- The bootstrap admin password is generated into a Secret (`platform-idp`, key `admin-password`); `./cli/haven admin` prints the command that reads it.
- Secrets (`csrf-key`, `secret-key`, `admin-client-secret`) are generated once and never overwritten. Rotating one is a deliberate operator action. `secret-key` encrypts TOTP seeds and upstream IdP secrets; losing it makes them unreadable.
- No admin password in Git. Ever.
- `spec.reclaimPolicy` defaults to `Orphan`. Deleting an IdentityPlane must not drop PostgreSQL.

## Upgrading from a release with the Keycloak engine

Earlier builds could run a plane on the Keycloak Operator (`spec.engine: keycloak`) and the console could talk to a Keycloak Admin API. That engine is gone: `haven-idp` is the only identity server.

- **IdentityPlane objects**: `spec.engine`, `spec.keycloak` and `status.keycloak` (plus `status.endpoints.keycloak|account|admin`) no longer exist in the CRD. Re-apply the CRD (`charts/haven/crds` or `config/crd`); the API server then prunes the stale fields from stored objects and your manifests keep working. Drop those fields from manifests you keep in Git so they stay clean. The `ProvisioningKeycloak` phase and the `KeycloakReady` condition are gone; planes report `IdentityProviderReady`.
- **RealmBundle** is removed from the CRD bundle (nothing reconciled it). Delete leftover `realmbundles.identity.haven.dev` objects and the CRD itself after upgrading.
- **A plane that still runs Keycloak** is not converted by the controller. Migrate it first with `haven-idp import-keycloak` ([migrate-from-keycloak.md](migrate-from-keycloak.md)); a controller that finds such a plane reconciles it as a `haven-idp` plane and would point it at a new, empty `haven_idp` database.
- **Console and API move together**: the routes `/api/v1/keycloak/{status,config,connect,admin-password}` are now `/api/v1/identity-server/...`, the field `keycloakUrl` is `identityServerUrl` and the error body field `keycloak` is `identityServer`. Upgrade the console image and the UI together; an old UI against the new API (or the reverse) shows the identity server as offline. The console no longer reads `KEYCLOAK_URL`, `KEYCLOAK_ADMIN_USER` or `KEYCLOAK_ADMIN_PASSWORD`, and `HAVEN_IDP_BACKEND` accepts only `native` (or unset).
- **Helm values**: `identity.backend` is removed; the chart always wires the console to `haven-idp`.

## Non-goals

- Managing LDAP servers
- Being a general Postgres platform
- SAML and LDAP federation (not started; see [own-idp-roadmap.md](own-idp-roadmap.md))
