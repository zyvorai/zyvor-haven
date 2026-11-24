# haven-idp deployment contract

Every deployment path (the controller, the kustomize overlays, the Helm chart)
renders the same names so tooling, NetworkPolicies and the console agree.
`<plane>` is the IdentityPlane / overlay name (the overlays use `platform`).

## Engine selection (controller)
`spec.engine`: `native` or `keycloak` (omitted = resolve at reconcile time:
`keycloak` if a Keycloak CR already exists for the plane, otherwise `native`).
An existing plane is therefore never switched silently. The Keycloak path stays
for migration and is deprecated; it is removed in a later release.

## Names and labels
| Object | Name |
|---|---|
| Deployment, Service, ServiceAccount, PodDisruptionBudget | `<plane>-idp` |
| Secret (app secrets) | `<plane>-idp` keys: `csrf-key`, `secret-key`, `admin-password`, `admin-client-secret` |
| Secret (database) | `<plane>-idp-db` keys: `username`, `password`, `dsn` |
| CNPG Cluster | `<plane>-db` (unchanged), database and owner `haven_idp` |
| CNPG bootstrap secret | `<plane>-db-app` (unchanged name), username `haven_idp` |

Labels on every object: `app.kubernetes.io/name: haven-idp`,
`app.kubernetes.io/instance: <plane>`, `app.kubernetes.io/part-of: haven`,
`app.kubernetes.io/component: identity`, plus the existing
`haven.identity/managed: "true"` and `haven.identity/plane: <plane>`.
Selector labels (immutable): `app.kubernetes.io/name`, `app.kubernetes.io/instance`.

## Pod
Container `haven-idp`, args `["serve"]`, ports `http` 8081 and `metrics` 9100.
Probes: liveness GET `/healthz`, readiness GET `/readyz` on `http`.
Security: runAsNonRoot (uid 65532), readOnlyRootFilesystem, no privilege
escalation, drop ALL capabilities, seccompProfile RuntimeDefault, no service
account token mounted (`automountServiceAccountToken: false`).
Replicas > 1 get a PodDisruptionBudget (`maxUnavailable: 1`) and a preferred
anti-affinity / topology spread across nodes.

## Environment (names are the haven-idp ones; secrets come from secretKeyRef)
| Variable | Source |
|---|---|
| `HAVEN_IDP_BASE_URL` | `https://<spec.hostname>` |
| `HAVEN_IDP_LISTEN` | `:8081` |
| `HAVEN_IDP_DSN` | secret `<plane>-idp-db` key `dsn` |
| `HAVEN_IDP_CSRF_KEY` | secret `<plane>-idp` key `csrf-key` |
| `HAVEN_IDP_SECRET_KEY` | secret `<plane>-idp` key `secret-key` (encrypts TOTP seeds and upstream IdP secrets; generated once like the others and **never regenerated**: losing it makes those secrets unreadable) |
| `HAVEN_IDP_TRUST_PROXY` | `1` (it always sits behind the ingress/gateway) |
| `HAVEN_IDP_BOOTSTRAP_REALM` | `spec.bootstrap.firstRealm` (default `platform`) |
| `HAVEN_IDP_BOOTSTRAP_USER` | `admin` |
| `HAVEN_IDP_BOOTSTRAP_PASSWORD` | secret `<plane>-idp` key `admin-password` |
| `HAVEN_IDP_ADMIN_CLIENT_SECRET` | secret `<plane>-idp` key `admin-client-secret` |
| `HAVEN_IDP_CONSOLE_REDIRECTS` | `https://<console host>/api/v1/auth/oidc/callback` |
| `HAVEN_IDP_METRICS_LISTEN` | `:9100` |
| `HAVEN_IDP_AUDIT` | `stdout` (JSON lines for the cluster log pipeline) |

Secrets are generated once (32 random bytes, base64url) and NEVER overwritten
on later reconciles, so rotating them is a deliberate operator action.
The database DSN is `postgres://haven_idp:<pw>@<plane>-db-rw.<ns>.svc:5432/haven_idp?sslmode=require`.
Migrations run inside `haven-idp` at start-up (advisory-locked), so there is no
migration Job.

## Image
`ghcr.io/zyvorai/haven-idp:<version>`; the controller reads the default from
`HAVEN_IDP_IMAGE` and `spec.idp.image` overrides it. Runs as the distroless
`nonroot` image, entrypoint `/haven-idp`, default command `serve`.

## Console
The console selects the backend with `HAVEN_IDP_BACKEND=native`,
`HAVEN_IDP_URL=http://<plane>-idp.<ns>.svc:8081`, `HAVEN_IDP_ADMIN_REALM`, and
`HAVEN_IDP_ADMIN_CLIENT_SECRET` from secret `<plane>-idp` key `admin-client-secret`.

## NetworkPolicy (prod)
Ingress to `haven-idp` pods: from the ingress/gateway namespace on 8081, from
the console pods on 8081, from the monitoring namespace on 9100. Egress: DNS,
the CNPG cluster on 5432, and the collector if tracing is enabled.
