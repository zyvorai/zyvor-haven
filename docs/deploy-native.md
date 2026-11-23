# Deploy haven-idp on Kubernetes

haven-idp is Haven's own OIDC server and the default identity engine
(`spec.engine: native`). This page takes a cluster that already has
[CloudNativePG](https://cloudnative-pg.io) and [cert-manager](https://cert-manager.io)
to a running plane. Names and labels used here are fixed by
`internal/render/IDP_CONTRACT.md`.

!!! note "Images"
    The controller runs `ghcr.io/zyvorai/haven-idp:<version>` (set by the
    `HAVEN_IDP_IMAGE` environment variable, overridable per plane with
    `spec.idp.image`). The image is distroless, runs as uid 65532 and needs no
    migration Job: schema migrations run inside `haven-idp` at start-up.

## 1. Operators and CRDs

```bash
./deploy/operators/install.sh      # CNPG + cert-manager. Keycloak operator is NOT installed.
make crds
```

`INSTALL_KEYCLOAK_OPERATOR=1 ./deploy/operators/install.sh` additionally installs the
deprecated Keycloak operator; you only need it while migrating
([migrate-from-keycloak.md](migrate-from-keycloak.md)).

## 2. Controller and console

```bash
helm install haven oci://ghcr.io/zyvorai/charts/haven --version 0.1.0 \
  --namespace haven-system --create-namespace \
  --set controller.enabled=true --set console.enabled=true
```

The chart defaults to `identity.backend: native`, so the console talks to
`http://platform-idp.identity.svc:8081` and reads its admin client secret from
Secret `platform-idp`. Override with `identity.url`, `identity.adminRealm` and
`identity.adminClientSecretRef` if your plane is not called `platform` in `identity`.

## 3. Apply a minimal plane

```yaml
apiVersion: v1
kind: Namespace
metadata: {name: identity}
---
apiVersion: identity.haven.dev/v1alpha1
kind: IdentityPlane
metadata: {name: platform, namespace: identity}
spec:
  engine: native
  profile: dev
  hostname: auth.127.0.0.1.nip.io
  consoleHostname: haven.127.0.0.1.nip.io
  database: {vendor: postgres, instances: 1, storage: 8Gi}
  expose: {class: ingress}
  bootstrap: {firstRealm: platform}
```

```bash
kubectl apply -f plane.yaml
make wait          # CNPG Ready, then IdentityProviderReady and the Deployment rollout
make doctor
```

The controller creates the CNPG cluster `platform-db` (database and owner `haven_idp`), the
Secrets `platform-idp` and `platform-idp-db` (32 random bytes each, generated once and never
overwritten on later reconciles), and the Deployment, Service, ServiceAccount and
PodDisruptionBudget `platform-idp`. `spec.engine` omitted resolves to `keycloak` if a
Keycloak CR for the plane already exists, otherwise `native`: an existing plane is never
switched silently.

!!! tip "No cluster controller"
    `make dev` applies `deploy/overlays/dev`, which renders the same objects with
    `CHANGE_ME_DEV_ONLY` placeholder secrets. Dev only. Do not combine it with an
    IdentityPlane for the same name.

## 4. Reach the console and first login

```bash
bash cli/haven open platform -n identity       # prints issuer and console URL
```

Browse to the console host and sign in through the `platform` realm as user `admin`. Read the
password without printing it into logs by running the command that `haven admin` shows:

```bash
bash cli/haven admin platform -n identity
# admin user: admin
# kubectl -n identity get secret platform-idp -o jsonpath='{.data.admin-password}' | base64 -d; echo
```

`haven admin --show-secret` prints the value itself. Change the password after the first login.
The OIDC issuer is `https://<spec.hostname>/realms/<realm>` (HTTP for `profile: dev`).

## 5. Secrets

| Secret | Keys |
|---|---|
| `platform-idp` | `csrf-key`, `admin-password`, `admin-client-secret` |
| `platform-idp-db` | `username`, `password`, `dsn` |
| `platform-db-app` | CNPG bootstrap login, username `haven_idp` |

For production, create them yourself before the plane (`./hack/gen-prod-secrets.sh`, which
refuses to overwrite and never echoes values) or use External Secrets. Rotation is a deliberate
act: replace the Secret, then `kubectl -n identity rollout restart deployment/platform-idp`.
Rotating `platform-idp-db` also requires changing the database role password.

## 6. Scale

```bash
kubectl -n identity scale deployment/platform-idp --replicas=3   # or spec.idp.replicas
```

Replicas above 1 get a PodDisruptionBudget (`maxUnavailable: 1`) and spread across nodes. All
replicas must share the same `csrf-key` (they do: it comes from the Secret). Size the CNPG
connection pool for the replica count.

## 7. Upgrade

1. Read the release notes for migration notes.
2. Bump the image: `helm upgrade ... --set idp.image.tag=<new>` (chart default for managed planes)
   or `spec.idp.image` on the plane.
3. The rollout is rolling; migrations run at pod start under an advisory lock, so concurrent
   replicas are safe. Roll back by re-pinning the previous tag; migrations are forward-only, so
   take a CNPG backup first.

## 8. Back up

haven-idp state lives only in Postgres, so a CNPG backup is a haven-idp backup. Configure the
object store and schedule as described in [backups.md](backups.md), and take an on-demand one
before upgrades:

```bash
bash cli/haven backup platform -n identity --now
```

Test restores into a scratch namespace regularly. Realm configuration can additionally be kept
in Git with [config as code](config-as-code.md).

## 9. Observability

Metrics are served on port 9100 (`metrics`), separate from the public listener, and audit events
go to stdout as JSON lines. Enable scraping with the Helm `ServiceMonitor`
(`--set idp.enabled=true --set observability.serviceMonitor=true`, only when the chart runs
haven-idp itself) or `deploy/observability/servicemonitor.yaml`. Dashboards, alerts, tracing and the
audit stream are described in [observability.md](observability.md).

## Production notes

`deploy/overlays/prod` adds a NetworkPolicy for `platform-idp`: ingress from the gateway
namespace and console on 8081 and from `monitoring` on 9100; egress to DNS, the CNPG cluster
on 5432 and (for tracing) an OTLP collector on 4318 in `observability`. Adjust the namespace
selectors to your cluster. See [production-overlay.md](production-overlay.md).
