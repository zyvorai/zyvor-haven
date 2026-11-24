---
hero:
  eyebrow: RUNBOOK
  title: Haven runbook
---

Operator guide: install, deploy, day-2 operations, and incident response.

> All commands assume the **Haven repo root**. Lab endpoints: [lab-host.md](lab-host.md).

---

## Install operators (once per cluster)

```bash
./deploy/operators/install.sh      # CloudNativePG + cert-manager
make crds
```

Planes live in the `identity` namespace.

---

## Deployment paths

<a id="path-a"></a>

### Path A: IdentityPlane + controller

```bash
kubectl apply -f config/samples/identityplane-dev.yaml
./cli/haven doctor -n identity
```

The controller (`haven-controller`, see [install-helm.md](install-helm.md)) builds the CloudNativePG cluster, the secrets, the `haven-idp` Deployment and the certificate from the plane. Full walkthrough: [deploy-native.md](deploy-native.md).

<a id="path-b"></a>

### Path B: dev overlay (no controller)

```bash
make dev
make wait
make admin
```

| Item | Value |
|---|---|
| Admin secret | `platform-idp`, key `admin-password` (namespace `identity`) |
| Issuer | `http://auth.127.0.0.1.nip.io/realms/platform` |

```bash
./cli/haven admin -n identity    # prints the kubectl command that reads the password
```

`make dev` applies the Haven CRDs and `deploy/overlays/dev`, which renders the same objects as the controller with `CHANGE_ME_DEV_ONLY` placeholder secrets. Dev only.

<a id="path-c"></a>

### Path C: production shape

Follow [production-overlay.md](production-overlay.md):

```bash
./hack/gen-prod-secrets.sh
make prod
kubectl -n identity wait cluster/platform-db --for=condition=Ready --timeout=600s
kubectl -n identity rollout status deployment/platform-idp
# then issue platform-tls and configure backups
```

Do not apply a `ScheduledBackup` until an ObjectStore plugin or volume snapshot class exists.

<a id="path-d"></a>

### Path D: console

The console talks to `haven-idp` through the Admin API. With the Helm chart it defaults to `http://platform-idp.identity.svc:8081` and reads its admin client secret from secret `platform-idp`: see [deploy-native.md](deploy-native.md#2-controller-and-console). For a lab machine see [lab-host.md](lab-host.md); for routes and auth modes see [console.md](console.md).

---

## Day-2 operations

| Action | How |
|---|---|
| Sign in to console | `/login`: admin credentials, or sign in through the plane's own realm |
| Change console password | Settings → Passwords (persist via secret for restarts) |
| Set realm user password | Realm Studio → Users → Set password |
| Scale haven-idp | `kubectl -n identity scale deployment/platform-idp --replicas=3` (or `spec.idp.replicas`) |
| Scale Postgres | patch `spec.database.instances` on the plane (or the CNPG `spec.instances`) |
| Backup now | `./cli/haven backup platform -n identity --now` (volumeSnapshot) |
| Upgrade haven-idp | bump the image (`spec.idp.image` or the Helm `idp.image.tag`); migrations run at start under an advisory lock. Take a CNPG backup first |
| Suspend auth | `spec.suspend` on the plane; the database is left alone |
| Restore | CNPG recover into a *new* Cluster, point a new plane at it |

Console recipes: [tutorials.md](tutorials.md). CLI reference: [cli.md](cli.md).

---

## Failure cheatsheet

| Symptom | Look at |
|---|---|
| `haven-idp` pod not ready / restarting | `kubectl -n identity logs deploy/platform-idp`; CNPG not ready, wrong DSN in `platform-idp-db`, or a changed `secret-key` |
| Plane stuck in `ProvisioningDatabase` | `DatabaseReady` condition: CNPG CRDs missing or cluster not healthy |
| Ingress 404 | the Ingress backend must point at the Service `platform-idp` on port 8081 |
| Issuer discovery fails | hostname, forwarded headers (`HAVEN_IDP_TRUST_PROXY=1` is set by the controller), TLS SAN |
| Slow logins | database pool size vs `max_connections`, lag on the primary |
| After node death, auth 5xx | fewer than 2 `haven-idp` replicas, no PDB (replicas above 1 get one) |
| `ScheduledBackup` rejected | Cluster has no object store / plugin |

**First step in any incident:** `./cli/haven doctor`

---

## Related docs

- [Getting started](getting-started.md): choose a path
- [Architecture](architecture.md): reconcile order and profiles
- [CLI](cli.md): commands and Makefile targets

## Gateway API alternative (Setura)

The dev overlay has `deploy/overlays/dev/gateway.yaml` (Gateway + two HTTPRoutes mirroring `ingress.yaml`, gatewayClassName `setura`). It is not listed in the kustomization; apply it with `kubectl apply -f deploy/overlays/dev/gateway.yaml`.

Install the controller once per cluster:

```bash
setura gateway install --image ghcr.io/zyvorai/zyvor-setura-gateway:0.7.0 --namespace setura-system | kubectl apply -f -
```

This is optional and off by default; the Ingress is unchanged. Use it instead of the Ingress, not as well.
