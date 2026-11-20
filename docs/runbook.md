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
./deploy/operators/install.sh
make crds
```

Creates/uses namespace `keycloak` for the Keycloak Operator. Planes live in `identity`.

---

## Deployment paths

### Path A — product CR (controller later) {#path-a}

```bash
kubectl apply -f config/samples/identityplane-dev.yaml
./cli/haven doctor -n identity
```

Until the controller image exists, Path A only **stores intent**. Use Path B to actually run Keycloak + Postgres.

### Path B — compose today (supported in v0) {#path-b}

```bash
make dev
make wait
make admin
```

| Item | Value |
|---|---|
| Admin secret | `platform-initial-admin` (Keycloak Operator bootstrap) |
| Admin Console | `http://auth.127.0.0.1.nip.io/admin` |
| First realm | `make realm-import` |

```bash
./cli/haven admin -n identity    # print credentials
```

`kubectl apply -k deploy/overlays/dev` no longer includes a Haven `RealmBundle`, so the compose path does not require Haven CRDs. `make dev` still applies them so samples work later.

### Path C — production shape {#path-c}

Follow [production-overlay.md](production-overlay.md):

```bash
./hack/gen-prod-secrets.sh
make prod
kubectl -n identity wait cluster/platform-db --for=condition=Ready --timeout=600s
./hack/sync-cnpg-ca.sh
# then issue platform-tls and configure backups
```

Do not apply a `ScheduledBackup` until an ObjectStore plugin or volume snapshot class exists.

### Path D — Haven console on lab host {#path-d}

```bash
./scripts/deploy-remote.sh <ephemeral-ip> operator
```

| Service | URL |
|---|---|
| Console | [http://<ephemeral-ip>:30742/login](http://<ephemeral-ip>:30742/login) |
| Keycloak admin | [http://<ephemeral-ip>:30180/admin](http://<ephemeral-ip>:30180/admin) |
| OIDC issuer | `http://<ephemeral-ip>:30180/realms/master` |

Secret: `haven-keycloak-admin` in `haven-ui`. Details: [lab-host.md](lab-host.md), [console.md](console.md).

---

## Day-2 operations

| Action | How |
|---|---|
| Sign in to console | `/login` — admin credentials or lab `demo`/`demo` |
| Change console password | Settings → Passwords (persist via secret for restarts) |
| Change Keycloak admin password | Settings → Passwords → Keycloak admin |
| Set realm user password | Realm Studio → Users → Set password |
| Scale Keycloak | `kubectl -n identity patch keycloak platform --type merge -p '{"spec":{"instances":5}}'` |
| Scale Postgres | patch CNPG `spec.instances` |
| Backup now | `./cli/haven backup platform -n identity --now` (volumeSnapshot) |
| Upgrade Keycloak | bump `KEYCLOAK_OPERATOR_REF` in `versions.env`, re-run `install.sh` |
| Suspend auth | scale Keycloak instances to 0; leave DB |
| Restore | CNPG recover into a *new* Cluster, point a new plane at it |

Console recipes: [tutorials.md](tutorials.md). CLI reference: [cli.md](cli.md).

---

## Failure cheatsheet

| Symptom | Look at |
|---|---|
| Keycloak CrashLoop `Unable to migrate database` | CNPG not ready, password mismatch between Secrets, TLS verify without `platform-db-ca` |
| Ingress 404 | Service is `<cr-name>-service` → `platform-service` |
| Issuer discovery fails | hostname / `proxy.headers` / TLS SAN |
| Slow logins | pool size vs `max_connections`, lag on primary |
| After node death, auth 5xx | Keycloak instances < 2, no PDB |
| `ScheduledBackup` rejected | Cluster has no object store / plugin |

**First step in any incident:** `./cli/haven doctor`

---

## Related docs

- [Getting started](getting-started.md) — choose a path
- [Architecture](architecture.md) — reconcile order and profiles
- [CLI](cli.md) — commands and Makefile targets
