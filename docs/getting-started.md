---
hero:
  eyebrow: GETTING STARTED
  title: Getting started
---

Pick the path that matches where you are running Haven. All commands assume you are in the **repo root**.

---

## Prerequisites

| Tool | Used for |
|---|---|
| `kubectl` | Cluster access |
| `make` | Dev overlay, UI build, CRDs |
| Docker (remote deploy) | Building console image on lab host |
| Node.js 20+ | Local UI development (`make ui-dev`) |

Install cluster operators once per cluster:

```bash
./deploy/operators/install.sh
make crds    # optional for compose-only; needed for samples
```

Pinned versions: `versions.env` (Keycloak Operator **26.8.0**, CloudNativePG **1.30.1**).

---

## Local cluster (compose path)

The fastest way to run Keycloak + Postgres without the v1 controller.

```bash
make dev
make wait
make doctor
make admin
```

| What | Where |
|---|---|
| Keycloak Admin Console | `http://auth.127.0.0.1.nip.io/admin` |
| Bootstrap secret | `platform-initial-admin` in namespace `identity` |
| Optional first realm | `make realm-import` |

`IdentityPlane` samples (`make samples-dev`) store **intent** for the future controller — they do not provision resources today. Do not confuse them with `make dev`.

**Next steps:** [Runbook → Path B](runbook.md#path-b) · [CLI](cli.md) · [Console local dev](console.md#local-ui-development)

---

## Lab host (remote console)

Deploy the Haven console to the shared lab machine and connect it to the existing Keycloak instance.

```bash
./scripts/deploy-remote.sh <ephemeral-ip> operator
./scripts/deploy-remote.sh <ephemeral-ip> operator --quick   # skip image rebuild
```

| Service | URL |
|---|---|
| Console login | [http://<ephemeral-ip>:30742/login](http://<ephemeral-ip>:30742/login) |
| Keycloak admin | [http://<ephemeral-ip>:30180/admin](http://<ephemeral-ip>:30180/admin) |
| OIDC issuer | `http://<ephemeral-ip>:30180/realms/master` |

Sign in with lab credentials (`demo` / `demo`) or Keycloak admin — see [Console → Authentication](console.md#authentication).

Full endpoint table, SSH access, and OIDC client wiring: **[lab-host.md](lab-host.md)**.

**Next steps:** [Tutorials → Verify deploy](tutorials.md#verify-deploy) · [Console](console.md)

---

## Production overlay {#production-overlay}

See [production-overlay.md](production-overlay.md) for the full guide. Short version:

1. `./hack/gen-prod-secrets.sh` — replace placeholder passwords
2. `make prod` — apply overlay
3. Wait for CNPG, then `./hack/sync-cnpg-ca.sh` (Keycloak verifies DB TLS)
4. Issue `platform-tls` from your ClusterIssuer
5. Configure backups separately — a `ScheduledBackup` **fails** without an object store

Details: [production-overlay.md](production-overlay.md) · [Runbook → Path C](runbook.md#path-c)

---

## Web UI (local development)

Product landing + live identity console in `ui/web/`:

```bash
make ui-install   # once
make ui-dev       # Vite → http://localhost:5173
go run ./cmd/haven-console
```

| Route | Purpose |
|---|---|
| `/` | Landing |
| `/login` | Sign-in |
| `/deck` | Command Deck — plane + Keycloak health |
| `/realms` | Realm Studio |
| `/settings` | Keycloak connect, passwords |

Route reference and auth modes: [console.md](console.md).

---

## Where to go next

| Role | Recommended reading |
|---|---|
| Platform operator | [Runbook](runbook.md) → [Tutorials](tutorials.md) |
| Architect / integrator | [Architecture](architecture.md) → [Private cloud](private-cloud.md) |
| UI / product | [UX](ux.md) → [Roadmap](roadmap.md) |
