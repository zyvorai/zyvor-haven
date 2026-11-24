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
| Go | Building `haven-idp` for the no-cluster path |
| `kubectl` | Cluster access |
| `make` | Dev overlay, UI build, CRDs |
| Node.js 20+ | Local UI development (`make ui-dev`) |

Install cluster operators once per cluster:

```bash
./deploy/operators/install.sh      # CloudNativePG + cert-manager
make crds                          # the Haven CRDs
```

Pinned versions: `versions.env` (CloudNativePG **1.30.2**, cert-manager **v1.21.3**).

---

## Try it with no cluster

```bash
go build -o haven-idp ./cmd/haven-idp
./haven-idp dev                          # prints an issuer URL, a test user and an admin secret
./haven-idp dev --persist ~/.haven-dev   # keep the data between restarts
```

Dev mode uses an embedded store and needs no database. See [dev-persist.md](dev-persist.md) for what `--persist` keeps.

---

<a id="local-cluster"></a>

## Local cluster (dev overlay)

The fastest way to run haven-idp + Postgres on a cluster, without the controller.

```bash
make dev
make wait
make doctor
make admin
```

| What | Where |
|---|---|
| Issuer | `http://auth.127.0.0.1.nip.io/realms/platform` |
| Admin user | `admin` (realm `platform`) |
| Admin password | `make admin` prints the `kubectl` command that reads secret `platform-idp`, key `admin-password`, in namespace `identity` |

The dev overlay renders secrets with `CHANGE_ME_DEV_ONLY` placeholders. Dev only.

To let the controller own the plane instead, apply an `IdentityPlane`: [Deploy haven-idp (native)](deploy-native.md). Do not combine it with `make dev` for the same name.

**Next steps:** [Runbook → Path B](runbook.md#path-b) · [CLI](cli.md) · [Console local dev](console.md#local-ui-development)

---

## Lab host

The shared lab machine and its console endpoints are described in **[lab-host.md](lab-host.md)**.

---

<a id="production-overlay"></a>

## Production overlay

See [production-overlay.md](production-overlay.md) for the full guide. Short version:

1. `./hack/gen-prod-secrets.sh`: generates the secrets (it never overwrites existing ones and never prints values)
2. `make prod`: apply the overlay
3. Issue `platform-tls` from your ClusterIssuer
4. Configure backups separately: a `ScheduledBackup` **fails** without an object store

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
| `/deck` | Command Deck: plane and identity-server health |
| `/realms` | Realm Studio |
| `/settings` | Connection, passwords |

Route reference and auth modes: [console.md](console.md).

---

## Where to go next

| Role | Recommended reading |
|---|---|
| Platform operator | [Runbook](runbook.md) → [Tutorials](tutorials.md) |
| Architect / integrator | [Architecture](architecture.md) → [Private cloud](private-cloud.md) |
| UI / product | [UX](ux.md) → [Roadmap](roadmap.md) |
| Migrating from another identity server | [Migrate from Keycloak](migrate-from-keycloak.md) |
