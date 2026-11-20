---
hero:
  eyebrow: CLI
  title: Haven CLI
---

The `./cli/haven` script is a thin operator over IdentityPlane CRs and the compose path. Use it for status checks, admin credentials, backups, and preflight diagnostics.

All commands default to plane **`platform`** in namespace **`identity`**.

---

## Commands

```bash
./cli/haven deploy -f plane.yaml
./cli/haven status  [name] [-n namespace]
./cli/haven open    [name] [-n namespace]
./cli/haven doctor  [name] [-n namespace]
./cli/haven backup  [name] [-n namespace] [--now]
./cli/haven admin   [name] [-n namespace]
```

### `deploy`

Apply an IdentityPlane (or other) manifest:

```bash
./cli/haven deploy -f config/samples/identityplane-dev.yaml
```

### `status`

Print IdentityPlane status (if present), Keycloak and CNPG objects, and the admin secret path:

```bash
./cli/haven status
./cli/haven status my-plane -n tenant-a
```

### `open`

Print Keycloak, admin, and console URLs from the CR or ingress:

```bash
./cli/haven open
```

### `doctor`

Preflight: CRDs, operator deployments, objects and pods in the namespace, CNPG phase. Exits non-zero if required CRDs are missing.

```bash
./cli/haven doctor
```

Run this first during any incident — see [Runbook → Failure cheatsheet](runbook.md#failure-cheatsheet).

### `admin`

Print Keycloak bootstrap credentials from the operator secret (`<name>-initial-admin`):

```bash
./cli/haven admin
```

Equivalent to `make admin`.

### `backup`

List backups, or request an on-demand volume snapshot:

```bash
./cli/haven backup platform -n identity          # list
./cli/haven backup platform -n identity --now    # snapshot now
```

Volume snapshots require a StorageClass with a snapshotter. For object-store backups, configure CNPG separately — see [backups.md](backups.md).

---

## Makefile targets

| Target | Action |
|---|---|
| `make crds` | Apply Haven CRDs |
| `make operators` | Run `deploy/operators/install.sh` |
| `make dev` | Apply dev overlay (includes CRDs) |
| `make prod` | Apply prod overlay (read prod README first) |
| `make wait` | Wait for plane readiness |
| `make doctor` | `./cli/haven doctor platform -n identity` |
| `make admin` | Print bootstrap admin credentials |
| `make realm-import` | Apply sample KeycloakRealmImport |
| `make samples-dev` | Apply dev IdentityPlane sample (intent only) |
| `make secrets-prod` | Generate production secrets |
| `make sync-ca` | Sync CNPG CA into Keycloak namespace |
| `make ui-install` | `npm install` in `ui/web` |
| `make ui-dev` | Vite dev server |
| `make ui-build` | Build SPA into `cmd/haven-console/dist` |
| `make console-build` | Build `bin/haven-console` |
| `make console-run` | Run local console binary |
| `make controller-build` | Build `bin/haven-controller` |

---

## Remote deploy script

Deploy the console to a remote k3s host:

```bash
./scripts/deploy-remote.sh <host> [user] [--quick] [--uninstall]
```

Lab example:

```bash
./scripts/deploy-remote.sh <ephemeral-ip> operator
```

Environment variables: `HAVEN_NODE_PORT` (default `30742`), `KEYCLOAK_NODE_PORT` (default `30180`), `HAVEN_IMAGE_TAG` (default `dev`).

See [lab-host.md](lab-host.md) for endpoints.
