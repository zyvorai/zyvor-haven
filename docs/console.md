---
hero:
  eyebrow: CONSOLE
  title: Haven console
---

The Haven console is a Go API (`haven-console`) with an embedded React UI. It operates Keycloak through the Admin API and shows live IdentityPlane health from `haven-controller`.

---

## Routes

| Route | Purpose |
|---|---|
| `/` | Product landing |
| `/login` | Axiom-style sign-in (local / Keycloak admin / lab demo) |
| `/deck` | Command Deck — plane health cards + reconcile timeline |
| `/planes` | Fleet list of IdentityPlane instances |
| `/atlas` | Topology: Console → Ingress → Keycloak → Postgres |
| `/realms` | Realm Studio — tenants, users, clients, IdPs, events |
| `/clients` | Cross-realm OIDC clients |
| `/deploy` | Deploy wizard (intent / profile) |
| `/settings` | Keycloak connection, theme, password changes |

Console routes (except `/` and `/login`) require a Bearer session. Unauthenticated API calls return `401`.

UX and information architecture: [ux.md](ux.md).

---

## Authentication

| Method | Credentials | Notes |
|---|---|---|
| OIDC (Keycloak) | `haven-console` public client + PKCE | Enabled when `HAVEN_OIDC_ISSUER` is set, or derived from `KEYCLOAK_URL` + `HAVEN_BOOTSTRAP_REALM` |
| Lab demo | `demo` / `demo` | **Opt-in** — only when `HAVEN_LAB_LOGIN` is `1` / `true` / `yes` (lab deploy sets this) |
| Local console | `HAVEN_CONSOLE_USER` / `HAVEN_CONSOLE_PASSWORD`, else Keycloak admin env | Role `admin` |
| Keycloak admin | Connected URL + master admin user/password | Validates via Admin token; reconnects Manager |

Sessions live in memory (~12h). Sign out revokes the token.

### Change passwords (UI)

| Target | Where |
|---|---|
| Console sign-in | Settings → Passwords → Change console password |
| Keycloak master admin | Settings → Passwords → Change Keycloak admin password |
| Realm user | Realm Studio → Users → Set password (optional temporary flag) |

Lab `demo` cannot change its own password. Persist console / Keycloak admin changes in `haven-keycloak-admin` (or `HAVEN_CONSOLE_*`) before pod restart.

---

## Lab remote deploy

```bash
./scripts/deploy-remote.sh <ephemeral-ip> operator
./scripts/deploy-remote.sh <ephemeral-ip> operator --quick   # skip image rebuild
```

| Service | URL |
|---|---|
| Console | [http://<ephemeral-ip>:30742](http://<ephemeral-ip>:30742) |
| Keycloak admin | [http://<ephemeral-ip>:30180/admin](http://<ephemeral-ip>:30180/admin) |
| OIDC issuer | `http://<ephemeral-ip>:30180/realms/master` |

Defaults: UI NodePort `30742`, Keycloak NodePort `30180`, image tag `dev`.

**Canonical endpoint reference:** [lab-host.md](lab-host.md)

Required secret (synced by deploy script): `haven-keycloak-admin` in namespace `haven-ui`.

Console Deployment environment:

```text
KEYCLOAK_URL=http://<ephemeral-ip>:30180
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=<from secret>
HAVEN_LAB_LOGIN=1
```

---

## Local UI development

```bash
make ui-install
make ui-dev          # Vite → http://localhost:5173
go run ./cmd/haven-console
```

API is under `/api/v1`. The Vite proxy (when configured) forwards to the local Go server.

---

## External plane mode

When CNPG / Keycloak Operator CRDs are absent, the controller reports `phase: Ready` with Postgres `external`. The console still talks to a live Keycloak Admin URL from Settings / env.

---

## Related docs

- [Tutorials](tutorials.md) — realm, client, password recipes
- [Runbook → Path D](runbook.md#path-d)
- [CLI](cli.md) — Makefile and deploy script
