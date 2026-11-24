---
hero:
  eyebrow: CONSOLE
  title: Haven console
---

The Haven console is a Go API (`haven-console`) with an embedded React UI. It operates `haven-idp` through its Admin API (`HAVEN_IDP_BACKEND=native`) and shows live IdentityPlane health from `haven-controller`.

---

## Routes

| Route | Purpose |
|---|---|
| `/` | Product landing |
| `/login` | Axiom-style sign-in (OIDC / local / lab demo) |
| `/deck` | Command Deck — plane health cards + reconcile timeline |
| `/planes` | Fleet list of IdentityPlane instances |
| `/atlas` | Topology: Console → Ingress → haven-idp → Postgres |
| `/realms` | Realm Studio — tenants, users, clients, IdPs, events |
| `/clients` | Cross-realm OIDC clients |
| `/deploy` | Deploy wizard (intent / profile) |
| `/access-review` | Access Review: privileged and stale accounts, break-glass check, recertification campaigns ([details](access-review.md)) |
| `/settings` | Identity-server connection, theme, password changes |

Console routes (except `/` and `/login`) require a Bearer session. Unauthenticated API calls return `401`.

UX and information architecture: [ux.md](ux.md).

---

## Authentication

| Method | Credentials | Notes |
|---|---|---|
| OIDC (haven-idp) | `haven-console` public client + PKCE | Enabled when `HAVEN_OIDC_ISSUER` is set, or derived from the identity server URL plus `HAVEN_BOOTSTRAP_REALM` (default `platform`) as `<url>/realms/<realm>`. `HAVEN_OIDC_CLIENT_ID` overrides the client id |
| Lab demo | `demo` / `demo` | **Opt-in**: only when `HAVEN_LAB_LOGIN` is `1` / `true` / `yes` |
| Local console | `HAVEN_CONSOLE_USER` / `HAVEN_CONSOLE_PASSWORD` | Role `admin` |

Sessions live in memory (~12h). Sign out revokes the token.

The console reaches the identity server with `HAVEN_IDP_BACKEND=native`, `HAVEN_IDP_URL`, `HAVEN_IDP_ADMIN_REALM`, `HAVEN_IDP_ADMIN_CLIENT_ID` (default `haven-admin`) and `HAVEN_IDP_ADMIN_CLIENT_SECRET` (or `HAVEN_IDP_ADMIN_CLIENT_SECRET_FILE`). The Helm chart wires these from the plane's `platform-idp` secret ([deploy-native.md](deploy-native.md#2-controller-and-console)).

### Change passwords (UI)

| Target | Where |
|---|---|
| Console sign-in | Settings → Passwords → Change console password |
| Realm user | Realm Studio → Users → Set password (optional temporary flag) |

Lab `demo` cannot change its own password. Persist console password changes in `HAVEN_CONSOLE_*` (or its secret) before a pod restart.

---

## Lab remote deploy

`./scripts/deploy-remote.sh <host> <user>` deploys the console to a lab k3s host on NodePort `30742`. It predates `haven-idp` and has not been verified against a haven-idp plane: see [lab-host.md](lab-host.md).

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

When the CloudNativePG CRDs are absent, the controller reports `phase: ProvisioningDatabase` with a `DatabaseReady=False` / `CNPGMissing` condition for a plane: the identity server needs CNPG. The console can still be pointed at any reachable `haven-idp` through `HAVEN_IDP_URL`.

---

## Related docs

- [Tutorials](tutorials.md) — realm, client, password recipes
- [Runbook → Path D](runbook.md#path-d)
- [CLI](cli.md) — Makefile and deploy script
