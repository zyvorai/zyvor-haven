---
hero:
  eyebrow: USER GUIDE
  title: Admin basics
---

## Endpoints

| Service | URL |
|---------|-----|
| Haven console | `http://<host>:30742` |
| Console login | `http://<host>:30742/login` |
| OIDC issuer | `https://<auth-host>/realms/<realm>` (HTTP for `profile: dev`) |
| OIDC discovery | `https://<auth-host>/realms/<realm>/.well-known/openid-configuration` |
| API health | `curl http://<host>:30742/api/v1/health` |

Typical namespaces: console `haven-ui` on the lab machine, the plane (`haven-idp`, Postgres) in `identity`. Port **8080** on a shared host may be a different app — prefer documented NodePorts.

## Ports (defaults)

| Service | Port | Notes |
|---------|------|------|
| Haven console | `30742` | NodePort — UI + `/api/v1` |

## Auth model

| Mode | Detail |
|------|--------|
| Lab demo | `demo` / `demo` when `HAVEN_LAB_LOGIN` empty/`1`/`true` |
| Local console | `HAVEN_CONSOLE_USER` / `HAVEN_CONSOLE_PASSWORD` |
| Plane admin (OIDC) | `admin` in the plane's realm; password in secret `platform-idp`, key `admin-password` |

Lab demo cannot change its own password. Persist console password changes in secrets before restart.

## Operate from the console (admin)

1. Settings → confirm the identity-server connection is healthy.
2. Deck → confirm Ready / Connected.
3. Deploy wizard only when installing a new plane; otherwise work in the existing one.
4. After password rotates, update dependent apps’ client secrets / OIDC config.

## Related

- [Getting Started](getting-started.md)
- [Passwords](passwords.md)
- [Settings](pages/console/settings.md)
