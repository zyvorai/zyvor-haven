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
| Keycloak admin | `http://<host>:30180/admin` |
| OIDC issuer | `http://<host>:30180/realms/master` |
| OIDC discovery | `http://<host>:30180/realms/master/.well-known/openid-configuration` |
| API health | `curl http://<host>:30742/api/v1/health` |

Typical namespaces: console `haven-ui`, Keycloak per your chart (lab often co-located). Port **8080** on a shared host may be a different app — prefer documented NodePorts.

## Ports (defaults)

| Service | Port | Notes |
|---------|------|------|
| Haven console | `30742` | NodePort — UI + `/api/v1` |
| Keycloak | `30180` | Admin / issuer NodePort (common) |

## Auth model

| Mode | Detail |
|------|--------|
| Lab demo | `demo` / `demo` when `HAVEN_LAB_LOGIN` empty/`1`/`true` |
| Local console | `HAVEN_CONSOLE_USER` / `HAVEN_CONSOLE_PASSWORD` |
| Keycloak admin | From `haven-keycloak-admin` secret |

Lab demo cannot change its own password. Persist console / Keycloak admin changes in secrets before restart.

## Operate from the console (admin)

1. Settings → **Test & connect** to Keycloak.
2. Deck → confirm Ready / Connected.
3. Deploy wizard only when installing a new plane; otherwise attach existing Keycloak.
4. After password rotates, update dependent apps’ client secrets / OIDC config.

## Related

- [Getting Started](getting-started.md)
- [Passwords](passwords.md)
- [Settings](pages/console/settings.md)
