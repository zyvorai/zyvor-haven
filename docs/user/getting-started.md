---
hero:
  eyebrow: USER GUIDE
  title: Getting Started with Haven
---

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| Kubernetes / k3s | kubectl access |
| Keycloak Admin URL **or** Haven compose operators | Existing Keycloak or Deploy wizard |
| Browser | Console NodePort (default **30742**) |

## 1. Lab deploy (remote)

```bash
git clone https://github.com/zyvorai/haven.git
cd haven
./scripts/deploy-remote.sh <host> <user>
./scripts/deploy-remote.sh <host> <user> --quick   # skip image rebuild
```

Open `http://<host>:30742/login`.

## 2. Sign in

| Account | Credentials | When |
|---------|-------------|------|
| Lab demo | `demo` / `demo` | `HAVEN_LAB_LOGIN` enabled |
| Admin | Keycloak admin user/password | Synced into `haven-keycloak-admin` |
| Local console | `HAVEN_CONSOLE_USER` / `PASSWORD` | Role `admin` |

Full login UX: [Login](pages/auth/login.md).

## 3. Orient yourself (UX)

1. **Command Deck** (`/deck`) — Keycloak connected? Phase Ready?
2. **Planes** — fleet card for your IdentityPlane.
3. **Atlas** — Console → Ingress → Keycloak → Postgres path.
4. **Realm Studio** — list/create realms; open detail for users/clients.
5. **Settings** — **Test & connect** until the green banner appears.

Command palette: `⌘K` / `Ctrl+K`.

## 4. First real job

- [Verify a fresh lab](workflows.md#verify-a-fresh-lab)
- [Create a realm and invite a user](workflows.md#create-a-realm-and-invite-a-user)
- [Mint an OIDC client](workflows.md#mint-an-oidc-client)

## Next steps

- [Using the Dashboard](using-the-dashboard.md)
- [Admin basics](admin-basics.md)
- [Passwords](passwords.md)
