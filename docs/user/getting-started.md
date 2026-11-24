---
hero:
  eyebrow: USER GUIDE
  title: Getting Started with Haven
---

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| Kubernetes / k3s | kubectl access |
| CloudNativePG and cert-manager | Installed once per cluster (`./deploy/operators/install.sh`) |
| Browser | Console NodePort (default **30742**) |

## 1. Deploy

```bash
git clone https://github.com/zyvorai/haven.git
cd haven
./deploy/operators/install.sh
make dev && make wait
```

This runs `haven-idp` and Postgres on your cluster; the full walkthrough, including the controller and console, is in [Deploy haven-idp (native)](../deploy-native.md). To try the identity server with no cluster, run `haven-idp dev`. For a console on a shared lab machine see [Lab host](../lab-host.md).

Open the console at its host, `/login`.

## 2. Sign in

| Account | Credentials | When |
|---------|-------------|------|
| Lab demo | `demo` / `demo` | `HAVEN_LAB_LOGIN` enabled |
| Plane admin (OIDC) | `admin` in realm `platform`; password from secret `platform-idp`, key `admin-password` | Console OIDC sign-in against the plane |
| Local console | `HAVEN_CONSOLE_USER` / `PASSWORD` | Role `admin` |

Full login UX: [Login](pages/auth/login.md).

## 3. Orient yourself (UX)

1. **Command Deck** (`/deck`) — identity server connected? Phase Ready?
2. **Planes** — fleet card for your IdentityPlane.
3. **Atlas** — Console → Ingress → haven-idp → Postgres path.
4. **Realm Studio** — list/create realms; open detail for users/clients.
5. **Settings** — confirm the identity-server connection is healthy.

Command palette: `⌘K` / `Ctrl+K`.

## 4. First real job

- [Verify a fresh lab](workflows.md#verify-a-fresh-lab)
- [Create a realm and invite a user](workflows.md#create-a-realm-and-invite-a-user)
- [Mint an OIDC client](workflows.md#mint-an-oidc-client)

## Next steps

- [Using the Dashboard](using-the-dashboard.md)
- [Admin basics](admin-basics.md)
- [Passwords](passwords.md)
