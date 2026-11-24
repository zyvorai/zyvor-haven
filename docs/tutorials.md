---
hero:
  eyebrow: TUTORIALS
  title: Haven tutorials
---

Step-by-step console recipes for operators. User-facing manuals also live on zyvor.dev:

- [Haven manual](https://zyvor.dev/docs/haven-manual)
- [Common workflows](https://zyvor.dev/docs/haven-manual/workflows)
- [Page-by-page guides](https://zyvor.dev/docs/haven-manual/pages)

---

## Verify deploy

Open the console (locally `http://localhost:5173` from `make ui-dev`, or the console host of your plane) and walk through the main surfaces:

Sign in → **Command Deck** (connected + Ready) → **Planes** → **Atlas**.

Lab machine notes: [lab-host.md](lab-host.md). Auth modes: [console.md](console.md#authentication).

---

## Create realm + user

1. `/realms` → **Create realm**
2. Open realm → **Users** → **Invite user** (optional temp password)
3. **Set password** for a permanent credential

Production profile (future): realm changes may route through Approvals; see [ux.md](ux.md).

---

## Mint client secret

1. Realm → **Clients** → **Mint client** (confidential)
2. **Secret** or **Rotate** → copy once

For public PKCE clients (no secret), register the exact redirect URIs on the client in Realm Studio, with an [`OIDCClient`](oidcclient-crd.md) manifest, or with the [add-an-app wizard](add-an-app.md). OIDC wiring example: [lab-host.md → Wire OIDC clients](lab-host.md#wire-oidc-clients).

---

## Passwords

| What | Where |
|---|---|
| Console sign-in | Settings → Passwords → Change console password |
| Realm user | Realm → Users → Set password |

Persist console password changes in `HAVEN_CONSOLE_*` (or its secret) before a pod restart.

---

## Related docs

- [Console](console.md) — routes and auth
- [Runbook → Day-2](runbook.md#day-2-operations)
- [Private cloud → Platform SSO catalog](private-cloud.md#platform-sso-catalog)
