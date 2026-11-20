---
hero:
  eyebrow: USER GUIDE
  title: Passwords
---

How to change Haven console and Keycloak admin credentials safely.

## Console password

1. Sign in as a non-lab admin (`HAVEN_CONSOLE_*` or Keycloak-synced admin).
2. **Settings** → change console password dialog.
3. Persist the new value in your deployment secret / env **before** the pod restarts — in-process changes die with the process.

Lab **`demo` / `demo`** cannot change its own password.

## Keycloak admin password

1. **Settings** → change Keycloak admin password dialog.
2. Haven reconnects with the new master-realm password.
3. Persist in `haven-keycloak-admin` (or equivalent) immediately.

## Client secrets

Rotate under **Clients** or **Realm detail** — copy the new secret once; update every relying party (Axiom, Forge, etc.).

## Related

- [Settings](pages/console/settings.md)
- [Admin basics](admin-basics.md)
- [Clients](pages/console/clients.md)
