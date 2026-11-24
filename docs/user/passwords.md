---
hero:
  eyebrow: USER GUIDE
  title: Passwords
---

How to change Haven console credentials and the plane admin password safely.

## Console password

1. Sign in as a non-lab admin (`HAVEN_CONSOLE_*`).
2. **Settings** → change console password dialog.
3. Persist the new value in your deployment secret / env **before** the pod restarts — in-process changes die with the process.

Lab **`demo` / `demo`** cannot change its own password.

## Plane admin password

The bootstrap `admin` user of a plane keeps its password in secret `platform-idp` (key `admin-password`). Change it after the first login, then update the Secret to match. Realm users get a new password in **Realm Studio → Users → Set password** (optional temporary flag).

## Client secrets

Rotate under **Clients** or **Realm detail** — copy the new secret once; update every relying party (Axiom, Forge, etc.).

## Related

- [Settings](pages/console/settings.md)
- [Admin basics](admin-basics.md)
- [Clients](pages/console/clients.md)
