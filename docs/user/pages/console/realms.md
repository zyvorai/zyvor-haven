---
hero:
  eyebrow: USER GUIDE
  title: Realm Studio
---

## Purpose

Create and manage Keycloak realms as tenant boundaries.

## When to use it

- Operate **Realm Studio** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm Keycloak connected in the sidebar status chip

## How to get there

- Route: `/realms`
- Nav: **Sidebar → Realm Studio**

## Operate from the console (UX)

1. Open `/realms`.
2. **+ Create realm** → name → Create.
3. Open a row → `/realms/:realm` for users/clients tabs.
4. Delete realm only with confirm (destructive).
5. **Empty / fail:** No realms → create one; Keycloak offline → Settings.
6. **Success:** Realm listed and openable in detail.

Console: `http://<host>:30742/` · Keycloak admin often `http://<host>:30180/admin` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Realm detail](realms-realm.md)
- [Clients](clients.md)
- [Command Deck](deck.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
