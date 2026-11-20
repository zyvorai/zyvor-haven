---
hero:
  eyebrow: USER GUIDE
  title: Realm detail
---

## Purpose

Users and clients inside one realm — invite, set password, mint/rotate secrets.

## When to use it

- Operate **Realm detail** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm Keycloak connected in the sidebar status chip

## How to get there

- Route: `/realms/:realm`
- Nav: **Realm Studio → realm row**

## Operate from the console (UX)

1. Open a realm from `/realms`.
2. Users: **+ Invite user**; set password via dialog when offered.
3. Clients: create/manage; **Regenerate client secret** with confirm; copy secret once.
4. **Empty / fail:** Invite fails → Keycloak permissions; secret regenerate is irreversible.
5. **Success:** User can authenticate to the realm; client secret pasted into your app.

Console: `http://<host>:30742/` · Keycloak admin often `http://<host>:30180/admin` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Realm Studio](realms.md)
- [Clients](clients.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
