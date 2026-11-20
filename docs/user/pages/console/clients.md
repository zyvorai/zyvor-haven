---
hero:
  eyebrow: USER GUIDE
  title: Clients
---

## Purpose

OIDC clients across all realms — mint, rotate secrets, manage redirect URIs.

## When to use it

- Operate **Clients** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm Keycloak connected in the sidebar status chip

## How to get there

- Route: `/clients`
- Nav: **Sidebar → Clients**

## Operate from the console (UX)

1. Open `/clients`.
2. Filter by realm; create or edit clients (redirect URIs, public/confidential).
3. Rotate secrets carefully; copy the new secret immediately.
4. **Empty / fail:** Empty list → create realm first; 403 → console role.
5. **Success:** Client appears with correct redirect URI for your app callback.

Console: `http://<host>:30742/` · Keycloak admin often `http://<host>:30180/admin` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Realm Studio](realms.md)
- [Command Deck](deck.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
