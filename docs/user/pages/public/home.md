---
hero:
  eyebrow: USER GUIDE
  title: Landing
---

## Purpose

Public product landing — sign in or jump to Command Deck when already authenticated.

## When to use it

- Operate **Landing** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm Keycloak connected in the sidebar status chip

## How to get there

- Route: `/`
- Nav: **Route `/` (marketing shell)**

## Operate from the console (UX)

1. Open `http://<host>:30742/`.
2. **Sign in** → `/login`, or **Open Command Deck** if you already have a session.
3. Read the Deploy Postgres + Keycloak story only as orientation — day-2 work lives under `/deck`.
4. **Empty / fail:** Page blank → console NodePort / ingress; not a substitute for Keycloak admin.
5. **Success:** You can reach Login or Deck without certificate/network surprises.

Console: `http://<host>:30742/` · Keycloak admin often `http://<host>:30180/admin` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Login](../auth/login.md)
- [Command Deck](../console/deck.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
