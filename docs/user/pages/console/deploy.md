---
hero:
  eyebrow: USER GUIDE
  title: Deploy wizard
---

## Purpose

Create an `IdentityPlane` when the console has cluster write RBAC, or **bootstrap the first realm** against a connected Keycloak when it does not.

## When to use it

- Operate **Deploy wizard** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm Keycloak connected in the sidebar status chip for realm bootstrap

## How to get there

- Route: `/deploy`
- Nav: **Sidebar → Deploy wizard**

## Operate from the console (UX)

1. Open `/deploy`.
2. The title reflects capabilities:
   - **Deploy identity plane** — console can `create` `IdentityPlane` CRs.
   - **Bootstrap first realm** — no create RBAC; durability/routing are informational only.
3. Walk audience / profile / hostname / admin steps.
4. Submit:
   - Plane mode → `POST /api/v1/planes` → Command Deck.
   - Realm mode → creates realm + `haven-console` client + optional admin user in Keycloak.
5. **Empty / fail:** 403/409 on plane create → apply sample CR or fix RBAC; realm mode needs Keycloak connected in Settings.
6. **Success:** Plane appears on Deck/Planes, or Realm Studio opens the new realm.

Console: `http://<host>:30742/` · Keycloak admin often `http://<host>:30180/admin` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Planes](planes.md)
- [Command Deck](deck.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
