---
hero:
  eyebrow: USER GUIDE
  title: Command Deck
---

## Purpose

Home operations surface — Keycloak connection, IdentityPlane health cards, reconcile timeline.

## When to use it

- Operate **Command Deck** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm Keycloak connected in the sidebar status chip

## How to get there

- Route: `/deck`
- Nav: **Sidebar → Command Deck**

## Operate from the console (UX)

1. Land on `/deck` after sign-in.
2. Read **Connected Keycloak** strip (URL, version, realm count).
3. Scan orbit cards: Keycloak, Phase, Postgres, backup, certificate, login RPS.
4. Follow **Reconcile Timeline** conditions (DatabaseReady, KeycloakReady, …).
5. Quick links: Realm Studio, Clients, Deploy wizard, Settings.
6. If offline: **Connect Keycloak** / Settings → Test & connect.
7. **Empty / fail:** Not connected → Settings; external plane may show Ready with Postgres `external` — expected.
8. **Success:** Connected banner + Ready phase (or understood external mode).

Console: `http://<host>:30742/` · Keycloak admin often `http://<host>:30180/admin` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Planes](planes.md)
- [Realm Studio](realms.md)
- [Atlas](atlas.md)
- [Settings](settings.md)
- [Deploy wizard](deploy.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
