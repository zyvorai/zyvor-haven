---
hero:
  eyebrow: USER GUIDE
  title: Command Deck
---

## Purpose

Home operations surface — identity-server connection, IdentityPlane health cards, reconcile timeline.

## When to use it

- Operate **Command Deck** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm the identity server shows as connected in the sidebar status chip

## How to get there

- Route: `/deck`
- Nav: **Sidebar → Command Deck**

## Operate from the console (UX)

1. Land on `/deck` after sign-in.
2. Read the connected identity-server strip (URL, version, realm count).
3. Scan orbit cards: identity server, Phase, Postgres, backup, certificate, login RPS.
4. Follow **Reconcile Timeline** conditions (DatabaseReady, CertificateReady, IdentityProviderReady).
5. Quick links: Realm Studio, Clients, Deploy wizard, Settings.
6. If offline: open Settings and check the identity-server connection.
7. **Empty / fail:** Not connected → Settings; external plane may show Ready with Postgres `external` — expected.
8. **Success:** Connected banner + Ready phase (or understood external mode).

Console: `http://<host>:30742/` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Planes](planes.md)
- [Realm Studio](realms.md)
- [Atlas](atlas.md)
- [Settings](settings.md)
- [Deploy wizard](deploy.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
