---
hero:
  eyebrow: USER GUIDE
  title: Atlas
---

## Purpose

Traffic path to identity — Console → Ingress → haven-idp → Postgres.

## When to use it

- Operate **Atlas** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm the identity server shows as connected in the sidebar status chip

## How to get there

- Route: `/atlas`
- Nav: **Sidebar → Atlas**

## Operate from the console (UX)

1. Open `/atlas`.
2. Walk the path diagram; confirm each hop looks healthy.
3. Use this before debugging OIDC redirect or login failures.
4. **Empty / fail:** Broken hop → Settings connection or ingress NodePorts.
5. **Success:** Path matches your deploy (console NodePort 30742 on the lab machine → ingress → haven-idp).

Console: `http://<host>:30742/` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Command Deck](deck.md)
- [Settings](settings.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
