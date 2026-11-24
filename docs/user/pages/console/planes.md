---
hero:
  eyebrow: USER GUIDE
  title: Planes
---

## Purpose

IdentityPlane instances — health, profile, and endpoints.

## When to use it

- Operate **Planes** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm the identity server shows as connected in the sidebar status chip

## How to get there

- Route: `/planes`
- Nav: **Sidebar → Planes**

## Operate from the console (UX)

1. Open `/planes`.
2. **+ Deploy plane** or **Deploy wizard** when empty.
3. Open a plane card → endpoints / health; jump **Open Command Deck**.
4. **Empty / fail:** No planes → Deploy wizard, or point the console at an existing `haven-idp` (`HAVEN_IDP_URL`).
5. **Success:** Fleet card shows Ready with identity-server/Postgres endpoints.

Console: `http://<host>:30742/` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Command Deck](deck.md)
- [Deploy wizard](deploy.md)
- [Atlas](atlas.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
