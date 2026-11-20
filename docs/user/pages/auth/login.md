---
hero:
  eyebrow: USER GUIDE
  title: Login
---

## Purpose

Sign in to the Haven identity console — lab demo, local console user, or Keycloak admin.

## When to use it

- Operate **Login** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm Keycloak connected in the sidebar status chip

## How to get there

- Route: `/login`
- Nav: **Unauthenticated → `/login`**

## Operate from the console (UX)

1. Open `http://<host>:30742/login`.
2. Confirm **This machine** context on the page (host, origin, protocol) so you know which console you are signing into.
3. Lab / test: when `HAVEN_LAB_LOGIN` is enabled, a lab banner shows `demo` / `demo` and a one-click fill control.
4. Or Keycloak admin / `HAVEN_CONSOLE_USER`+`PASSWORD`.
5. **Sign in** — failures show an inline error.
6. **Empty / fail:** Wrong password → check `haven-keycloak-admin` secret; lab demo cannot change its own password.
7. **Success:** Redirect to Command Deck; sidebar shows Keycloak connected status.

Console: `http://<host>:30742/` · Keycloak admin often `http://<host>:30180/admin` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Command Deck](../console/deck.md)
- [Settings](../console/settings.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
