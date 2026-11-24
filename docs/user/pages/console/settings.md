---
hero:
  eyebrow: USER GUIDE
  title: Settings
---

## Purpose

Check the identity-server connection and manage console appearance / passwords.

## When to use it

- Operate **Settings** when your job matches this screen
- Prefer **Command Deck** after login if you are unsure where to start
- Confirm the identity server shows as connected in the sidebar status chip

## How to get there

- Route: `/settings`
- Nav: **Sidebar → Settings**

## Operate from the console (UX)

1. Open `/settings` (from Deck / Realm Studio when the identity server shows offline).
2. If the identity server is offline, check the console's `HAVEN_IDP_URL` and admin client secret (see [Console](../../../console.md#authentication)).
3. Or enter any Admin API URL → **Test & connect**; expect a green Connected banner.
4. Change the console password via the dialog (persist secrets before restart).
6. **Empty / fail:** Connection failed → URL/network/admin creds; lab demo cannot change its password.
7. **Success:** `Connected to … · v… · N realms`; Deck status goes green. OIDC SSO uses the connected URL when `HAVEN_OIDC_ISSUER` is unset.

Console: `http://<host>:30742/` · Health: `GET /api/v1/health`. Never publish lab IPs — use `<host>`.

## Related pages

- [Command Deck](deck.md)
- [Login](../auth/login.md)
- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
