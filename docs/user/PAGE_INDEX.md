---
hero:
  eyebrow: USER GUIDE
  title: Haven — Complete page index
---

Every primary navigable dashboard route.

_Generated: 2026-09-04 · 10 routes_

Regenerate: `node scripts/user-docs/generate-page-index.mjs`

## PUBLIC

| Page | Route | Purpose | Guide |
|------|-------|---------|-------|
| Landing | `/` | Public product landing — sign in or jump to Command Deck when already authenticated. | [Open](pages/public/home.md) |

## AUTH

| Page | Route | Purpose | Guide |
|------|-------|---------|-------|
| Login | `/login` | Sign in to the Haven identity console — lab demo, local console user, or OIDC sign-in against the plane. | [Open](pages/auth/login.md) |

## CONSOLE

| Page | Route | Purpose | Guide |
|------|-------|---------|-------|
| Command Deck | `/deck` | Home operations surface — identity-server connection, IdentityPlane health cards, reconcile timeline. | [Open](pages/console/deck.md) |
| Deploy wizard | `/deploy` | Spin up an identity plane — haven-idp + Postgres via the Haven dev overlay or an IdentityPlane. | [Open](pages/console/deploy.md) |
| Planes | `/planes` | IdentityPlane instances — health, profile, and endpoints. | [Open](pages/console/planes.md) |
| Atlas | `/atlas` | Traffic path to identity — Console → Ingress → haven-idp → Postgres. | [Open](pages/console/atlas.md) |
| Realm Studio | `/realms` | Create and manage realms as tenant boundaries. | [Open](pages/console/realms.md) |
| Realm detail | `/realms/:realm` | Users and clients inside one realm — invite, set password, mint/rotate secrets. | [Open](pages/console/realms-realm.md) |
| Clients | `/clients` | OIDC clients across all realms — mint, rotate secrets, manage redirect URIs. | [Open](pages/console/clients.md) |
| Settings | `/settings` | Check the identity-server connection and manage console appearance / passwords. | [Open](pages/console/settings.md) |

## Related

- [User docs home](README.md)
- [Page-by-page guides](pages/README.md)
