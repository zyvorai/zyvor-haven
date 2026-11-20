---
hero:
  eyebrow: USER GUIDE
  title: Page-by-page guides
---

Each guide follows: Purpose → When to use it → How to get there → Operate from the console (UX) → Related pages.

Every route is also listed in the [complete page index](../PAGE_INDEX.md).

## Auth

| Page | What it covers |
|------|----------------|
| [Login](auth/login.md) | Sign in to the Haven identity console — lab demo, local console user, or Keycloak admin. |

## Console

| Page | What it covers |
|------|----------------|
| [Atlas](console/atlas.md) | Traffic path to identity — Console → Ingress → Keycloak → Postgres. |
| [Clients](console/clients.md) | OIDC clients across all realms — mint, rotate secrets, manage redirect URIs. |
| [Command Deck](console/deck.md) | Home operations surface — Keycloak connection, IdentityPlane health cards, reconcile timeline. |
| [Deploy wizard](console/deploy.md) | Spin up an identity plane — Postgres + Keycloak via Haven compose path. |
| [Planes](console/planes.md) | IdentityPlane instances — health, profile, and endpoints. |
| [Realm detail](console/realms-realm.md) | Users and clients inside one realm — invite, set password, mint/rotate secrets. |
| [Realm Studio](console/realms.md) | Create and manage Keycloak realms as tenant boundaries. |
| [Settings](console/settings.md) | Connect Haven to Keycloak and manage console appearance / passwords. |

## Public

| Page | What it covers |
|------|----------------|
| [Landing](public/home.md) | Public product landing — sign in or jump to Command Deck when already authenticated. |

---

10 guides. Regenerate: `node scripts/user-docs/generate-guide-index.mjs`.
