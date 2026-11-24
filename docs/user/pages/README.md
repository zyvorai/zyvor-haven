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
| [Login](auth/login.md) | Sign in to the Haven identity console — lab demo, local console user, or single sign-on against the plane. |

## Console

| Page | What it covers |
|------|----------------|
| [Atlas](console/atlas.md) | Traffic path to identity — Console → Ingress → haven-idp → Postgres. |
| [Clients](console/clients.md) | OIDC clients across all realms — mint, rotate secrets, manage redirect URIs. |
| [Command Deck](console/deck.md) | Home operations surface — identity-server connection, IdentityPlane health cards, reconcile timeline. |
| [Deploy wizard](console/deploy.md) | Create an `IdentityPlane` when the console has cluster write RBAC, or bootstrap the first realm against the connected identity server when it does not. |
| [Planes](console/planes.md) | IdentityPlane instances — health, profile, and endpoints. |
| [Realm detail](console/realms-realm.md) | Users and clients inside one realm — invite, set password, mint/rotate secrets. |
| [Realm Studio](console/realms.md) | Create and manage realms as tenant boundaries. |
| [Settings](console/settings.md) | Check the identity-server connection and manage console appearance / passwords. |

## Public

| Page | What it covers |
|------|----------------|
| [Landing](public/home.md) | Public product landing — sign in or jump to Command Deck when already authenticated. |

---

10 guides. Regenerate: `node scripts/user-docs/generate-guide-index.mjs`.
