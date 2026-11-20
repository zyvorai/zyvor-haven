---
hero:
  eyebrow: USER GUIDE
  title: Common workflows
---

Each recipe assumes `http://<host>:30742/` is reachable.

## Verify a fresh lab

1. Deploy: `./scripts/deploy-remote.sh <host> <user>` ([Getting Started](getting-started.md)).
2. Sign in (`demo` / `demo` or admin).
3. [Command Deck](pages/console/deck.md) — Connected + Ready (or external Postgres noted).
4. [Settings](pages/console/settings.md) — green Connected banner.
5. [Atlas](pages/console/atlas.md) — path hops look healthy.

## Create a realm and invite a user

1. [Realm Studio](pages/console/realms.md) → **+ Create realm**.
2. Open [Realm detail](pages/console/realms-realm.md) → **+ Invite user**.
3. Set password when prompted; verify login against that realm’s account console if needed.

## Mint an OIDC client

1. [Clients](pages/console/clients.md) (or realm detail Clients tab).
2. Create confidential/public client with redirect URI for your app.
3. Copy client secret once; paste into the relying party.
4. Optional: regenerate secret later with confirm.

## Deploy a new identity plane

1. [Deploy wizard](pages/console/deploy.md) → Review & Deploy.
2. Watch [Planes](pages/console/planes.md) and Deck reconcile timeline until Ready.

## Related

- [Using the Dashboard](using-the-dashboard.md)
- [Passwords](passwords.md)
