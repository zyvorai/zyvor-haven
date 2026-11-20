---
hero:
  eyebrow: UX
  title: Haven UX — private-cloud identity, not an admin form
---

The target feeling is Zeus OS: an infrastructure desktop, not a settings page. Identity is a fleet you operate.

**Current console:** route map and auth in [console.md](console.md). **Recipes:** [tutorials.md](tutorials.md). **Scope:** [roadmap.md](roadmap.md).

## Command palette first

`⌘K` / `Ctrl+K` is the primary navigation.

```
Deploy a new identity plane
Open plane “platform”
Show database lag
Restore realm platform to yesterday 02:00
Mint OIDC client for Grafana
Rotate bootstrap admin
Invite tenant admin
```

Every destructive action is preview → confirm → audit.

## Information architecture

```
Haven
├── Command Deck          plane health, endpoints, last backup, certs
├── Planes                list / create wizard
│     └── Plane inspector
│           Overview · Database · Keycloak · Endpoints · Events
├── Realm Studio          realms as tenants
│     └── Realm
│           Clients · Roles · IdPs · Themes · Users (set password)
├── Clients               platform OIDC clients + secret status
├── Backups               CNPG backups + Keycloak realm exports
├── Approvals             realm diffs waiting for a second pair of eyes
├── Time Machine          CR + realm JSON history
├── Atlas                 topology: Gateway → Keycloak → Postgres
└── Settings              Keycloak connect, theme, passwords
```

Density modes inherited from Zeus OS: Compact, Comfortable, Theatre.

## Deploy wizard — four questions

Most Keycloak-on-Kubernetes guides are twelve files. Haven asks four questions.

**1. Who is this for?**
- Platform SSO (Kubernetes, Grafana, Argo, Zeus OS)
- Application tenants (B2B realms)
- Both

**2. How durable?**
- Dev — 1 Postgres, 1 Keycloak, disposable
- Staging — 2/2, daily backup
- Production — 3/3, PITR, NetworkPolicy, PDB

**3. How do people reach it?**
- Hostname
- TLS issuer (cluster issuer / provided secret / automatic self-signed)
- Gateway API or Ingress class

**4. Who signs in first?**
- Admin email
- First realm name
- Optional: attach platform clients from a catalog (Zeus OS, k8s, Grafana, Argo CD)

Submit writes one `IdentityPlane`. The Deck switches to a live reconcile timeline:

```
✓ Namespace + network policy
✓ PostgreSQL cluster  1/3 → 3/3
✓ Database TLS + role
✓ Certificate issued
◉ Keycloak rolling  2/3
○ First realm import
○ Console OIDC bind
```

No log diving required unless a step fails. Failed steps open the exact Condition and a suggested fix.

## Plane inspector

Orbit cards on Overview:

| Card | Source | Good | Bad |
|---|---|---|---|
| Phase | IdentityPlane.status | Ready | Degraded / Failed |
| Keycloak replicas | Keycloak CR | 3/3 | 2/3 for >2m |
| DB primary | CNPG status | RW service ready | failover in progress |
| Replication lag | CNPG metrics | < 32MB | > 256MB |
| Last backup | ScheduledBackup | < 26h | > 36h |
| Cert expiry | Certificate | > 21d | < 14d |
| Login RPS | Keycloak metrics | sparkline | error rate |

Actions on the inspector toolbar:

- Scale (instances for KC and/or PG)
- Backup now
- Rotate DB password
- Rotate TLS
- Open Keycloak admin (SSO)
- Open Grafana folder
- Suspend (scale to zero Keycloak, keep DB)
- Destroy (two-step, typed name)

## Database is a first-class screen

This is the gap every Keycloak Helm chart leaves.

- Topology: primary + replicas, AZ labels
- Storage used / PVC
- Connections vs pool
- Backup calendar + one-click restore to a *new* plane (never in-place on production without Approval)
- WAL archive status
- Switchover (calls CNPG)

Engineers stop SSH-ing into Postgres pods to answer “is auth down because of the DB?”

## Realm Studio

Realms are tenants of the private cloud.

- List with user count, client count, last login, SSO bindings
- Create from blueprint: `platform-sso`, `b2b-tenant`, `ci-robots`
- Diff view before apply (Time Machine)
- Production profile: apply goes to Approvals
- Export is a `RealmBundle` you can put in Git

Keycloak Admin Console remains available for deep SPI work. Haven does not hide it; it links in with SSO and returns.

## Visual language

- Apple off-white / deep dark surfaces with Zyvor ink + blue accents (not SaaS purple)
- Monospace for endpoints, resource names, lag
- Human labels for phase
- Motion only on reconcile progress and failover
- Empty states teach the next verb (“Deploy your first plane”)
- Login matches Axiom: brand panel + glass sign-in card, with host/origin “This machine” context and lab/test credentials when enabled

## Console auth (current)

Axiom-style `/login` gates the console. Methods today:

1. **OIDC (Keycloak)** — authorization code + PKCE via the `haven-console` client when `HAVEN_OIDC_ISSUER` (or `{KEYCLOAK_URL}/realms/{HAVEN_BOOTSTRAP_REALM}`) is configured.
2. **Lab demo** — `demo` / `demo` only when `HAVEN_LAB_LOGIN` is explicitly `1`/`true`/`yes` (opt-in; lab deploy sets it).
3. **Local console** — `HAVEN_CONSOLE_*` or Keycloak admin env; changeable in Settings (in-process until restart).
4. **Keycloak admin** — username/password validated against the connected Admin API.

Sessions are Bearer tokens in `sessionStorage` (~12h). API routes under `/api/v1` (except health + auth providers/login/OIDC) require `Authorization: Bearer`.

Password ops without leaving Haven:

- Settings → change console password or Keycloak master admin
- Realm Studio → Users → Set password (temporary optional)

Deploy wizard is dual-mode: creates an `IdentityPlane` when the console SA can write CRs; otherwise bootstraps a realm on the connected Keycloak.

## CLI parity

```
haven deploy   -f plane.yaml
haven status   platform -n identity
haven open     platform            # prints + opens endpoints
haven backup   platform --now
haven realm    apply -f realm.yaml
haven client   mint grafana --realm platform
haven doctor   platform            # preflight + live checks
```

Output is table by default, `--json` for GitHub Actions.
