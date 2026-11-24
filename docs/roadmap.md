---
hero:
  eyebrow: ROADMAP
  title: Roadmap
---

What is built, what is being finished and what comes later. The identity server's own per-feature status table, with honest "not yet" lists, is in [own-idp-roadmap.md](own-idp-roadmap.md). Operations: [Getting started](getting-started.md).

## Built (tagged release 0.1.0 and `main`)
- `haven-idp`: OIDC core, Admin API, Postgres store, passkeys, TOTP, SSO sessions and single logout, device flow, DPoP, PAR/JAR/RAR building blocks, SCIM, CIBA, consent, federation to OIDC upstreams, Shared Signals
- Controller with `IdentityPlane` and `OIDCClient` (the database, identity server, certificates, database NetworkPolicy and ingress from one resource), deployed on k3s
- Kustomize overlays (`deploy/overlays/dev`, `deploy/overlays/prod`) that render the same objects without a controller
- Helm chart (RBAC by default; controller and console are opt-in)
- Console: login gate, Command Deck, Planes, Atlas, Realm Studio, Clients, Settings, Access Review, console OIDC (PKCE)
- `haven` CLI (device login, kubectl exec plugin), `haven-audit` (offline Guard, diff, access review), `./cli/haven` for plane operations
- Haven Guard, Time Machine, Credential Center, Federation Hub, Policy as code, Access Review
- macOS service and Keychain support (unsigned)
- Honest prod overlay: secrets, TLS and backups called out as prerequisites

## In progress
- Finalizer honoring `reclaimPolicy` (default Orphan)
- Newer features run against third-party systems (real Okta/Entra for SCIM, a real Shared Signals receiver, real hardware authenticators)

## v1.1: console depth
- Approvals in production profile
- Plane inspector (scale / backup / rotate)
- Backups + Time Machine screens (not in nav yet)

## v2: private-cloud depth
- Multi-site status
- One-click kube-apiserver Bind recipe on top of the platform catalog
- Backup restore wizard that creates a *new* plane
- Zeus OS Identity Center embed (iframe + shared OIDC session)
- Retire password bootstrap once OIDC is the default everywhere

## Not started
- SAML, LDAP, organizations, i18n, mTLS client authentication

## Non-goals until someone pays for them
- Managing LDAP/AD servers
- Being a generic Postgres platform
