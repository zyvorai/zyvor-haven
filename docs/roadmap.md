---
hero:
  eyebrow: ROADMAP
  title: Roadmap
---

What ships in this repo today vs what the v1 controller and console will add. Operations for v0: [Getting started](getting-started.md).

## v0 — this repository
- CRDs for IdentityPlane, RealmBundle, OidcClient (`reclaimPolicy`, `suspend`)
- Compose overlays that deploy CNPG + official Keycloak Operator today
- CLI that reads the real operator admin secret and CRD presence
- Official `KeycloakRealmImport` sample (works without the Haven controller)
- Helm chart that installs RBAC only (controller/console images unpublished)
- UX and architecture specs
- Honest prod overlay: secrets, TLS, CA sync, backups called out as prerequisites

## v1 — controller + console (in progress)
- Controller with external-plane mode when operator CRDs are absent
- Live `GET /api/v1/plane/status` for Command Deck cards
- Console: login gate, Command Deck, Planes, Atlas, Realm Studio, Clients, Settings
- Password UI: console sign-in, Keycloak master admin, realm users
- Remote lab deploy script (`scripts/deploy-remote.sh`)
- Deploy wizard dual-mode: `IdentityPlane` create when RBAC allows, else Keycloak realm bootstrap
- Platform client catalog on Clients (kubernetes / grafana / argocd)
- Console OIDC (PKCE) + lab demo **opt-in** via `HAVEN_LAB_LOGIN=1`
- Remaining: full Kubebuilder reconcile of CNPG + Keycloak Operator + cert-manager
- Remaining: finalizer honoring `reclaimPolicy` (default Orphan)

## v1.1 — console depth
- Approvals in production profile
- Plane inspector (scale / backup / rotate)
- Backups + Time Machine screens (not in nav yet)

## v2 — private-cloud depth
- Multi-site status (Keycloak HA v2)
- Realm Time Machine
- One-click kube-apiserver Bind recipe on top of the platform catalog
- Backup restore wizard that creates a *new* plane
- Zeus OS Identity Center embed (iframe + shared OIDC session)
- Retire password bootstrap once OIDC is the default everywhere

## Non-goals until someone pays for them
- Managing LDAP/AD servers
- Being a generic Postgres platform
- Replacing Keycloak Admin Console entirely
