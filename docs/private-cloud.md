---
hero:
  eyebrow: PRIVATE CLOUD
  title: Haven inside a private cloud (Zyvor-shaped)
---

Zyvor / Zeus OS already treats identity as a module (`/identity-center`). Haven is that module made real: a deployable plane, not a settings form that assumes Keycloak exists.

Deploy and operate: [Getting started](getting-started.md) · CRD design: [Architecture](architecture.md) · Console UX: [UX](ux.md)

## Mapping

| Zeus OS module | Haven surface |
|---|---|
| Command Deck | Plane health, endpoints, backup age |
| Identity Center | Realm Studio + Clients |
| Users & RBAC | First realm `platform` + groups mapped to Kubernetes RoleBindings |
| Approvals | RealmBundle diffs in production profile |
| Time Machine | CR + realm JSON history |
| Atlas | Gateway → Keycloak → CNPG topology |
| Marketplace | Realm blueprints (`platform-sso`, `b2b-tenant`, `ci-robots`) |

## Platform SSO catalog

A production plane can mint the clients every private cloud actually needs:

| Client | Used by | Type |
|---|---|---|
| `haven-console` | This product | public |
| `zeus-os` | VM/container control plane | public |
| `kubernetes` | API server OIDC | confidential |
| `grafana` | Observability | confidential |
| `argocd` | GitOps | confidential |
| `harbor` | Registry | confidential |

Each becomes an `OidcClient` CR. The controller writes a Secret the workload mounts. No copy-paste of client secrets into Helm values.

## Kubernetes API OIDC

Once the plane is Ready:

```
--oidc-issuer-url=https://auth.cloud.internal/realms/platform
--oidc-client-id=kubernetes
--oidc-username-claim=email
--oidc-groups-claim=groups
```

Haven does not patch kube-apiserver. It produces the values and a ClusterRoleBinding recipe in the console under **Clients → kubernetes → Bind**.

## Tenancy model

- One IdentityPlane per region / management cluster.
- Realms = tenants (or environments).
- B2B user gets a `RealmBundle` from blueprint `b2b-tenant`.
- Platform operators never share the `master`/`platform` admin password with tenants.

## Air-gapped

- Mirror Keycloak, CNPG, and cert-manager images.
- `spec.keycloak.image` and `spec.database.imageName` pin the mirrors.
- Issuer is an internal ClusterIssuer.
- Console ships as a static bundle; no CDN.

## What we deliberately do not wrap

- Guest VM identity agents
- SPIFFE / workload identity (pair later; Keycloak already growing federated client auth)
- LDAP server lifecycle (federation *targets* only)

Haven stays the identity *plane*. The rest of the private cloud stays Zeus OS / Forge / PacketWolf.
