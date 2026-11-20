# Why Haven

Why the Keycloak Operator alone is not enough, how Haven compares with the alternatives, and an honest maturity note.

[Back to the README](https://github.com/zyvorai/haven#readme) · [Documentation map](documentation-map.md)

---

## The gap

The official Keycloak Operator runs Keycloak well. It **does not** manage the database. That gap is where production identity dies.

| Pain | What teams actually do | What Haven does |
|---|---|---|
| Database is “bring your own” | Bitnami chart, random StatefulSet, forgotten RDS URL | CloudNativePG cluster owned by the same plane |
| Secrets are tribal knowledge | `kubectl create secret` in Slack | Generated, rotated, referenced automatically |
| First-boot is a scavenger hunt | Hunt `-initial-admin`, guess hostname, fight TLS | Wizard + ready URL + operator bootstrap secret |
| Day-2 is two UIs and a prayer | kubectl + Keycloak admin, no backup story | One console: plane health, DB, realms, clients, backups |
| Multi-tenant private cloud | One Keycloak, many undocumented realms | Realms as first-class tenants with platform OIDC clients |

Haven composes **official** CloudNativePG and the **official** Keycloak Operator. No forks. No custom Keycloak image required for v0.

## Is this for you?

Haven is a small, source-available (Zyvor Production License v1.0) **packaging/operations layer** over the official Keycloak Operator and CloudNativePG — not a replacement IdP, not managed SaaS, and not a Keycloak fork.

| | **Haven** | Plain Keycloak Operator | Auth0 / Okta | Authentik | Zitadel | AWS Cognito |
|---|---|---|---|---|---|---|
| Primary scope | Keycloak + HA Postgres as one plane | Keycloak lifecycle only — BYO database | Managed cloud IdP | Self-hosted IdP | Self-hosted IdP | Managed (AWS-tied) |
| Database included | Yes — CloudNativePG | No | N/A | You bring your own | You bring your own | N/A |
| Self-hosted / private cloud | Yes | Yes | No | Yes | Yes | No |
| License | Zyvor Production 1.0 (free non-production) | Apache-2.0 (Keycloak) | Proprietary | Apache-2.0/AGPL | Apache-2.0 + commercial | Proprietary |
| Identity engine | Keycloak (official, unmodified) | Keycloak | Proprietary | Custom | Custom | Custom |

*(General characterizations as of writing — verify against each project's own docs.)*

> **Maturity (honest):** repository framed as **v0** — compose overlays, CLI, and CRDs are defined; Helm today “installs RBAC only (controller/console images unpublished)” until you opt in. Full Kubebuilder reconcile is v1, in progress. Production overlay is “a shape, not a one-command install.” Tagged release: `0.1.0`. See [docs/roadmap.md](roadmap.md).

New here? [docs/faq.md](faq.md) · [docs/troubleshooting.md](troubleshooting.md)
