<div align="center">

<img src="docs/social/haven-hero-dark.jpg" alt="Haven - One intent. One console. Keycloak + HA Postgres." width="100%">

# Haven

### Identity for the private cloud.

One intent. One console. Official Keycloak + HA Postgres that actually ship together.<br>
A small packaging and operations layer over the official Keycloak Operator and CloudNativePG — not a replacement IdP, not managed SaaS, not a Keycloak fork.

[![CI](https://github.com/zyvorai/zyvor-haven/actions/workflows/ci.yml/badge.svg)](https://github.com/zyvorai/zyvor-haven/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-0071e3?style=flat-square&labelColor=1d1d1f)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-live-0071e3?style=flat-square&labelColor=1d1d1f)](https://zyvorai.github.io/zyvor-haven/)
[![Keycloak Operator](https://img.shields.io/badge/Keycloak_Operator-26.7.2-0071e3?style=flat-square&labelColor=1d1d1f)](versions.env)
[![CloudNativePG](https://img.shields.io/badge/CloudNativePG-1.27.1-0071e3?style=flat-square&labelColor=1d1d1f)](versions.env)
[![Version](https://img.shields.io/badge/version-0.1.0-0071e3?style=flat-square&labelColor=1d1d1f)](CHANGELOG.md)

[![Book a demo](https://img.shields.io/badge/Book_a_demo-0071e3?style=for-the-badge)](https://zyvor.dev/schedule?utm_source=github&utm_medium=haven&utm_campaign=readme_hero)
[![30-day PoC](https://img.shields.io/badge/30--day_PoC-1d1d1f?style=for-the-badge)](https://zyvor.dev/poc?utm_source=github&utm_medium=haven&utm_campaign=readme_hero)

[**Quick start**](#quick-start) · [**Console**](docs/console.md) · [**Docs**](https://zyvorai.github.io/zyvor-haven/) · [**Production**](#production-overlay) · [**License**](#license)

</div>

---

<a id="why-haven"></a>

## The gap Haven closes

The official Keycloak Operator runs Keycloak well. It **does not** manage the database. That gap is where production identity dies.

| Pain | What teams actually do | What Haven does |
|---|---|---|
| Database is “bring your own” | Bitnami chart, random StatefulSet, forgotten RDS URL | CloudNativePG cluster owned by the same plane |
| Secrets are tribal knowledge | `kubectl create secret` in Slack | Generated, rotated, referenced automatically |
| First-boot is a scavenger hunt | Hunt `-initial-admin`, guess hostname, fight TLS | Wizard + ready URL + operator bootstrap secret |
| Day-2 is two UIs and a prayer | kubectl + Keycloak admin, no backup story | One console: plane health, DB, realms, clients, backups |
| Multi-tenant private cloud | One Keycloak, many undocumented realms | Realms as first-class tenants with platform OIDC clients |

<a id="is-this-for-you"></a>Haven composes the **official** CloudNativePG and the **official** Keycloak Operator. No forks. No custom Keycloak image required for v0. How it compares with Auth0, Okta, Authentik, Zitadel and Cognito: [docs/why-haven.md](docs/why-haven.md).

> **Maturity (honest):** repository framed as **v0** — compose overlays, CLI, and CRDs are defined; Helm today “installs RBAC only (controller/console images unpublished)” until you opt in. Full Kubebuilder reconcile is v1, in progress. Production overlay is “a shape, not a one-command install.” Tagged release: `0.1.0`. See [docs/roadmap.md](docs/roadmap.md).

<a id="what-you-get"></a>

## What you get

<a id="console"></a>

<table>
<tr>
<td valign="top" width="33%">
<b>IdentityPlane</b><br>
One CR for Postgres + Keycloak + certs + ingress (controller path in v1).<br>
<a href="docs/architecture.md">Architecture</a>
</td>
<td valign="top" width="33%">
<b>Compose today</b><br>
<code>deploy/overlays/{dev,prod}</code> are the exact manifests the controller will render.<br>
<a href="docs/what-you-get.md">Components</a>
</td>
<td valign="top" width="33%">
<b>Command Deck</b><br>
Live plane and Keycloak health in one glass.<br>
<a href="docs/console.md">Console: routes and auth</a>
</td>
</tr>
<tr>
<td valign="top" width="33%">
<b>Realm Studio</b><br>
Realms, users, clients and IdPs without living in the Keycloak admin UI.<br>
<a href="docs/console.md">Console</a>
</td>
<td valign="top" width="33%">
<b>CLI</b><br>
<code>deploy</code>, <code>status</code>, <code>doctor</code>, <code>admin</code>, <code>backup</code>.<br>
<a href="docs/cli.md">CLI</a>
</td>
<td valign="top" width="33%">
<b>Private-cloud defaults</b><br>
NetworkPolicies, TLS and metrics on in <code>production</code>.<br>
<a href="docs/security-posture.md">Security posture</a>
</td>
</tr>
</table>

```text
  you ──► IdentityPlane CR ──► Haven controller (v1)
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
              CloudNativePG   Keycloak CR    Certs + Gateway
              (HA Postgres)   (official op)  (cert-manager)

  v0 compose path: deploy/overlays/{dev,prod}  (no controller required)
```

**Scope:** Haven deploys and operates Keycloak + PostgreSQL (CloudNativePG). It is **not** an AI agent or app-data tool — the Postgres cluster is Keycloak’s store, not your app OLTP. Pinned versions: [`versions.env`](versions.env). Design principles: [docs/what-you-get.md](docs/what-you-get.md).

## Quick start

```bash
git clone https://github.com/zyvorai/zyvor-haven.git
cd haven

# 1. Operators (once per cluster)
./deploy/operators/install.sh

# 2. Postgres + Keycloak
make dev
make wait
make doctor
make admin
```

| | |
|---|---|
| Keycloak Admin | `http://auth.127.0.0.1.nip.io/admin` |
| Bootstrap secret | `platform-initial-admin` in namespace `identity` |
| First realm | `make realm-import` (optional) |

Remote lab console and the local UI: [docs/quick-start.md](docs/quick-start.md). First deploy in depth: [docs/getting-started.md](docs/getting-started.md).

<a id="install-with-helm"></a>

## Install with Helm

```bash
helm install haven oci://ghcr.io/zyvorai/charts/haven --version 0.1.0 \
  --set controller.enabled=true \
  --set console.enabled=true
```

Images: `ghcr.io/zyvorai/haven-console:0.1.0` · `ghcr.io/zyvorai/haven-controller:0.1.0`. Controller and console default to `enabled: false`; chart installs RBAC by default. Details: [docs/install-helm.md](docs/install-helm.md).

<a id="production-overlay"></a>

## Production overlay

`deploy/overlays/prod` is a shape, not a one-liner. Read [docs/production-overlay.md](docs/production-overlay.md) before apply:

1. `./hack/gen-prod-secrets.sh` — do not use the placeholder password
2. Wait for CNPG, then `./hack/sync-cnpg-ca.sh` (Keycloak verifies DB TLS)
3. Issue `platform-tls` from your ClusterIssuer
4. Configure backups separately ([docs/backups.md](docs/backups.md))

<a id="documentation"></a>

## Documentation

| Doc | When to read |
|---|---|
| [zyvorai.github.io/zyvor-haven](https://zyvorai.github.io/zyvor-haven/) | Product docs |
| [docs/faq.md](docs/faq.md) | Deciding whether to adopt |
| [docs/getting-started.md](docs/getting-started.md) | First deploy |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Real operational issues |
| [docs/architecture.md](docs/architecture.md) | CRDs, reconcile order |
| [docs/roadmap.md](docs/roadmap.md) | v0 / v1 / v2 scope |

Every page, with the comparison and design principles: [docs/documentation-map.md](docs/documentation-map.md). Social assets: [docs/social/](docs/social/).

## License

Commercial subscriptions and support: see [docs/SUBSCRIPTION-MODEL.md](docs/SUBSCRIPTION-MODEL.md).

### Open source (Apache-2.0)

Licensed under the [Apache License, Version 2.0](LICENSE). Personal, lab, and commercial production use at no charge, subject to Apache-2.0 (preserve notices / NOTICE where required). See [NOTICE](NOTICE) for third-party attribution (Keycloak and CloudNativePG remain under their own licenses).

### Enterprise

Production support, SLAs, and Zyvor Enterprise products are licensed separately.
Contact [sales@zyvor.dev](mailto:sales@zyvor.dev) or see [zyvor.dev](https://zyvor.dev?utm_source=github&utm_medium=haven&utm_campaign=readme_footer).

**Next step:** [Book a demo](https://zyvor.dev/schedule?utm_source=github&utm_medium=haven&utm_campaign=readme_footer) · [30-day PoC](https://zyvor.dev/poc?utm_source=github&utm_medium=haven&utm_campaign=readme_footer)
