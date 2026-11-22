---
hero:
  eyebrow: FAQ
  title: FAQ
---

Questions people evaluating Haven actually ask, before they've decided to
adopt it. Already decided? [Getting started](getting-started.md) is a
better next stop.

## Licensing & cost

**Is it really free?** No. A 30-day trial is available on request from sales@zyvor.dev (a paid evaluation Order at no charge); production and any other use needs a paid Order under the Zyvor Production Licence v2.0. See the README's [License](https://github.com/zyvorai/haven#license)
section. Note Haven composes third-party projects (Keycloak, CloudNativePG)
that retain their own licenses — see [`NOTICE`](https://github.com/zyvorai/haven/blob/main/NOTICE).

**What does "Enterprise" mean here?** Production support, SLAs, and
Zyvor's other commercial products are licensed separately. Contact
sales@zyvor.dev. Nothing in this repository requires it.

## Support

**What if I find a bug?** Open a GitHub issue.

**What if I find a security vulnerability?** See [`SECURITY.md`](https://github.com/zyvorai/haven/blob/main/SECURITY.md)
— report to info@zyvor.dev or via GitHub Security Advisories. Security
fixes apply to the latest release on `main`; older tagged releases may not
be backported unless noted.

## Production readiness

**Is this production-ready?** Be precise about what exists today.
[`docs/roadmap.md`](roadmap.md) frames the current repository as **v0**:
compose overlays, the CLI, and CRDs are defined, but the Helm chart
"installs RBAC only (controller/console images unpublished)" — the full
Kubebuilder reconcile loop is v1, "in progress." Only one tagged release
exists (`0.1.0`). [`docs/production-overlay.md`](production-overlay.md)
describes itself as "a shape, not a one-command install" — read it in full
before a production deployment, don't assume defaults are production-safe.

**What problem does Haven actually solve?** The official Keycloak Operator
runs Keycloak well but "does not manage the database" — teams end up
improvising a Postgres backend (a Bitnami chart, a random StatefulSet, a
forgotten RDS URL) and hand-managing secrets. Haven instead ships a
CloudNativePG cluster owned by the same lifecycle as Keycloak, with
generated/rotated secrets and one console for both.

## Architecture

**Does Haven fork Keycloak or Postgres?** No — "Haven composes **official**
CloudNativePG and the **official** Keycloak Operator. No forks. No custom
Keycloak image required for v0." (README, "Why Haven")

**What are the design principles?** See the README's "Design principles"
section: database and Keycloak share a lifecycle; operators stay official
(not forked); secrets never leave the cluster; Git is optional, not
mandatory; private-cloud defaults (NetworkPolicies/TLS/metrics on in
`production`); identity is a platform service that can mint OIDC clients
for other platform components.

## Security

**What's the security posture?** See [`docs/security-posture.md`](security-posture.md)
for Haven Guard's scoring/drift detection, and [`SECURITY.md`](https://github.com/zyvorai/haven/blob/main/SECURITY.md)
for the reporting process and supported-version policy.
