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
section. Note Haven builds on third-party projects (CloudNativePG, cert-manager and
Go libraries) that retain their own licenses — see [`NOTICE`](https://github.com/zyvorai/haven/blob/main/NOTICE).

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

**Is this production-ready?** Be precise about what exists today. Haven is
young: the identity server, controller and console are implemented and covered
by unit, handler and store-conformance tests (the store suite runs against real
PostgreSQL), and the core stack has been deployed and exercised on a k3s
cluster. Newer features (SCIM, Shared Signals, CIBA, PAR/JAR/RAR, consent,
agent and workload identities) have been run against the dev binary but not
against third-party production systems, and FAPI 2.0 is a set of building
blocks, not a certified profile. Only one tagged release exists (`0.1.0`).
[`docs/production-overlay.md`](production-overlay.md) describes itself as "a
shape, not a one-command install" — read it in full before a production
deployment, don't assume defaults are production-safe. Per-feature status and
"not yet" lists: [`docs/own-idp-roadmap.md`](own-idp-roadmap.md).

**What problem does Haven actually solve?** Running identity yourself is easy to
start and hard to keep safe: a database nobody owns, hand-managed secrets, two
UIs for day 2, and no way to tell whether realms are configured safely. Haven
ships its own OIDC identity server (`haven-idp`) with a CloudNativePG cluster
owned by the same lifecycle, generated secrets, one console, and Haven Guard
posture checks.

**I run another identity server today. Can I move?** See
[Migrate from Keycloak](migrate-from-keycloak.md) and
[Import a Keycloak realm](import-from-keycloak.md).

## Architecture

**Does Haven fork anything?** No. The identity server is Haven's own Go code,
and the database and certificates come from the official CloudNativePG and
cert-manager operators, unmodified.

**What are the design principles?** See [What you get](what-you-get.md): the
database and identity server share a lifecycle; operators stay official (not
forked); secrets never leave the cluster; Git is optional, not mandatory;
private-cloud defaults (NetworkPolicies/TLS/metrics on in `production`);
identity is a platform service that can mint OIDC clients for other platform
components.

## Security

**What's the security posture?** See [`docs/security-posture.md`](security-posture.md)
for Haven Guard's scoring/drift detection, and [`SECURITY.md`](https://github.com/zyvorai/haven/blob/main/SECURITY.md)
for the reporting process and supported-version policy.
