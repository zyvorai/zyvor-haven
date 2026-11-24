# Why Haven

Why running identity yourself needs more than an identity server, and an honest maturity note.

[Back to the README](https://github.com/zyvorai/haven#readme) · [Documentation map](documentation-map.md)

---

## The gap

Running identity yourself is easy to start and hard to keep safe. An identity server alone does not give you a database you can fail over, secrets nobody pasted into chat, or a way to tell whether your realms are configured safely. Haven makes the safe path the default one.

| Pain | What teams actually do | What Haven does |
|---|---|---|
| Database is "bring your own" | Random StatefulSet, forgotten RDS URL | CloudNativePG cluster owned by the same plane |
| Secrets are tribal knowledge | `kubectl create secret` in Slack | Generated once, never overwritten, referenced automatically |
| First-boot is a scavenger hunt | Hunt the admin password, guess the hostname, fight TLS | One `IdentityPlane`, a ready issuer URL and a generated admin secret |
| Day-2 is two UIs and a prayer | kubectl plus an admin console, no backup story | One console: plane health, DB, realms, clients, backups |
| Multi-tenant private cloud | Many undocumented realms | Realms as first-class tenants, with config as code |
| Nobody can say if realms are safe | Occasional manual review | Haven Guard posture scoring, drift detection and SARIF for CI |

The identity server is `haven-idp`, Haven's own Go OIDC server with secure defaults (PKCE S256 only, Argon2id, ES256 tokens, passkeys and TOTP). It stores everything in PostgreSQL and runs as stateless replicas. Nothing in the default install needs a second product to be useful.

## Is this for you?

Haven is a small, source-available (Zyvor Production Licence v2.0) identity product for the private cloud: an identity server, an operations layer and a console. It is not managed SaaS and it is not FAPI certified (FAPI 2.0 is a set of building blocks).

> **Maturity (honest):** Haven is young. The identity server, controller and console are implemented and covered by unit, handler and store-conformance tests (the store suite runs against real PostgreSQL), and the core stack has been deployed and exercised on a k3s cluster. Newer features have been run against the dev binary but not against third-party production systems. The production overlay is "a shape, not a one-command install." Tagged release: `0.1.0`. Per-feature status and "not yet" lists: [own-idp-roadmap.md](own-idp-roadmap.md) and [roadmap.md](roadmap.md).

Moving from another identity server? See [Migrate from Keycloak](migrate-from-keycloak.md).

New here? [docs/faq.md](faq.md) · [docs/troubleshooting.md](troubleshooting.md)
