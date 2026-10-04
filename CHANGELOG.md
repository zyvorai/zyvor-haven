# Changelog

All notable changes to Haven are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Haven Guard: deterministic OIDC/Keycloak security posture scoring and drift detection, a live `/api/v1/security/posture` + SARIF API, an offline `haven-audit` CI CLI, and a console Guard page
- Time Machine: immutable per-realm recovery points with drift diff (clients, users, roles, groups, IdPs, access bindings) and safe restore into a new realm
- Credential Center: confidential-client secret inventory, rotation with overlap detection, and explicit retirement, never exposing the previous secret
- Federation Hub: guided onboarding templates for Microsoft Entra ID, Google Workspace, GitHub, generic OIDC, and SAML 2.0, with secret/certificate redaction on every response
- Optional persistent console volume (`console.persistence`) for durable Time Machine history, restricted to `console.replicas=1`
- CI now runs gofmt, golangci-lint, govulncheck and gosec, and tests with `-race`

### Changed

- Go 1.27.1, controller-runtime v0.25.2, current golang.org/x, Prometheus, zap and OpenAPI modules (Kubernetes libraries stay on v0.37.1, the latest stable)
- Operators: CloudNativePG 1.30.1, Keycloak Operator/server 26.8.0, cert-manager v1.21.2; PostgreSQL image 16.15
- Images: golang 1.27.1-alpine, node 24 LTS, nginx 1.30.5-alpine, distroless static-debian13, all pinned by digest
- Release workflow: Helm v4.3.0, setup-buildx-action v4, action-gh-release v3; UI on Vite 8.3.2

### Security

- Each new IdentityPlane gets a random database password instead of the fixed `change-me-dev-only`; existing planes keep their stored password
- OIDC PKCE cookies are always cleared with HttpOnly and SameSite attributes

## [0.1.0] — 2026-09-04

### Added

- Initial Haven identity plane: compose overlays, console, controller scaffolding, Helm chart, and documentation
- Full Apache License 2.0 `LICENSE` and `NOTICE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, DCO
- GitHub Actions CI and Dependabot
- Published multi-arch images and Helm chart to GHCR:
  - `ghcr.io/zyvorai/haven-console:0.1.0`
  - `ghcr.io/zyvorai/haven-controller:0.1.0`
  - `oci://ghcr.io/zyvorai/charts/haven:0.1.0`

[Unreleased]: https://github.com/zyvorai/haven/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zyvorai/haven/releases/tag/v0.1.0
