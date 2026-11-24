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
- Haven Guard realm hardening rules HAVEN014-023 (TLS requirement, password policy, token and session lifetimes including SSO max and offline idle, user and admin events, refresh-token rotation); settings a source omits produce no finding and the baseline fingerprint is unchanged
- Policy as code: `haven-audit --policy` evaluates declarative organisation rules (JSON, RE2 patterns, size caps, credential-bearing paths rejected) and merges them into text, JSON and SARIF output
- Access Review: privileged/stale account report, break-glass coverage check and recertification campaigns (`/api/v1/access-review`, `haven-audit access-review`, console page); decisions are recorded, Keycloak is never changed
- `haven-audit --waivers`: accepted-risk waivers with mandatory reason, approver and expiry; expired waivers reopen their finding and unused waivers are reported
- `haven-audit --known` / `--write-known`: gate CI on findings that are new since a saved baseline
- Haven Guard rules HAVEN024-030: login events kept forever, refresh-token reuse, loose brute-force lockout, offline sessions without a maximum lifespan, Full Scope Allowed, `offline_access` as a default scope, per-client access token lifespan above one hour (settings a source omits produce no finding; fingerprints unchanged)
- `haven-audit --format markdown` (PR comment / job summary) and `--format junit` (CI test reports, waived findings as skipped cases)
- `haven-audit rules` and `haven-audit explain RULE`: built-in rule catalog and per-rule remediation, with a test that keeps the docs table in sync
- `haven-audit diff --ignore GLOB` and `--format markdown`
- `haven-audit diff`: secret-redacting, field-level comparison of two realm exports for GitOps review
- docs/RESEARCH.md: identity-platform research and ranked ideas
- Optional persistent console volume (`console.persistence`) for durable Time Machine history, restricted to `console.replicas=1`
- CI now runs gofmt, golangci-lint, govulncheck and gosec, and tests with `-race`

### Changed

- Go 1.27.1, controller-runtime v0.25.2, current golang.org/x, Prometheus, zap and OpenAPI modules (Kubernetes libraries stay on v0.37.1, the latest stable)
- Operators: CloudNativePG 1.30.1, Keycloak Operator/server 26.8.0, cert-manager v1.21.2; PostgreSQL image 16.15
- Images: golang 1.27.1-alpine, node 24 LTS, nginx 1.30.5-alpine, distroless static-debian13, all pinned by digest
- Release workflow: Helm v4.3.0, setup-buildx-action v4, action-gh-release v3; UI on Vite 8.3.2
- Dependencies refreshed (`go get -u`): controller-runtime v0.25.3, client-go/api/apimachinery v0.37.2, prometheus client_golang v1.25.0, golang.org/x; UI on react-router-dom 7.18.6 and @vitejs/plugin-react 6.3.0
- Operators: CloudNativePG 1.30.2, Keycloak Operator/server 26.8.2 (security fixes), cert-manager v1.21.3; docs build runs on Python 3.14

### Removed

- **Breaking:** the Keycloak engine. `IdentityPlane` loses `spec.engine`, `spec.keycloak`, `status.keycloak`, `status.endpoints.keycloak|account|admin` and the `ProvisioningKeycloak` phase; the controller no longer renders or watches Keycloak CRs or `KeycloakRealmImport`, and its RBAC for `k8s.keycloak.org` is gone. The unreconciled `RealmBundle` CRD is removed. Existing planes only need the stale fields dropped (the API server prunes them once the new CRD is applied); see "Upgrading" in docs/architecture.md
- **Breaking:** the Keycloak Admin REST backend of the console (`internal/keycloak`, `KEYCLOAK_URL`, `KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD`; `HAVEN_IDP_BACKEND` accepts only `native`) and the Helm value `identity.backend`
- **Breaking:** console API routes `/api/v1/keycloak/{status,config,connect,admin-password}` are now `/api/v1/identity-server/{status,config,connect,admin-password}`, the payload field `keycloakUrl` is `identityServerUrl` and the error body field `keycloak` is `identityServer`; the console UI and API must be upgraded together
- **Breaking:** the plane condition `KeycloakReady` is now `IdentityProviderReady` in the console's plane status (the controller already emitted that name for `haven-idp` planes)
- Kept on purpose: `haven-idp import-keycloak`, legacy Keycloak password-hash verification for imported users, and the ability of Haven Guard / `haven-audit` to read a realm export JSON file

### Held back

- `k8s.io/kube-openapi` stays at the 20260721 pseudo-version: the 20261104 revision moves to `structured-merge-diff/v7`, which apimachinery v0.37.2 (still on v6) cannot compile against
- PostgreSQL stays on 16.15 (the newest 16.x CloudNativePG image tag); a major bump needs a `pg_upgrade` or dump/restore migration Haven does not provide
- The `go` directive and the golang/node image digests stay at 1.27.1 / 24.21.0 (digest-pinned); a bump needs new digests
- Unverified action pins left as is: golangci/golangci-lint-action v9, golang/govulncheck-action v1, softprops/action-gh-release v3

### Fixed

- CI: gosec v2.29.0 could not read Go 1.27 export data ("export data version 5") and failed every run; pinned to v2.30.0

- Console API request bodies are capped at 4 MiB (handlers decoded JSON straight from the request body without a limit)
- Time Machine and Access Review capture return an error instead of dereferencing a nil client when Keycloak is not connected
- `haven-audit` caps input files and stdin at 64 MiB

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
