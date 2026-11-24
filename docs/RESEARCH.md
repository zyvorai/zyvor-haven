# Identity-platform research for Haven

Scope: what comparable identity products and standards offer that matters to
Haven (Keycloak + CloudNativePG as one private-cloud plane), what Haven lacks,
and which gaps fit Haven's boundaries. Date of research: 2026-11-23.

Evidence labels. A claim without a label was read from a page fetched during
this session (URL given). **[U]** marks a claim written from prior knowledge
that was not re-read from a fetched page; verify before relying on it.

## Haven's boundaries (from the repository)

- Haven is a packaging and operations layer over the official Keycloak
  Operator and CloudNativePG. It is not a replacement IdP and not a Keycloak
  fork (README).
- Secrets: snapshots, diffs and reports never carry client secrets, passwords
  or credential payloads (docs/identity-ops.md, Credential Center).
- Honesty: README maturity table and "deterministic" Guard rules. Features
  must say what they do not do.
- Restores go to a new realm, never in place (docs/identity-ops.md).
- Every source file carries the SPDX header; commits carry a DCO sign-off.

## What the field does

### Keycloak itself

- `kc.sh export` / `import` run with the server stopped; exports are JSON,
  can split users into files, and do not include events, persisted sessions or
  revoked tokens. The docs call the process limited as a backup mechanism and
  say Admin Console partial exports mask secrets with `*`.
  <https://www.keycloak.org/server/importExport>
  Implication for Haven: realm JSON in Git is the practical GitOps artefact,
  and a reviewer needs a readable, secret-safe diff of it. Haven had a
  fingerprint ("something changed") and Time Machine diff ("which objects
  changed") but no field-level diff of two exports.
- Keycloak realm settings Guard could evaluate but did not: SSL requirement,
  password policy, token and session lifetimes, event storage, refresh-token
  revocation. [U] (setting names from the Admin REST `RealmRepresentation`;
  the Server Admin Guide fetch returned only a table of contents.)
- The Keycloak Operator's `KeycloakRealmImport` CR imports a realm once and
  does not reconcile later changes. [U]

### Authentik

- Blueprints: YAML files applied atomically (one DB transaction, rolled back
  on any failure), discovered from a watched directory, validated when saved.
  The page describes no dry-run and no drift detection.
  <https://docs.goauthentik.io/customize/blueprints/>
  Gap relative to Haven: Guard already detects drift by fingerprint; neither
  product previews a change against a live realm before applying.

### Zitadel, Ory, Dex, FusionAuth

- Comparison pages list Zitadel and Authentik as having audit logs and log
  streams, Zitadel with event-driven webhooks and Actions, Ory Kratos with
  JSON configuration and webhooks. An editorial source with no stated
  methodology: <https://ssojet.com/ciam-vendors/comparison/authentik-vs-zitadel/>
  Dex is an OIDC/OAuth2 identity broker, not an identity manager. [U]
  FusionAuth offers "Kickstart" file-based provisioning and a Terraform
  provider. [U]
  Takeaway: audit-event streaming is table stakes; Haven's Keycloak plane can
  only stream if events are enabled, which Guard did not check.

### Microsoft Entra ID (admin tooling)

- Emergency-access (break-glass) accounts: two or more cloud-only accounts
  with permanent top-level admin rights, not tied to individuals, excluded
  from blocking policies, protected by strong passwordless methods such as
  passkeys, tested regularly (for example quarterly) and monitored on
  sign-in. Privileged account reviews can be run as access reviews, and a CIS
  benchmark item suggests access reviews for break-glass users.
  <https://learn.microsoft.com/azure/active-directory/roles/security-emergency-access>
  <https://learn.microsoft.com/en-us/entra/architecture/ops-guide-govern>
- Access reviews / recertification campaigns (reviewer decisions with
  justification, review of privileged roles) are a licensed Entra ID
  Governance feature. [U]

### Standards and guidance

- RFC 9700 (OAuth 2.0 Security BCP): exact redirect URI matching, no implicit
  grant, mandatory PKCE for public clients with S256, refresh tokens of public
  clients sender-constrained or rotated, the password grant must not be used.
  <https://www.rfc-editor.org/rfc/rfc9700> Guard HAVEN001-010 already cover
  most of this; refresh-token rotation was missing (now HAVEN021).
- NIST SP 800-63B-4: password-only authentication needs at least 15
  characters (8 when used with MFA), no composition rules, no periodic
  rotation, and verifiers must offer a phishing-resistant option at AAL2.
  <https://pages.nist.gov/800-63-4/sp800-63b.html> Guard now flags password
  policies below 12 characters or absent (HAVEN015/016).
- SCIM 2.0 (RFC 7643/7644) is the standard provisioning protocol; Keycloak
  has no first-party SCIM server. [U]
- OpenID Connect conformance suite and FAPI profiles for certification. [U]
- WebAuthn/passkeys: Keycloak 26 supports passkeys, including conditional UI.
  [U]

## What Haven lacked

1. Guard checked only registration, brute force and client rules. Realm
   transport, password, token, session, event and refresh-token settings were
   invisible.
2. No way to encode an organisation's own baseline ("access tokens at most 15
   minutes", "every client has an owner") and gate CI on it.
3. No readable, secret-safe diff between two realm exports for pull requests.
4. No recertification workflow: Time Machine stores who holds which role, but
   nothing flags privileged or stale access, checks break-glass coverage, or
   records reviewer decisions.
5. No audit-event streaming, SCIM, conformance testing or realm-import
   reconciliation.

## Ranked ideas

| Rank | Idea | Why | Fit | Decision |
|---|---|---|---|---|
| 1 | Realm hardening rules in Guard (HAVEN014-023) | Cheapest, deterministic, standards-backed (RFC 9700, NIST 800-63B-4); closes the biggest blind spot | Same engine, same CI | Built |
| 2 | Policy as code (`haven-audit --policy`) | Lets each tenant encode its own baseline; no code execution, bounded input | Offline, deterministic, no secrets | Built |
| 3 | Access Review campaigns + break-glass check | Recertification and emergency-access hygiene are the governance gap vs Entra; reuses Time Machine data | Records decisions only, never mutates Keycloak | Built (API, CLI, console page) |
| 4 | Secret-safe realm diff (`haven-audit diff`) | Makes realm JSON in Git reviewable; complements fingerprint drift | Pure function, redaction by construction | Built |
| 5 | Audit-event streaming sink (Keycloak event listener to webhook/OTLP) | Table stakes elsewhere | Needs an in-cluster component and a real Keycloak to test; HAVEN019/020 only check that events are on | Rejected for now |
| 6 | SCIM provisioning | Standard for HR/SaaS lifecycle | Keycloak has no SCIM server; a bridge is a product of its own and needs a live IdP to validate | Rejected for now |
| 7 | Realm import reconciliation controller (apply realm JSON, then keep it in sync) | Closes the `KeycloakRealmImport` one-shot gap | Large controller change, cannot be tested without Kubernetes and Keycloak | Rejected for now |
| 8 | OIDC/SAML conformance runner | Certification evidence | Needs a running IdP and the conformance suite | Rejected for now |

## Honest limits of this work

- Nothing here was run against a real Keycloak, PostgreSQL, Kubernetes or a
  browser. Rules read the standard `RealmRepresentation` field names; the
  live API path is covered by unit tests with synthetic data only.
- Guard treats a setting a source omits as unknown, not as a finding. A
  realm export produced by a tool that strips settings will therefore look
  cleaner than it is.
- Access Review sees only realm-role and group assignments that Time Machine
  captures. Client-role mappings and composite roles are not expanded, so a
  user can hold admin access through a path the review does not show.
