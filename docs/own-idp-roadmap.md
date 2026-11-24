# haven-idp: beyond Keycloak parity

Parity (OIDC core, admin API, native Provider) is in flight. This is everything
else we intend to build, ordered by value per effort. Principle: **secure by
default, zero to first login in one command, and no feature that needs a second
product to be useful.**

## Tier 1: ease of use (build first)
1. **One-command start.** `haven-idp init` generates secrets/keys and a config;
   `haven-idp dev` runs with an embedded store and prints a ready login URL and a
   test user. No Postgres needed for dev, CNPG for production.
2. **Add-an-app wizard + live OIDC debugger.** Register an app, get copy-paste
   snippets (Go, Node, Python, Rust, kubectl/oidc-login, nginx/oauth2-proxy) with
   issuer, client id and redirect URI filled in; a "Test login" button shows the
   decoded tokens and which check failed, with a fix.
3. **Config as code.** Declarative realm files (`haven-idp apply`, `plan`, `diff`),
   reusing `realmdiff` and `policy`. GitOps friendly; the console shows drift.
4. **Kubernetes-native apps.** An `OIDCClient` CRD (and an Ingress annotation):
   the controller creates the client and writes its secret to a Secret. Apps
   register themselves; no console clicks.
5. **Device authorization grant (RFC 8628) and a `haven login` CLI** so terminals,
   kubectl and CI log in without pasting tokens.
6. **Dynamic client registration (RFC 7591)** behind an admin-issued initial
   access token, for tools that self-register.

## Tier 2: modern authentication
7. **Passkeys (WebAuthn) first-class**, passwordless by default; TOTP, recovery
   codes, email magic links as fallbacks.
8. **SSO sessions** with idle/absolute timeouts, remember-device, single logout
   (back-channel logout).
9. **Leaked-password and weak-password checks** offline (k-anonymity bloom
   filter shipped with the binary; no third-party call).
10. **Sender-constrained tokens** (DPoP, mTLS) so a stolen token is useless.

## Tier 3: differentiators (what Keycloak does not have)
11. **Guard as an admission gate.** Every write is scored first; configs that
    would introduce a High finding are refused (or require an explicit,
    audited override). The posture score becomes a property you cannot regress.
12. **Native Time Machine: undo anything.** An append-only change log gives
    point-in-time restore and per-change undo, not only whole-realm snapshots.
13. **Time-boxed access (JIT).** Roles and group memberships with an expiry,
    request/approve flow, break-glass accounts that auto-expire and alert;
    feeds Access Review so recertification is mostly automatic.
14. **Workload identity for pods.** Token exchange (RFC 8693) from a Kubernetes
    ServiceAccount or SPIFFE ID to a scoped access token: services get identity
    with no static secrets.
15. **Agent and MCP identities.** OAuth for AI agents and MCP servers: resource
    indicators (RFC 8707), scoped short-lived grants a human approves, consent
    receipts, and a kill switch per agent.
16. **Risk-based step-up.** Impossible travel, new device, velocity and
    credential-stuffing signals trigger step-up or block, with the reason shown.

## Tier 4: operations and integration
17. **Observability built in:** Prometheus metrics, OpenTelemetry traces, an
    audit stream (webhook, NATS, syslog) per realm. No secrets in any of it.
18. **Federation:** upstream OIDC first, then Entra/Google/GitHub, then SAML,
    LDAP and SCIM provisioning. The existing Federation Hub templates apply.
19. **HA by default:** stateless replicas, keys and sessions in Postgres,
    zero-downtime key rotation and migrations.
20. **Migration:** `haven-audit import-keycloak` turns a Keycloak realm export
    into a native realm (users with password hashes where portable).

## Order of work
Parity merge -> 1, 3, 17 (foundation) -> 5, 6, 8 -> 7 -> 4, 2 -> 11, 12, 13 ->
14, 15 -> 9, 10, 16 -> 18, 19, 20.

## Status (updated)
Done and verified end to end: parity (OIDC core, Admin API v1, native Provider,
selectable console backend), #1 `haven-idp init` / `dev` (with a browser OIDC
playground, the first slice of #2), #3 config as code (`validate`/`plan`/`apply`/
`export`, Guard gate, drift `--check`), #17 observability (Prometheus metrics,
W3C tracing with OTLP export, hash-chained audit stream to stdout/file/signed
webhook, dashboards and alert rules), and #7's email transport: self-service email verification and
password reset (SMTP, single-use links; see
[email-and-password-reset.md](email-and-password-reset.md)).

Item 9 (offline weak/leaked-password checks) is partially done;
see [password-policy.md](password-policy.md). Shipped in the policy engine:
`notCommon()` against an embedded 71k-entry pattern-derived list (not a breach
corpus), `notPersonal()` (via `CheckPolicyFor`), and the `notBreached()` bloom
filter mechanism with builder and loader. Not done: a real breach corpus (none
is shipped), wiring `CheckPolicyFor` into the handlers, and the
`HAVEN_IDP_BREACH_FILTER` setting.

Known gaps carried forward: authorization-code replay and refresh-reuse
revocation of already-issued tokens is partly in-memory (not shared across
replicas); federation is not implemented on the native backend; rotated-secret
overlap is unsupported; `--prune` removes clients only.
