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
playground, the first slice of #2; the add-an-app wizard and Test login debugger are in [add-an-app.md](add-an-app.md)), #3 config as code (`validate`/`plan`/`apply`/
`export`, Guard gate, drift `--check`), #17 observability (Prometheus metrics,
W3C tracing with OTLP export, hash-chained audit stream to stdout/file/signed
webhook, dashboards and alert rules), and #7's email transport: self-service email verification and
password reset (SMTP, single-use links; see
[email-and-password-reset.md](email-and-password-reset.md)), and SSO sessions with single logout
(`haven_sso` cookie, `prompt`/`max_age`, `sid`, RP-initiated and back-channel logout, Admin session
routes; see [sso-and-logout.md](sso-and-logout.md)). #11 Guard as an admission gate is done for
realm create/update and client create/update (off, warn or enforce, audited overrides, waivers, dry-run
route; see [guard-gate.md](guard-gate.md)); users, roles, groups and realm import are not gated.
The `haven` CLI client (device-flow login, `haven token`, kubectl exec plugin; see [haven-cli.md](haven-cli.md)) is tested against a fake RFC 8628 IdP and was run end to end against the real `haven-idp` device endpoint (login with approval, `token`, `whoami` with JWKS-verified ID token, `exec-credential`, `logout`); it has no OS keychain and no Windows cross-process lock.
#13 is partly done: time-boxed *role* grants (reason, expiry, realm policy, audit, Admin API) are in [time-boxed-access.md](time-boxed-access.md); there is no approval workflow, no break-glass alerting, no group-membership expiry and no Access Review integration yet.
The OAuth device authorization grant (RFC 8628) for terminals and CI (opt-in per client, login reuses the normal flow incl. extra auth steps; fixed TTL/interval, no admin view of pending requests; see [device-flow.md](device-flow.md)).
OAuth dynamic client registration (RFC 7591/7592) behind
admin-issued initial access tokens (no anonymous mode, no software statements or JWT-secured registration, per-client
scope is recorded but not enforced at authorize; see [dynamic-client-registration.md](dynamic-client-registration.md)).
TOTP two-step verification with recovery codes (login step, enforced enrollment via a per-realm `requireMfa` policy, account page, Admin reset; see [mfa-totp.md](mfa-totp.md)); not done there: QR code, `amr`/`acr` claims, a link to the account page.
Workload identity (RFC 8693 token exchange and RFC 7523 JWT bearer: a Kubernetes projected service-account token, verified against pinned issuer, audience and subject and an inline or SSRF-safely fetched JWKS, is exchanged for a short-lived secretless token; see [workload-identity.md](workload-identity.md)) and agent/MCP identities (owner-bound, scoped, short-TTL revocable credentials, delegated tokens with an RFC 8693 `act` claim, audited, Admin API only; see [agent-identities.md](agent-identities.md)) are done with software-signed test tokens only: not run against a real cluster or MCP client, no `jti` single-use, no delegation chains or owner self-service page.
WebAuthn passkeys (first factor and second factor, account page, Admin API; hand-rolled verifier, attestation `none`/`packed` self only, tested with software authenticators and a headless-Chrome virtual authenticator, not with real hardware; see [passkeys.md](passkeys.md)).
Ingress-annotation app registration (item 4) is implemented in the controller and unit-tested against the fake client only, not on a real cluster; see [ingress-registration.md](ingress-registration.md).
A per-realm "use another method" fallback between an enrolled passkey and TOTP, and risk-based step-up (new device cookie, network change, idle, sensitive scope, `max_age`; pure decision function, report-only mode, blocks silent SSO reuse and forces factor enrollment; see [login-fallback-and-stepup.md](login-fallback-and-stepup.md)); not done there: geo/ASN/reputation/fingerprint signals, per-client or per-user rules, `acr`/`amr`, step-up for federated logins or refresh tokens, a user-facing devices page; fallback was not exercised with a real hardware passkey.
DPoP (RFC 9449) sender-constrained tokens at the token and userinfo endpoints (ES256/RS256/EdDSA proofs, replay cache, `cnf.jkt` on access tokens and on public-client refresh tokens, introspection reports `cnf`) and the RFC 8628 device grant in dynamic client registration (opt-in per realm policy); not done: `dpop_jkt` at the authorize endpoint, per-client "DPoP required", DPoP on revocation and client authentication, mTLS binding; see [dpop.md](dpop.md).
MCP client onboarding and consent: OAuth Client ID Metadata Documents (https `client_id`, SSRF-safe fetch with size/time/cache limits, exact redirect and identity checks, public PKCE-only clients, off per realm by default), a consent screen for CIMD and dynamically registered clients, remembered/revocable grants with an account page and Admin API, hash-chained consent receipts and a per-client/per-agent kill switch (see [mcp-clients-and-consent.md](mcp-clients-and-consent.md)); not done: per-scope consent, binding granted `resource`s into token `aud`, signed metadata or `private_key_jwt`, recalling already issued access tokens, an external anchor for the receipt chain, and a run against a real MCP client.
`haven-idp dev --persist DIR` keeps dev state across restarts (periodic atomic JSON snapshot, owner-only files; plain-text-at-rest and dev only, short-lived rows are not kept; see [dev-persist.md](dev-persist.md)). Self-service "change my email" (`/account/email`: password re-auth every time, link to the new address, notice to the old one, rate limits) is in [email-and-password-reset.md](email-and-password-reset.md); it needs SMTP and has no admin approval or per-realm policy. Time Machine undo on the native backend (preview, fingerprint-bound apply, audit journal) is in [time-machine-undo.md](time-machine-undo.md): it reverts added/removed objects only, not edits, and cannot delete roles/groups or remove role mappings because the Admin API has no such routes.

Item 9 (offline weak/leaked-password checks) is partially done;
see [password-policy.md](password-policy.md). Shipped in the policy engine:
`notCommon()` against an embedded 71k-entry pattern-derived list (not a breach
corpus), `notPersonal()` (via `CheckPolicyFor`), and the `notBreached()` bloom
filter mechanism with builder and loader. Not done: a real breach corpus (none
is shipped), wiring `CheckPolicyFor` into the handlers, and the
`HAVEN_IDP_BREACH_FILTER` setting.

#4 Kubernetes-native apps: the `OIDCClient` CRD is done (the controller creates the
client and writes its secret to a Secret; see [oidcclient-crd.md](oidcclient-crd.md)). It has
not been run on a real cluster. The Ingress annotation half of #4 is **not** done.

Known gaps carried forward: authorization-code replay and refresh-reuse
revocation of already-issued tokens is partly in-memory (not shared across
replicas); federation (identity brokering) covers upstream OIDC only (Google, Microsoft Entra ID, generic OIDC; see [federation.md](federation.md)) and does not cover SAML, GitHub, LDAP/SCIM, an account-linking UI, storing upstream tokens or IdP-initiated login; rotated-secret
overlap is unsupported; `--prune` removes clients only.
