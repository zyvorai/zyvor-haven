---
hero:
  eyebrow: TROUBLESHOOTING
  title: Troubleshooting
---

Real operational issues, with the documented fix. For the condensed
version, see [`runbook.md`](runbook.md)'s "Failure cheatsheet" — this page
expands on it. **First step in any incident: `./cli/haven doctor`.**

## haven-idp CrashLoopBackOff or never Ready

Check `kubectl -n identity logs deploy/platform-idp` and the plane's
`IdentityProviderReady` condition. Usual causes, in order of likelihood:

1. CloudNativePG isn't ready yet — check the CNPG cluster status
   (`kubectl -n identity get cluster platform-db`) first; the plane stays in
   `ProvisioningDatabase` until it is healthy. Migrations run inside
   `haven-idp` at start-up under an advisory lock, so a slow Postgres can delay
   the first successful start.
2. A password mismatch between the Secrets each component reads —
   the controller generates these once and never overwrites them; if you've
   hand-edited `platform-idp-db` or `platform-db-app`, that's the likely culprit.
3. `secret-key` in `platform-idp` was replaced. It encrypts TOTP seeds and
   upstream IdP secrets and is never regenerated; losing it makes those values
   unreadable.

## Ingress returns 404

Check that the Ingress backend points at the Service `platform-idp` (named
`<plane>-idp`) on port 8081 — wiring it to a differently named Service is the
most common ingress misconfiguration.

## OIDC issuer discovery fails

Check, in order: the configured hostname (`spec.hostname`), forwarded headers
(the controller sets `HAVEN_IDP_TRUST_PROXY=1` because `haven-idp` always sits
behind the ingress/gateway), and the TLS certificate's SAN list actually
covering that hostname. The issuer is `https://<hostname>/realms/<realm>`
(HTTP for `profile: dev`).

## Logins are slow

Check the Postgres connection pool size against CloudNativePG's
`max_connections` (size the pool for the replica count), and check for
replication lag on the primary if reads are being served from a replica.

## After a node dies, auth starts returning 5xx

Check your `haven-idp` replica count and PodDisruptionBudget — this is
expected if you're running a single replica, since there is no failover during a
node loss. Replicas above 1 get a PodDisruptionBudget and are spread across
nodes. [`docs/production-overlay.md`](production-overlay.md) covers the
production-shaped configuration that avoids this.

## `ScheduledBackup` is rejected

The CloudNativePG cluster needs an object store or backup plugin
configured — a `ScheduledBackup` with nowhere to write will be rejected
outright rather than silently failing later. See
[`docs/backups.md`](backups.md).

## The Helm chart installs RBAC only

Expected by default: the controller and console are `enabled: false` until you
opt in. Install with `--set controller.enabled=true --set console.enabled=true`;
see [`docs/install-helm.md`](install-helm.md) and
[`docs/deploy-native.md`](deploy-native.md).

## Nothing here matches

Check [`runbook.md`](runbook.md) and [`architecture.md`](architecture.md)
for the full operational and design picture, then
[open an issue](https://github.com/zyvorai/haven/issues) with
`./cli/haven doctor` output and relevant logs (redact secrets).
