---
hero:
  eyebrow: TROUBLESHOOTING
  title: Troubleshooting
---

Real operational issues, with the documented fix. For the condensed
version, see [`runbook.md`](runbook.md)'s "Failure cheatsheet" — this page
expands on it. **First step in any incident: `./cli/haven doctor`.**

## Keycloak CrashLoopBackOff: "Unable to migrate database"

Almost always one of three causes, in order of likelihood:

1. CloudNativePG isn't ready yet — check the CNPG cluster status before
   Keycloak; Haven starts Postgres and Keycloak as one lifecycle, but a
   slow Postgres bootstrap can still race Keycloak's first connection.
2. A password mismatch between the Secrets each component reads —
   Haven generates and references these automatically; if you've
   hand-edited a Secret, that's the likely culprit.
3. TLS verification failing without `platform-db-ca` present — confirm the
   CA secret Haven expects is actually mounted.

## Ingress returns 404

Check the service name — it's `<cr-name>-service`, not `platform-service`.
This is the single most common ingress misconfiguration per the runbook's
own cheatsheet.

## OIDC issuer discovery fails

Check, in order: the configured hostname, `proxy.headers` (if behind a
reverse proxy/ingress that needs to forward the original host), and the
TLS certificate's SAN list actually covering that hostname.

## Logins are slow

Check the Postgres connection pool size against CloudNativePG's
`max_connections`, and check for replication lag on the primary if reads
are being served from a replica.

## After a node dies, auth starts returning 5xx

Check your Keycloak instance count and PodDisruptionBudget — this is
expected if you're running fewer than 2 Keycloak instances with no PDB,
since a single-instance deployment has no failover during a node loss.
[`docs/production-overlay.md`](production-overlay.md) covers the
production-shaped configuration that avoids this.

## `ScheduledBackup` is rejected

The CloudNativePG cluster needs an object store or backup plugin
configured — a `ScheduledBackup` with nowhere to write will be rejected
outright rather than silently failing later. See
[`docs/backups.md`](backups.md).

## The Helm chart doesn't install a working controller/console

Expected today — per [`docs/roadmap.md`](roadmap.md), the current
repository is "v0": the Helm chart "installs RBAC only
(controller/console images unpublished)." Use the compose overlay path
(`deploy/overlays/{dev,prod}`) instead until v1's full reconcile loop
ships.

## Nothing here matches

Check [`runbook.md`](runbook.md) and [`architecture.md`](architecture.md)
for the full operational and design picture, then
[open an issue](https://github.com/zyvorai/haven/issues) with
`./cli/haven doctor` output and relevant logs (redact secrets).
