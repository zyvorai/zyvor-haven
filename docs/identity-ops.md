---
hero:
  eyebrow: IDENTITY OPS
  title: Haven Identity Ops
---

Haven Identity Ops adds three day-2 capabilities on top of the existing Haven console and Haven Guard.

## Time Machine

Time Machine captures a portable realm recovery point containing realm settings, OIDC/SAML clients, users, realm roles, groups, identity providers, user realm-role mappings, and group memberships. It also stores a sanitized Keycloak native partial export so richer client/group/role configuration can be recovered when the connected Keycloak version supports partial import/export.

Client secrets, passwords, and credential payloads are **not** stored in snapshots. Haven recursively removes secret/password/credential fields from Keycloak native exports. Server-generated object IDs are also stripped from the portable projection so fingerprints remain deterministic across clean restores.

### Data directory

The console writes recovery points and rotation metadata under `HAVEN_DATA_DIR`.

- local default: `${TMPDIR}/haven`
- Helm deployment: `/var/lib/haven`
- durable Helm deployment: enable `console.persistence.enabled=true`

Create a recovery point in the console or via API:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"realm":"platform","reason":"before production rollout"}' \
  https://haven.example/api/v1/time-machine/snapshots
```

Haven intentionally refuses in-place restore. A recovery point must be restored to a new realm. Validate the recovery realm, run Haven Guard, then promote through your normal change process.

## Credential Center

Credential Center inventories confidential clients and tracks rotations performed by Haven.

Default rotation target: 90 days. Override with:

```text
HAVEN_CLIENT_SECRET_ROTATION_DAYS=60
```

A rotation returns the newly generated secret exactly through the authenticated API response and marks the response `Cache-Control: no-store`.

When Keycloak client-secret rotation is enabled, the previous secret remains available as the rotated credential. Haven exposes that as an **Overlap** state. Update consumers, verify them, then choose **Retire previous**.

If Keycloak does not expose a rotated credential, Haven reports that overlap is unavailable and the new secret must be propagated immediately.

> Keycloak client-secret rotation is version/feature dependent. Test the overlap workflow on the exact Keycloak release used by your environment before enabling automated production rotation.

## Federation Hub

Federation Hub provides opinionated templates for:

- Microsoft Entra ID
- Google Workspace
- GitHub
- generic OpenID Connect
- SAML 2.0

Provider secrets are sent directly to Keycloak and are not persisted by Haven's Identity Ops store. API responses redact fields whose names contain `secret`, `password`, or `certificate`.

The SAML template enables signature validation and signed authentication requests by default. OIDC templates enable JWKS-based verification where applicable.

## API

### Time Machine

```text
GET    /api/v1/time-machine/snapshots?realm=platform
POST   /api/v1/time-machine/snapshots
GET    /api/v1/time-machine/snapshots/{id}
GET    /api/v1/time-machine/snapshots/{id}/diff
POST   /api/v1/time-machine/snapshots/{id}/restore
DELETE /api/v1/time-machine/snapshots/{id}
```

### Credentials

```text
GET  /api/v1/credentials
POST /api/v1/credentials/{realm}/{client-uuid}/rotate
POST /api/v1/credentials/{realm}/{client-uuid}/retire
```

### Federation

```text
GET    /api/v1/federation/catalog
GET    /api/v1/federation/connections?realm=platform
POST   /api/v1/federation/connections
DELETE /api/v1/federation/connections/{realm}/{alias}
```

## Production notes

1. Use persistent storage for the Haven console if Time Machine history must survive pod recreation.
2. Back up the Haven data volume independently from the Keycloak PostgreSQL backup.
3. Treat recovery snapshots as sensitive IAM configuration even though they do not contain client secrets.
4. Run Haven Guard on a restored realm before promoting it.
5. User password credentials are not recoverable from Time Machine; restored users may require credential reset/re-enrollment. Use Keycloak/PostgreSQL backups for complete database-level disaster recovery. Time Machine is a realm-level identity configuration recovery mechanism, not a replacement for database backups.
