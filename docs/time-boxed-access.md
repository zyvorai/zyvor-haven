# Time-boxed access (just-in-time roles)

Give a user a realm role for a limited time, with a written reason, and let it end by itself. Typical
uses: on-call elevation, a contractor who needs `dba` for a migration window, a one-off support
session. Nobody has to remember to take the role away.

A **grant** is a role, a user, a reason and an expiry. While the grant is active the user's tokens carry the
role; when it expires or is revoked, the next refreshed token does not.

## How it works

- The roles claim (`realm_access.roles`) of every access token is computed **when the token is
  issued**: the user's permanent roles plus the roles of their *active* grants. This runs on the
  authorization-code exchange and on every refresh, so a grant takes effect on the user's next token
  and stops with the first refresh after it ends. A grant for a role the user already holds
  permanently changes nothing.
- A refresh token cannot keep a role past its grant: the roles are re-derived on each refresh, they are
  not copied from the old token.
- "Active" means: not revoked, and the current time is strictly before `expiresAt`. At exactly
  `expiresAt` the grant is over. This is checked on every lookup, so an expired grant is never
  effective whether or not the purge job has run.
- If the grant lookup fails while issuing a token, the token gets the permanent roles only (a database
  hiccup never widens access).
- If the store does not support grants, the feature is off: the routes answer `501` and tokens are
  unchanged.

## Policy (per realm)

`GET/PUT /admin/v1/realms/{realm}/grants-policy`

| Field | Default | Meaning |
|---|---|---|
| `maxDurationSeconds` | 28800 (8 h) | longest grant allowed (60 s to 30 days) |
| `requireReason` | `true` | a reason is mandatory |
| `allowedRoles` | `[]` | allowlist of grantable roles; empty means any role except `haven-admin` |

`PUT` takes any subset of the fields. Narrowing the policy does not shorten or revoke grants that
already exist; revoke those explicitly.

## Admin API

```
POST   /admin/v1/realms/{realm}/users/{id}/grants          {role, durationSeconds | expiresAt, reason}
GET    /admin/v1/realms/{realm}/users/{id}/grants?state=active|all
GET    /admin/v1/realms/{realm}/grants?state=active        (whole realm, for review)
DELETE /admin/v1/realms/{realm}/users/{id}/grants/{grantId}[?endSessions=true]
GET/PUT /admin/v1/realms/{realm}/grants-policy
```

Rules: the user must exist and be enabled; the role must exist in the realm and be allowed by the
policy; exactly one of `durationSeconds` and `expiresAt` (RFC3339, whole seconds, must be in the future
and within the policy maximum); a reason of at most 500 characters; at most **20 active grants per
user**. The role `haven-admin` cannot be granted temporarily: the Admin API checks the user's permanent
role, so a temporary one would not work, and we refuse rather than pretend.

### Example: on-call elevation

```sh
# Give alice the "ops" role for 4 hours.
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"role":"ops","durationSeconds":14400,"reason":"on-call, INC-4711"}' \
  https://idp.example.com/admin/v1/realms/acme/users/$ALICE/grants
# -> 201 {"id":"...","role":"ops","expiresAt":"2026-...Z","state":"active",...}

# What is active in the realm right now (access review):
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  'https://idp.example.com/admin/v1/realms/acme/grants?state=active'

# Incident over, take it away now (and sign alice out everywhere):
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://idp.example.com/admin/v1/realms/acme/users/$ALICE/grants/$GRANT?endSessions=true"
```

A realm that only ever wants on-call elevation can set `{"allowedRoles":["ops"],"maxDurationSeconds":43200}`.

From Go, `native.Client` implements the optional `idp.RoleGranter` interface (`CreateRoleGrant`,
`ListRoleGrants`, `RevokeRoleGrant`).

## Audit and retention

| Event | When | Detail |
|---|---|---|
| `ROLE_GRANT_CREATED` | grant created | `grant <role> until <time> by <actor>` |
| `ROLE_GRANT_REVOKED` | grant revoked | `grant <role> until <time> by <actor>` |
| `ROLE_GRANT_EXPIRED` | the purge loop (every 5 minutes) first sees an expired, unrevoked grant | `grant <role> until <time>` |

`UserID` is the user who holds the role. Events are written when the realm logs admin events. The
reason is stored on the grant row (visible through the API) and is **never** copied into an event, a
log line or a metric. Ended grants (expired or revoked) stay in the database for **90 days** for
audit, then the purge loop deletes them. The `EXPIRED` event is emitted once, up to 5 minutes after the
expiry, so do not use it as the moment the access ended: the grant stops being effective at
`expiresAt` regardless.

## Postgres

Migration `0010_role_grants.sql` adds `role_grants` and `grant_policies` (both cascade with the realm).
The 20-grant limit is enforced under a per-user advisory lock, so concurrent requests cannot exceed it.
The in-memory store (used by `haven-idp dev` and tests) implements the same interface.

## Limits (honest list)

- **Access tokens keep the role until they expire.** Revoking a grant, or the grant expiring, does not
  recall a token already issued: it stays valid for at most the realm's access-token lifetime
  (default 5 minutes). The next refresh drops the role. `?endSessions=true` ends the user's SSO
  sessions and their online refresh tokens (offline tokens survive, but they too lose the role on
  refresh), and it still cannot recall an access token in flight. Userinfo and introspection do not report roles, so they cannot disagree.
- **Resource servers that cache tokens or roles** longer than the token lifetime defeat the expiry.
- **No approval workflow.** An administrator creates the grant directly; there is no request, no
  second approver, no break-glass account and no alert on use.
- **Roles only.** There is no automatic expiry of group membership, and no time-boxed *permanent* role
  or group assignment. Groups are not part of this feature.
- **No re-grant limits** beyond 20 concurrent active grants per user, and a realm-wide cap does not
  exist.
- `haven-admin` cannot be granted this way (see above); permanent admin membership remains a normal
  role assignment.
- Roles cannot be deleted in haven-idp today, so a grant never points at a missing role; if role
  deletion is added, the grant lookup must be revisited.
- A grant made in the Admin API takes the new role into **the next token**; a client that never
  refreshes or re-logs in keeps its old token.
- Config as code (`haven-idp plan/apply`) does not manage grants: they are runtime state, not
  configuration.
- The console UI has no screen for grants yet; use the Admin API.
