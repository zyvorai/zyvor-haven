# SCIM 2.0 provisioning

haven-idp is a SCIM 2.0 server ([RFC 7643](https://www.rfc-editor.org/rfc/rfc7643),
[RFC 7644](https://www.rfc-editor.org/rfc/rfc7644)). An identity source such as Okta, Microsoft Entra ID or a
script can create, update, disable and delete users and manage group membership in a realm without touching
the Admin API.

```
https://idp.example.com/realms/{realm}/scim/v2
```

It is **off for every realm** until an admin issues that realm's SCIM token. The server answers `501` on a
store that lacks SCIM support (the in-memory dev store and Postgres both have it).

## Authentication: a dedicated SCIM token

SCIM does **not** accept Admin API tokens, and an Admin API client cannot be used as a SCIM client. Each realm
has at most one SCIM bearer token, managed from the Admin API (which is how you control who may issue it):

| Admin API call | Effect |
|---|---|
| `POST /admin/v1/realms/{r}/scim/token` | Issue or **rotate** the token. Body `{"readOnly": true}` is optional. Returns `201 {token, endpoint, readOnly, createdAt}`. The token is shown **this once**; rotating invalidates the old one immediately. |
| `GET /admin/v1/realms/{r}/scim/token` | `{configured, endpoint, readOnly, createdAt, createdBy}`. Never the token. |
| `DELETE /admin/v1/realms/{r}/scim/token` | Revoke. `204`; `404` when none. |

* Format `scim_<43 base64url chars>` (256 bits of randomness), so secret scanners can recognise it.
* Only the SHA-256 of the token is stored; it is compared in constant time. It is never logged and never in an
  audit event or error message. Issue and revoke are audited as `ADMIN_ACTION scim-token issued|revoked`.
* The token is bound to the realm's id, not just its name: a realm deleted and created again under the same
  name does not inherit it. A disabled realm refuses it.
* A **read-only** token may use GET (list, read, discovery) but gets `403` on every write. Use it for
  reconciliation or reporting clients.
* Unknown realm, realm without a token, wrong token and an Admin API token all produce the same `401`.
* Clients put the token in `Authorization: Bearer ...` (RFC 6750). Configure it as "Bearer token" / "API token"
  in the provisioning client with the endpoint above as base URL.

## What is supported

| Feature | Status |
|---|---|
| `GET /ServiceProviderConfig`, `/ResourceTypes[/{id}]`, `/Schemas[/{id}]` | yes (token required) |
| `Users`: `GET` list, `GET /{id}`, `POST`, `PUT`, `PATCH`, `DELETE` | yes |
| `Groups`: `GET` list, `GET /{id}`, `POST`, `PUT`, `PATCH` | yes: **membership** only |
| `Groups` `DELETE`, renaming a group | **no** (`501` / `mutability`): the store has neither |
| Filter | `eq ne co sw ew pr`, `and`, `or`, parentheses; see limits below |
| Pagination | `startIndex` (1-based), `count` (default 50, max 100), `totalResults`, `itemsPerPage` |
| PATCH | `add`, `remove`, `replace`; with or without `path`; case-insensitive `op` |
| ETag / `If-Match` / `If-None-Match` | yes, weak ETags (`meta.version`) on every resource |
| **Bulk** (`/Bulk`) | **not supported**: `bulk.supported` is `false` and `/Bulk` answers `501` |
| Sorting | not supported (`sort.supported` is `false`); lists come back ordered by userName / group path |
| Password sync | **no**: `changePassword.supported` is `false`; a `password` attribute is rejected with `400 mutability` |
| `attributes=` projection | not supported (ignored); `excludedAttributes=members` is honoured on `/Groups` |
| Enterprise user extension, `roles`, `addresses`, `phoneNumbers`, ... | not stored; ignored in POST/PUT, rejected in PATCH (see below) |

### User attributes

| SCIM | haven-idp | Notes |
|---|---|---|
| `userName` | username | unique per realm, case-insensitive; `409 uniqueness` on conflict |
| `externalId` | kept in a SCIM-owned table | unique per realm; filterable; `eq` is an index lookup |
| `name.givenName`, `name.familyName` | first / last name | `name.formatted` and `displayName` are derived and read-only |
| `emails` | email | one address is stored (primary, else first) and returned as the primary `work` address. `emails[type eq "work"].value` is accepted as a PATCH path |
| `active` | enabled | `false` disables the account **and ends its sessions**; accepts `"True"`/`"False"` strings too |
| `groups` | group membership | read-only; change it through `/Groups` |

An address that changes is **unverified** until its owner confirms it (SCIM can never assert verification), and,
if email is configured, a verification mail is sent exactly as for an Admin API change. A user created through
SCIM has no password: they sign in through federation or use the password-reset email.

`DELETE /Users/{id}` hard-deletes the user (RFC 7644 semantics). To keep the account, send `active=false`.

### Groups

A group resource has `displayName` (immutable, no `/`) and `members` (users only; nested groups are not
supported). Members are the realm's group membership, so a change here is the same as `PUT
/users/{id}/groups/{gid}` in the Admin API. Adding an unknown (or hidden) user is `400 invalidValue`. A group
PATCH changes several users one at a time and is not transactional: if the store fails midway, some members
changed (the response is an error; re-read and retry).

### Filter

Supported attributes: Users `id userName externalId active displayName name.givenName name.familyName emails
emails.value`; Groups `id displayName members members.value`. String comparison is case-insensitive except for
`id`, `externalId` and `members.value`. Values are quoted strings, `true`, `false` or `null`.

Rejected with `400 invalidFilter`: `not(...)`, `gt ge lt le`, value paths (`emails[type eq "work"]`), unknown
attributes, malformed input. **Limits**: 1024 characters, 16 comparison terms, 4 levels of parentheses.

A filter that is exactly one `userName eq`, `id eq` or `externalId eq` is an index lookup. Everything else
(and an unfiltered list) walks the realm's users in pages of 500 and stops with `400 tooMany` beyond
**20,000 users** in the realm; use an indexed lookup for realms that large.

## Security properties

* **No enumeration beyond the token.** Anything a token holder reads they can also read with the (more
  privileged) Admin API, but SCIM is deliberately narrower: users holding the `haven-admin` role and
  `service-account-*` users are invisible to SCIM (absent from lists and filters, `404` on read, update and
  delete), a `service-account-` user name cannot be created, and roles are never exposed or writable, so a SCIM
  token cannot disable, delete or take over an administrator or grant itself a role. (`POST` of a user name that
  collides with a hidden user answers `409`, which reveals only that the name exists.)
* **Bounded work.** Bodies are capped at 256 KiB (`413`), filters at the limits above, PATCH at 100
  operations, group requests at 1000 members, `count` at 100, `startIndex` at 1,000,000, and a list at 20,000
  scanned users.
* **Rate limits** (shared across replicas through the store, keyed by hashed client address and realm): 600
  requests per minute, and 20 failed authentications per minute (`429` with `Retry-After`). A limiter store
  error fails closed (`503`). The client address is the TCP peer; behind a proxy that is the proxy.
* **Same rules as the Admin API.** Users and groups are validated by the Admin API's own code (`applyUser`,
  `validGroup`), written to the same stores, and audited like Admin API changes (`ADMIN_CREATE|UPDATE|DELETE`,
  actor `scim:{realm}`) when the realm logs admin events. Disabling a user and deleting a user end sessions and
  drop federation links as the Admin API does.
* **Guard.** The Guard admission gate (see [guard-gate.md](guard-gate.md)) scores realm and client writes. SCIM
  writes neither, so the gate does not apply to it, and SCIM cannot reach a realm or client setting.
* **Concurrency.** Writes in a realm are serialised inside one process, so an `If-Match` check and its update
  are one step. Across replicas, or against a concurrent Admin API edit, the window between check and update
  is not closed (there is no row version in the store): `If-Match` protects against stale clients, not against
  two writers racing within milliseconds.
* Responses are `Cache-Control: no-store`, `Content-Type: application/scim+json`, `nosniff`.

## Setting up a client

1. `POST /admin/v1/realms/{r}/scim/token` as a realm admin; copy `token` into the provisioning client.
2. Base URL `https://idp.example.com/realms/{r}/scim/v2`; authentication "HTTP header / Bearer".
3. Map `userName`, `givenName`, `familyName`, `email`, `active`, `externalId`. Do not map a password. Turn
   on "push groups" if you want memberships; create the group first from the client (or use existing ones).
4. Test: `GET /Users?filter=userName eq "someone"`.

## Not yet

* Bulk, sorting, `attributes=` projection, `not` and comparison operators in filters, filter on value paths.
* Group deletion and rename (needs store support), nested groups.
* Password sync (deliberately), `roles`, enterprise extension, multiple emails, phone numbers, addresses.
* Outbound provisioning (haven-idp pushing to other SCIM servers) and SCIM against the Keycloak backend.
* Separate scopes per token (one token per realm, read-only or read-write), token expiry.
* A row version in the store for cross-replica `If-Match`.
* Dev-store persistence (`dev-persist`) does not yet include SCIM tokens or external ids; issue the token again
  after a restart.
