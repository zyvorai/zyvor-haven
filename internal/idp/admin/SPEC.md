# haven-idp Admin API v1 (contract)

Served by `haven-idp` under `/admin/v1`. Consumed by `internal/idp/native`
(an `idp.Provider`). JSON bodies reuse the wire types in `internal/idp/types.go`
(`idp.Realm`, `idp.Client`, ...), so existing Haven handlers, Guard and Time
Machine keep working. Both sides implement exactly this document.

## Authentication
`Authorization: Bearer <access token>` issued by haven-idp for the **admin
realm** (`HAVEN_IDP_ADMIN_REALM`, default = `HAVEN_IDP_BOOTSTRAP_REALM`).
Verify with `core.Signer.Verify(adminRealm, token)`, then require `iss` ==
`<BaseURL>/realms/<adminRealm>`, unexpired, `typ` == "Bearer" (not an ID token),
and one of:
  * a service-account token: `sub` == `"service-account-"+client_id` and
    `client_id` is in the configured admin client list (default `haven-admin`),
    which must be a confidential `ServiceAccount` client in the admin realm
    (re-check in the Store that the client exists, is enabled and is such a
    client; do not trust the token alone); or
  * `realm_access.roles` contains `haven-admin` (a user holding that realm role).
401 + `WWW-Authenticate: Bearer` when missing/invalid; 403 when valid but not
admin. Compare nothing secret with `==`. All responses `Cache-Control: no-store`.
Request bodies limited to 1 MiB (`http.MaxBytesReader`), unknown JSON fields are
rejected with 400. Never include secrets/hashes in responses or logs.

## Errors
`{"error":"<message>"}` with 400 invalid input, 401, 403, 404 not found, 409
conflict (duplicate), 501 unsupported (`idp.ErrUnsupported`), 500 internal (no
internal detail in the message). `native` maps 404->`idp.ErrNotFound` via
`*idp.StatusError` (status/body preserved), 409->`ErrConflict`.

## Routes (`{r}` realm name, `{id}` opaque id)
Create calls return `201` with `Location: <resource url>` and body `{"id":"..."}`.
Updates/deletes return `204`. Names are case-insensitive unique where the Store says so.

| Method & path | Body / result |
|---|---|
| GET `/status` | `idp.Status` (`connected:true`, `version`, `realmCount`) |
| GET, POST `/realms` | list `[]idp.Realm` / create `idp.Realm` |
| GET, PUT, DELETE `/realms/{r}` | `idp.Realm`; PUT replaces mutable fields |
| GET, POST `/realms/{r}/clients` | `[]idp.Client` (optional `?clientId=` exact-match filter) / create `idp.Client` (secret generated for confidential clients, returned ONCE as `{"id","secret"}`) |
| GET, PUT, DELETE `/realms/{r}/clients/{id}` | `idp.Client` (never contains `secret`) |
| POST `/realms/{r}/clients/{id}/secret` | regenerate; returns `idp.ClientSecret{type:"secret",value}` once |
| GET `/realms/{r}/clients/{id}/secret` | 501 (only a hash is stored) |
| GET, DELETE `/realms/{r}/clients/{id}/secret/rotated` | 404 (no overlap support in v1) |
| GET `/realms/{r}/client-scopes` | fixed `[openid, profile, email, offline_access]` |
| GET `/realms/{r}/users?search=&first=&max=` | `[]idp.User` (max default 100, cap 1000) |
| POST `/realms/{r}/users` | create `idp.User` |
| POST `/realms/{r}/users/import` | bulk import `{"users":[idp.ImportUser]}` (see "User import"); 200 `idp.ImportResult` |
| GET, PUT, DELETE `/realms/{r}/users/{id}` | `idp.User`. PUT email rules: when the email changes (trimmed, case-insensitive compare; a case-only change is not a change) `emailVerified` becomes false unless the body explicitly contains `emailVerified:true` (admins may assert it); clearing the email also sets false. On any change all outstanding verify and reset links of the user are deleted (they were bound to the old address; this also resets the per-hour rate-limit count). If the result is unverified, the user is enabled and email is configured, a verification link is sent to the NEW address only, best effort in the background (30s context, errors logged, never failing the update); nothing is sent when email is not configured or the email was cleared. `VERIFY_EMAIL` is not added to `requiredActions` automatically. POST create is unchanged: an explicit `emailVerified` is honoured and no mail is sent (use `send-verify-email`). `users/import` is unchanged. |
| PUT `/realms/{r}/users/{id}/password` | `idp.PasswordReset`; enforce realm password policy via `password.CheckPolicy`; `temporary:true` adds pending action `UPDATE_PASSWORD`; resets lockout |
| POST `/realms/{r}/users/{id}/send-verify-email`, `.../send-reset-email` | emails a single-use link to the address on file (never returned); 204; 409 if email is not configured, 400 no address / disabled user, 429 after 3 per user per hour, 502 on delivery failure |
| GET `/realms/{r}/sessions?userId=&max=` | `[]idp.Session` (`id,userId,username,ipAddress,userAgent,start,lastAccess,expires,clients`), live sessions only (not past the absolute or idle expiry, judged by the config clock), newest first; `max` default 100, cap 500, 400 on a bad `max`; `username` empty if the user is gone; never contains the cookie hash; 404 unknown realm |
| GET `/realms/{r}/users/{id}/sessions` | same list for one user; `max` as above; 404 unknown user |
| DELETE `/realms/{r}/sessions/{sid}` | ends the session via `Config.Sessions.End`: row removed, its non-offline refresh tokens revoked, clients notified (back-channel logout); 204; 404 when unknown or already ended (no second notification). Audit `ADMIN_ACTION` detail `session <sid>` |
| DELETE `/realms/{r}/users/{id}/sessions` | `Config.Sessions.EndUser`; 200 `{"ended":n}` (0 when none); 404 unknown user. Audit `ADMIN_ACTION` detail `user-sessions <username>` |
| GET, POST `/realms/{r}/users/{id}/roles` | `idp.RoleMappings` / `[]idp.Role` (match by name; unknown role -> 400) |
| GET `/realms/{r}/users/{id}/groups` | `[]idp.Group` |
| PUT `/realms/{r}/users/{id}/groups/{gid}` | join |
| GET, POST `/realms/{r}/roles` | `[]idp.Role` / create |
| GET, POST `/realms/{r}/groups` | `[]idp.Group` / create (`path` = "/"+name) |
| GET, POST `/realms/{r}/identity-providers` | GET returns `[]`; POST 501 (federation is not implemented in v1) |
| DELETE `/realms/{r}/identity-providers/{alias}` | 404 |
| GET `/realms/{r}/events?max=50` | `[]idp.AdminEvent` (from `core.Event` with Type prefix `ADMIN_`, newest first) |
| GET `/realms/{r}/keys` | `[]idp.Key` (`providerId` "ecdsa-generated", `type` "EC", `status` ACTIVE/PASSIVE, `kid`) |
| GET `/realms/{r}/export` | native export (below) |
| POST `/realms/{r}/import` | native export; idempotent, conflicts are skipped, returns `{"imported":{"roles":n,"groups":n,"clients":n}}` |

## Session side effects on users
Through `Config.Sessions` (best effort, errors logged, never failing the call): PUT user
with `enabled` going true to false ends all of the user's sessions; a successful
`PUT .../password` ends them too; DELETE user ends them BEFORE the user is deleted so
clients are notified. Optional Go interface `idp.SessionManager` (`ListSessions`,
`EndSession`, `EndUserSessions`) is implemented by `native.Client`, not by `idp.Provider`.

## Mapping rules (`core` <-> `idp` wire)
* Realm: `Realm`=Name; `RegistrationAllowed`=SelfRegistration; `VerifyEmail`=
  EmailVerificationRequired; `BruteForceProtected`; hardening fields are always
  populated on GET: `SSLRequired`=TransportSecurity, `PasswordPolicy`,
  `AccessTokenLifespan`/`SSOSessionIdleTimeout` in seconds, `EventsEnabled`=
  AuthEventsLogged, `AdminEventsEnabled`=AdminEventsLogged,
  `RevokeRefreshToken`=RefreshTokenRotation. On create, nil hardening fields get
  secure defaults (external TLS, `length(12)`, 300s access, 1800s idle, rotation
  on, brute-force on, events on). Realm names must match `^[a-z0-9][a-z0-9._-]{0,62}$`.
* Client: `PublicClient`=Public; `StandardFlowEnabled`=AuthCodeFlow;
  `DirectAccessGrantsEnabled`=PasswordFlow (rejected with 400 if true: not
  implemented); `ImplicitFlowEnabled` true -> 400; `ServiceAccountsEnabled`=
  ServiceAccount; `WebOrigins`=Origins; `Protocol` always "openid-connect";
  `Attributes["pkce.code.challenge.method"]`="S256" iff RequirePKCE (and
  RequirePKCE true on write when that attribute is "S256"). Public clients
  default RequirePKCE=true. Secret storage: `oidc.HashSecret`.
  `BackchannelLogoutURL`=BackchannelLogoutURI (`backchannelLogoutUrl`, omitted
  when empty). Validated on create and update by `idp.ValidateLogoutURI`
  (<= 2048 chars, no control chars, no userinfo/fragment, host required, https;
  http only for localhost/loopback) -> 400 `invalid backchannelLogoutUrl: ...`.
  Client PUT is a full replace, so omitting the key clears it.
* User: straightforward; `RequiredActions`=PendingActions. Passwords are never
  accepted on user create/update bodies (use the password route).
* Group paths are "/name". Role/group membership is by name/path inside core.User.

## User import
`POST /realms/{r}/users/import` takes up to 1000 users and 8 MiB (more: 413; unknown
JSON fields, including any plaintext `password`: 400). Users are processed sequentially;
one bad user never fails the batch. Per user: same username/email/name rules as user
create; `passwordHash` (optional) must pass `password.ValidateEncoded` and is stored
as-is (never returned or logged); every role name and group path must exist;
`requiredActions` are filtered to {UPDATE_PASSWORD, VERIFY_EMAIL}. An existing
username (case-insensitive) is counted in `skipped` and never modified, its password
included. A username repeated inside one request is an error "duplicate in request".
Store failures are reported generically. Response `idp.ImportResult{created,skipped,errors}`:
`errors` is capped at 100 entries (failed users beyond the cap are not in the response,
only in the admin event's failed count). Admin event `ADMIN_IMPORT` detail is
`users: created=N skipped=M failed=K` (counts only). Metrics:
`AdminOp(realm,"user","action",ok)`.

## Native export format
`{"version":1,"realm":"<r>","roles":[idp.Role],"groups":[idp.Group],"clients":[idp.Client without secrets]}`.
`idp.Provider.PartialExport` returns this as `json.RawMessage`; `PartialImport`
accepts it.

## Admin events
Every mutating call appends `core.Event{Type:"ADMIN_<CREATE|UPDATE|DELETE|ACTION>",
Detail:"<resource> <name-or-id>"}` to the target realm when `Realm.AdminEventsLogged`
(no payloads, no secrets).

## Native Provider (`internal/idp/native`)
`native.New(native.Config{BaseURL, Realm, ClientID, ClientSecret string, HTTP *http.Client}) *Client`
implements `idp.Provider`. It fetches an access token with `client_credentials`
from `<BaseURL>/realms/<Realm>/protocol/openid-connect/token` (HTTP Basic client
auth), caches it until 30s before expiry (mutex-protected, single-flight), retries
once with a fresh token on 401. `Status` also calls GET `/status`. Unsupported
operations return `*idp.StatusError` 501. `BootstrapRealm(name)` = create the realm
if missing (409 ignored) + `EnsureHavenConsoleClient`. `EnsureHavenConsoleClient`
mirrors `internal/keycloak/ensure.go` semantics (merge redirect URIs, public
client, PKCE S256). `EnsureUserPassword` creates the user if missing, then sets
the password via the password route. `BaseURL()`/`User()` mirror the Keycloak client.

## Once-only secrets (`idp.SecretCreator`)
`native.Client` also implements `CreateClientWithSecret(ctx, realm, idp.Client) (id, secret, err)`
because the server stores only a hash and `GET .../secret` is 501. The console's
create-client handler uses it for confidential clients and returns
`201 {"id","secret"}` with `Cache-Control: no-store`; the UI must show the secret
once. Providers that can read secrets back (Keycloak) keep the old 201-with-no-body response.

## Guard admission gate (`guard.go`, docs/guard-gate.md)
Realm create/update and client create/update are scored by Haven Guard before
they are applied (`HAVEN_IDP_GUARD=off|warn|enforce`, default warn;
`_THRESHOLD`, `_WAIVERS`, `_NO_OVERRIDE`). Only findings that are new (present
after, not before) at or above the threshold, after waivers, count.
  * warn: applied; response header `X-Haven-Guard: findings=N max=SEV`; event `GUARD_WARN`.
  * enforce: `422 {"error":"guard_blocked","findings":[{ruleId,severity,title,resource,detail,fix}]}`,
    event `GUARD_BLOCK`; `X-Haven-Guard-Override: <10..300 chars>` applies the write and records
    `GUARD_OVERRIDE` (caller, rule ids, reason); `400 guard_override_invalid`, `403 guard_override_denied`
    (service accounts when NO_OVERRIDE=1). Evaluation failure: `500 guard_unavailable` (override allowed).
  * `POST /realms/{r}/guard/evaluate` `{"kind":"realm"|"client","body":<write body>}` -> `idp.GuardVerdict`, applies nothing.
  * `GET /realms/{r}/guard` -> `{realm,mode,threshold,score,grade,findings,waived,expiredWaivers}`.
## Time-boxed access (role grants)
Optional feature: needs a store implementing `core.GrantStore` (memstore and pgstore do,
migration 0010); otherwise every route below answers `501 {"error":"time-boxed access is not
available on this store"}`. All routes need the admin token like every other route (401/403).
Wire types: `idp.RoleGrant`, `idp.RoleGrantRequest`.

| Method + path | Body / query | Success |
|---|---|---|
| `POST /realms/{r}/users/{id}/grants` | `{role, expiresAt (RFC3339) XOR durationSeconds, reason}` | `201 idp.RoleGrant` |
| `GET /realms/{r}/users/{id}/grants?state=active\|all&max=` | default `state=active`, `max` 1..1000 (default 200) | `200 [idp.RoleGrant]` newest first |
| `GET /realms/{r}/grants?state=active\|all&max=` | realm-wide, for review | `200 [idp.RoleGrant]` |
| `DELETE /realms/{r}/users/{id}/grants/{gid}?endSessions=true\|false` | | `204`; `endSessions=true` also ends the user's SSO sessions |
| `GET /realms/{r}/grants-policy` | | `200 {maxDurationSeconds, requireReason, allowedRoles}` (defaults 28800, true, []) |
| `PUT /realms/{r}/grants-policy` | any subset of the three fields; omitted keep their value | `200` the stored policy |

`idp.RoleGrant`: `{id, userId, role, grantedBy, reason, createdAt, expiresAt, revokedAt?, revokedBy?, state}`;
`state` is `active`, `expired` or `revoked` at the time of the call. Times are truncated to whole seconds.

Create validation (all `400` unless noted): user exists (404) and is enabled; `role` is an existing
realm role, is allowed by the policy's `allowedRoles` (empty = any) and is not `haven-admin` (the
Admin API checks the permanent role, so a temporary one would not work); exactly one of
`expiresAt` / `durationSeconds`; duration > 0; `expiresAt` strictly after now; expiry at most
`maxDurationSeconds` from now (equal is allowed); `reason` trimmed, at most 500 characters, no control
characters, non-empty when `requireReason`; at most 20 active grants per user (`429`, atomic in the
store). Policy `PUT`: `maxDurationSeconds` 60..2592000; `allowedRoles` must be existing roles other than
`haven-admin`. Narrowing a policy never touches grants that exist. Revoking a grant that already
ended (expired or revoked) is `409`; an unknown grant, or one of another user or realm, is `404`.

Effect: `realm_access.roles` of every token issued by the OIDC provider (`issue`) is the user's
permanent roles plus the roles of their active grants at issue time. Access tokens already issued keep
the role until they expire.

Events (when `Realm.AdminEventsLogged`): `ROLE_GRANT_CREATED`, `ROLE_GRANT_REVOKED` (appended by the API,
`UserID` = the user, `Detail` = `grant <role> until <RFC3339> by <actor>`) and `ROLE_GRANT_EXPIRED` (appended by the
purge loop once per expired grant, `Detail` = `grant <role> until <RFC3339>`). The reason text is never
put in an event. Obs: `AdminOp(realm,"role-grant","create"|"delete",ok)`, `AdminOp(realm,"grants-policy","update",ok)`.
## Device authorization grant (RFC 8628)
* Client: `DeviceFlowEnabled`=`core.Client.DeviceFlow` (`deviceFlowEnabled`, omitted
  when false). Default false; opt-in per client. Client PUT is a full replace, so
  omitting the key switches the flow off (like `redirectUris`). Create/update with
  `serviceAccountsEnabled: true` and `deviceFlowEnabled: true` -> 400
  `deviceFlowEnabled cannot be combined with serviceAccountsEnabled`.
* Config as code: `clients[].deviceFlowEnabled` (same validation).
* Protocol endpoints and behaviour: `docs/device-flow.md`. There is no Admin API for
  pending device requests.
