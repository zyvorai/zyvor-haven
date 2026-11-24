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
| `/realms/{r}/identity-providers[/{alias}]`, `/realms/{r}/users/{id}/federated-identities[/{alias}]` | upstream OIDC identity brokering: see "Identity providers" at the end of this file (a store without federation answers `[]` / 501) |
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
## Dynamic client registration (RFC 7591/7592)
Needs a store with `core.DCRStore`; without it these routes answer 501
`dynamic client registration is not available on this store`. The registration
endpoint itself is served by the OIDC provider
(`POST /realms/{realm}/clients-registrations/openid-connect`), see
docs/dynamic-client-registration.md.

- `POST /realms/{r}/initial-access-tokens` body `{expirationSeconds?, count?, note?}`
  (defaults 86400 and 1; max 2592000 s and 1000 uses; note at most 255 chars, no
  control characters; unknown fields rejected). 201 `{id, token, count, expiresAt, note}`.
  `token` (`hiat_...`) is shown exactly once; only its sha256 is stored. Audit
  `ADMIN_CREATE initial-access-token <id>`.
- `GET /realms/{r}/initial-access-tokens` -> `[{id, note, createdAt, expiresAt, count, remaining}]`.
  Never the token or its hash. Expired and exhausted tokens stay listed until deleted.
- `DELETE /realms/{r}/initial-access-tokens/{id}` -> 204, or 404. The token then fails
  exactly like an unknown one.
- `GET /realms/{r}/registration-policy` -> `{maxClients, allowedGrantTypes}` (defaults 100
  and all of authorization_code, refresh_token, client_credentials when none was set).
- `PUT /realms/{r}/registration-policy` body `{maxClients (required, 0..100000),
  allowedGrantTypes?}` -> 200 with the stored policy. `maxClients: 0` switches registration
  off for the realm. `allowedGrantTypes` must be a non-empty subset of the three grants, each
  once; omitted = all three.
- `GET /realms/{r}/registered-clients` -> `[{id, clientId, name, enabled, createdVia:"dcr",
  initialTokenId, createdAt}]`: clients created through the registration endpoint that still
  exist. Admin-created clients are never listed.
## MFA (TOTP) routes (`admin/mfa.go`, docs/mfa-totp.md)
Needs `HAVEN_IDP_SECRET_KEY` (`Config.SecretBox`) and a store implementing
`core.MFAStore`. Without the key every route below answers
`409 {"error":"HAVEN_IDP_SECRET_KEY is not set: TOTP is disabled ..."}`; a store
without support answers 501. Neither a seed nor a recovery code is ever returned.

| Method & path | Body / result |
|---|---|
| GET `/realms/{r}/users/{id}/mfa` | `{"totpEnrolled":bool,"totpPending":bool,"recoveryCodesRemaining":int}` (`totpPending`: setup started, not confirmed; the remaining count is 0 unless enrolled). 404 unknown user. |
| DELETE `/realms/{r}/users/{id}/mfa` | `204`. Deletes the credential and every recovery code (lost device) and ends all of the user's SSO sessions (`Sessions.EndUser`). Idempotent. Audit: `ADMIN_ACTION "user-mfa <username>"` and, when the realm logs auth events, `TOTP_RESET` (user id, detail `admin`). Metrics `AdminOp(realm,"user-mfa","delete",ok)`. |
| GET `/realms/{r}/mfa-policy` | `{"requireMfa":bool}` (default false) |
| PUT `/realms/{r}/mfa-policy` | body `{"requireMfa":bool}` (required, unknown fields rejected); returns the stored policy. When true, a user without a confirmed TOTP credential must enroll during login. Audit `ADMIN_UPDATE "mfa-policy <realm>"`. Metrics `AdminOp(realm,"mfa-policy","update",ok)`. |

Auth events written by the login/account flows (never contain codes): `TOTP_ENROLLED`
(detail `login`|`account`), `TOTP_DISABLED`, `RECOVERY_USED`, `RECOVERY_REGENERATED`,
`MFA_FAILED` (detail `invalid_code` or `reauth`).
## Passkeys (WebAuthn)
Needs a store implementing `core.PasskeyStore`; otherwise every route answers 501.
- `GET /realms/{r}/users/{id}/passkeys` -> 200 `[{"id","name","createdAt","lastUsedAt"?,"backupEligible","backupState","transports":[],"aaguid","signCount"}]`
  (empty array when none; the public key is never returned). 404 for an unknown user.
- `DELETE /realms/{r}/users/{id}/passkeys/{credId}` -> 204; 404 when the credential does
  not belong to that user. Does not end sessions. Ignores the realm's passkey policy
  (admins can always remove). Audit `ADMIN_DELETE passkey <username>` (no credential id).
- `GET /realms/{r}/passkey-policy` -> `{"requirePasskeys":bool}`;
  `PUT` with the same body (unknown fields -> 400). When true, the account page refuses to
  remove a user's last passkey. Audit `ADMIN_UPDATE passkey-policy <realm>`.
Metrics: `AdminOp(realm,"passkey","delete",ok)` and `AdminOp(realm,"passkey-policy","update",ok)`.
## Identity providers (identity brokering, `internal/idp/admin/federation.go`)
Upstream OpenID Connect providers ("Sign in with ..."): Google, Microsoft Entra ID and any
generic OIDC provider. Authorization code + PKCE (S256) + nonce only. GitHub (not OIDC) and
SAML are not supported: `providerId` other than `oidc`, `google`, `microsoft` is a 400.
Needs the store's `core.FedStore` (memstore and pgstore have it; migration 0011); without
it GET list answers `[]`, POST 501, other routes 404.

| Route | Behaviour |
|---|---|
| GET `/realms/{r}/identity-providers` | `[]idp.IdentityProvider`, by alias |
| POST `/realms/{r}/identity-providers` | create; 201 `{"alias"}` + Location; 409 duplicate alias; 400 invalid; at most 50 per realm |
| GET `/realms/{r}/identity-providers/{alias}` | one provider; 404 |
| PUT `/realms/{r}/identity-providers/{alias}` | replace (full body, as GET returns it); 204; the alias cannot change |
| DELETE `/realms/{r}/identity-providers/{alias}` | 204; removes the provider and its federated identities, never the users |
| GET `/realms/{r}/users/{id}/federated-identities` | `[{identityProvider (alias), userId (upstream sub), userName "", createdAt, lastLoginAt (epoch ms)}]` |
| DELETE `/realms/{r}/users/{id}/federated-identities/{alias}` | unlink; 204; 404 when not linked |

Mutations audit as `ADMIN_<CREATE|UPDATE|DELETE>` with detail `identity-provider <alias>` /
`federated-identity <username> <alias>` (no config, no secrets). Deleting a user removes its links
(pg: foreign key cascade; the delete handler also calls `DeleteFedLinksForUser` for other stores).

Wire shape: `idp.IdentityProvider{alias, displayName, providerId, enabled, trustEmail, config}`.
`storeToken:true` and `firstBrokerLoginFlowAlias` are rejected (upstream tokens are never stored).
`alias` matches `[a-z0-9-]{1,32}`; `displayName` is at most 64 characters (defaults to "Google",
"Microsoft" or the alias). `config` keys (anything else is a 400; every value is a string):

| key | meaning |
|---|---|
| `issuer` | generic: the exact `iss` of the provider (https, no userinfo/query/fragment; http only for loopback when the server runs with AllowPrivate = dev). Fixed for google/microsoft (accepted if equal, else 400) |
| `discoveryUrl` | generic: discovery document URL. Default `{issuer}/.well-known/openid-configuration`. Without `issuer` it must end in `/.well-known/openid-configuration` (the issuer is derived). The discovery `issuer` must equal the issuer exactly or login fails |
| `clientId` | required |
| `clientSecret` | **write-only**. Stored only via secretbox bound to `idp|{realm}|{alias}`. GET/list show `"clientSecret":"**********"` when one is stored and never the value; a PUT that sends the mask (or omits the key) keeps the stored secret; any other value replaces it. Without `HAVEN_IDP_SECRET_KEY` a create/update carrying a secret answers 409 `HAVEN_IDP_SECRET_KEY is not set: ...`; GET/list still work. A provider without a secret is a public PKCE client |
| `scopes` | space separated, must include `openid`; default `openid email profile` |
| `tenant` | microsoft only: a tenant id (GUID), or `common` (default), `organizations`, `consumers` = multi-tenant: the ID token issuer is then matched against the token's `tid` claim (`https://login.microsoftonline.com/{tid}/v2.0`), the link subject becomes `{tid}/{sub}`, and `linkExistingByEmail=true` is refused |
| `hostedDomain` | google only: sends `hd` and requires the ID token's `hd` to equal it |
| `usernameClaim` | claim for the new user's username; default `preferred_username` (falls back to the email local part) |
| `linkExistingByEmail` | `"true"`/`"false"` (default false). See `docs/federation.md`: account-takeover risk |
| `autoCreateUsers` | `"true"`/`"false"` (default false): create a local user on first login |
| `roleMappings` | compact JSON string `[{"claim":"groups","value":"eng","roles":["developer"]}]`; a claim is a top-level name or a dotted path, an array claim matches when it contains the value |
| `roleSyncMode` | `import` (default: only adds roles) or `sync` (also removes roles federation itself added earlier and the mappings no longer grant; never touches roles an administrator assigned) |

Responses always show every config key explicitly (defaults filled in) plus `issuer` for the presets.

### Login flow (`internal/idp/oidc/federation.go`)
* The login page lists `Continue with <displayName>` for each enabled provider.
* `GET /realms/{r}/broker/{alias}/login?<original /auth query>` re-validates the authorization
  request (client, exact redirect URI, PKCE, state), stores a single-use login state row
  (`core.FedLoginState`: sha256 of the `state`, sha256 of the browser-binding cookie `haven_fed`,
  nonce, the original query; 10 minutes) and redirects to the upstream authorization endpoint
  (PKCE S256 with a verifier derived from the server CSRF key and the state, so nothing secret is
  stored; nonce). Rate limit: 30 starts per 5 minutes per IP (fail closed).
* `GET /realms/{r}/broker/{alias}/endpoint?code&state` consumes the state (any outcome), checks the
  cookie, exchanges the code (`client_secret_basic`, or `client_secret_post` when only that is
  advertised), validates the ID token (alg RS256/ES256/PS256 only, JWKS `kid` selection with one
  rate-limited refresh, iss, aud/azp, exp/iat/nbf with 60 s skew, nonce), resolves the user and
  ends in the same `completeLogin` as a password login (event `LOGIN`, detail `federated:{alias}`).
  Local MFA steps are not run (`federatedRunsAuthSteps`).
* Failures render a generic page; `LOGIN_ERROR` events carry `federated:{alias}:{kind}` with a fixed
  kind (`unknown_state`, `browser_mismatch`, `bad_nonce`, `bad_signature`, `blocked_address`, ...).

Tables (pg migration `0011_federation.sql`): `fed_providers`, `fed_links (realm, alias, subject)
unique`, `fed_login_states`.

## Login fallback and step-up (migration `0013`)
Needs a store implementing `core.StepUpStore`; otherwise every route answers 501. Docs: `docs/login-fallback-and-stepup.md`.
| Route | Notes |
|---|---|
| GET `/realms/{r}/stepup-policy` | `{"allowFallback","enabled","enforce","onNewDevice","onIpChange":bool,"idleAfterSeconds":int,"onMaxAge":bool,"sensitiveScopes":[string],"sensitiveAuthMaxAgeSeconds":int}`; a realm never configured has everything off/0/`[]`. |
| PUT `/realms/{r}/stepup-policy` | Replaces the whole policy (missing fields = false/0/`[]`; unknown fields rejected). 400: seconds outside 0..one year, more than 20 or malformed (`[A-Za-z0-9_.:-]{1,64}`) scopes, `enforce` without `enabled`. `enabled` without `enforce` is report-only: decisions are audited (`STEPUP_REPORT`) and devices learned, nothing is changed for users. Audit `ADMIN_UPDATE "stepup-policy <realm>"`. |
| GET `/realms/{r}/users/{id}/devices` | `[{"id","firstSeen","lastSeen"}]`, most recent first (`id` is the sha256 of the device cookie; the cookie and the IP hash are never returned). 404 unknown user. |
| DELETE `/realms/{r}/users/{id}/devices[/{hash}]` | `204`, idempotent; forgets all / one device of that user (the next login there counts as a new device). Audit `ADMIN_ACTION "user-devices <username>"`. |

Auth events: `STEPUP_REQUIRED` / `STEPUP_REPORT` (detail `login:` or `sso:` plus comma separated reasons from `new_device,ip_changed,idle,sensitive_scope,max_age`), `MFA_FALLBACK` (detail `to:totp|passkey`).
Tables (pg migration `0013_stepup.sql`): `realm_stepup_policy`, `known_devices`.
## DPoP and the device grant in registration policy (`docs/dpop.md`)
* `PUT /realms/{r}/registration-policy` `allowedGrantTypes` may now also contain
  `urn:ietf:params:oauth:grant-type:device_code` (each once). It is never part of the default policy: a realm
  must opt in, after which dynamic registration may create device-flow clients (`DeviceFlow`).
* The Admin API rejects any access token that carries a `cnf` claim (a DPoP-bound token) with `401`: it does not
  verify proofs, so a bound token is never accepted as a plain bearer token.
## Workload identities and agent/MCP identities

See `docs/workload-identity.md` and `docs/agent-identities.md`. Both are optional store extensions
(`core.WorkloadStore`, `core.AgentStore`); a store without them answers 501. Request bodies reject unknown
fields. Creating either also creates an inert backing client (public, no secret, no flows); a `clientId`
that already exists is 409 and never adopted. Pg migrations `0015_workload_identities.sql`,
`0016_agent_identities.sql`.

| Method and path | Notes |
|---|---|
| `GET /realms/{r}/workload-identities` | list; `inlineJwks` bool instead of the JWKS body |
| `POST /realms/{r}/workload-identities` | `{name, clientId?, issuer, jwksUri` xor `jwks, audience, subject, scopes[], ttlSeconds?}` -> 201; 400 on wildcard/empty pins, non-https issuer, bad keys, scope `openid`/`offline_access`, ttl outside 30..3600; 409 duplicate name/client |
| `GET /realms/{r}/workload-identities/{id}` | 404 unknown |
| `POST .../{id}/enable`, `POST .../{id}/disable` | returns the identity |
| `DELETE .../{id}` | 204; also deletes the backing client |
| `GET /realms/{r}/agents[?owner=]` | list |
| `POST /realms/{r}/agents` | `{name, ownerUserId, scopes[], roles[]?, audiences[]?, tokenTtlSeconds?}` -> 201; owner must exist and be enabled; every role must be held by the owner; ttl 30..900 |
| `GET /realms/{r}/agents/{id}` | |
| `POST .../{id}/enable`, `POST .../{id}/disable` | |
| `DELETE .../{id}` | 204; deletes credentials and backing client |
| `GET .../{id}/credentials` | `[{id, scopes, note, state, createdBy, createdAt, expiresAt, revokedAt?, revokedBy?, lastUsedAt?}]`; never the secret |
| `POST .../{id}/credentials` | `{ttlSeconds? 60..604800, scopes[]?, note?}` -> 201 `{credential, secret, tokenType, clientId}` (secret once); 409 when disabled or 5 active |
| `DELETE .../{id}/credentials/{cid}` | 204; 409 already ended |
| `POST .../{id}/revoke-credentials` | `{"revoked": n}` |

Events (admin events flag): `WORKLOAD_IDENTITY_CREATE|ENABLE|DISABLE|DELETE`, `AGENT_CREATE|ENABLE|DISABLE|DELETE`,
`AGENT_CREDENTIAL_ISSUED`, `AGENT_CREDENTIAL_REVOKED`. Token endpoint events (auth events flag):
`WORKLOAD_TOKEN`, `WORKLOAD_TOKEN_ERROR`, `AGENT_TOKEN`, `AGENT_TOKEN_ERROR`.

## SCIM token

See `docs/scim.md`. The SCIM 2.0 server itself is NOT under `/admin/v1`: it is `admin.SCIM(cfg)`, mounted at
`/realms/{r}/scim/v2/` and authenticated by the realm's SCIM bearer token, never by an Admin API token. These
routes manage that token. Optional store extension `core.SCIMStore` (501 without it); Pg migration `0020_scim.sql`.

| Method and path | Notes |
|---|---|
| `GET /realms/{r}/scim/token` | `{configured, endpoint, readOnly?, createdAt?, createdBy?}`; never the token |
| `POST /realms/{r}/scim/token` | optional body `{readOnly?}`; issues or rotates (old token dies at once) -> 201 `{token, endpoint, readOnly, createdAt}`; the token is shown only here |
| `DELETE /realms/{r}/scim/token` | revoke -> 204; 404 when none |

Events (admin events flag): `ADMIN_ACTION scim-token issued|revoked` (no token material). SCIM writes are audited as
`ADMIN_CREATE|UPDATE|DELETE|ACTION` with actor `scim:{realm}`.
## CIBA (client-initiated backchannel authentication)

See `docs/ciba.md`. Optional store extension (`core.CIBAStore`); a store without it answers 501. Pg migration
`0019_ciba.sql`. The opt-in is keyed by the client's opaque id, so a deleted and re-created `clientId` does not inherit it.

| Method and path | Notes |
|---|---|
| `GET /realms/{r}/clients/{id}/ciba` | `{"enabled": bool}`; 404 unknown client |
| `PUT /realms/{r}/clients/{id}/ciba` | `{"enabled": bool}` -> 200; unknown fields 400; enabling a public client or a service account is 400 |

Events (admin events flag): `UPDATE client-ciba`. Protocol events (auth events flag): `CIBA_AUTH_REQUEST`,
`CIBA_AUTH_REQUEST_ERROR`, `CIBA_APPROVE`, `CIBA_DENY`, `CIBA_TOKEN`.
## FAPI building blocks: PAR, JAR, RAR, require-PAR / require-DPoP (`docs/fapi-par-jar-rar.md`)

Optional store extension `core.FAPIStore`; a store without it answers 501. Pg migration `0018_fapi.sql`
(`client_fapi`, `fapi_requests`, `fapi_bindings`). Request bodies reject unknown fields. `{id}` is the client's UUID.

| Method and path | Notes |
|---|---|
| `GET /realms/{r}/clients/{id}/fapi` | `{requirePar, requireDpop, requireSignedRequest, jwks, authorizationDetailTypes[]}`; all off / `null` / `[]` when never set. 404 unknown client. |
| `PUT /realms/{r}/clients/{id}/fapi` | Replaces the settings (missing fields = off). 400: `requirePar` or `requireSignedRequest` on a public client (the PAR endpoint authenticates the client), `requireSignedRequest` without `jwks`, a `jwks` that is not a JWKS with at least one usable public key (EC P-256, or RSA 2048-8192 bits; a key with private members does not count), more than 20 or malformed (`^[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}$`) `authorizationDetailTypes`. Duplicate types are removed. Audit `ADMIN_UPDATE "client-fapi <clientId>"` (no key material). |

Auth events: `PAR` (a request was pushed), `PAR_ERROR` and `LOGIN_ERROR` with detail `invalid_request_object`; never the request.
## Shared signals (SSF 1.0 transmitter)

See `docs/shared-signals.md`. Optional store extension `core.SSFStore`; a store without it answers 501. The
receiver-facing endpoints are not here: they live under `/realms/{realm}/ssf/` and use receiver bearer tokens.
Pg migration `0021_shared_signals.sql`. Request bodies reject unknown fields.

| Method and path | Notes |
|---|---|
| `GET /realms/{r}/ssf/receivers` | list; never the token or its hash |
| `POST /realms/{r}/ssf/receivers` | `{name, audience?, allSubjects?, allowEmail?, events[]?}` -> 201 with `token` (shown once); 400 bad name/audience/event URI; 409 duplicate name |
| `DELETE /realms/{r}/ssf/receivers/{id}` | 204; deletes its streams, subjects and queued events |
| `POST /realms/{r}/ssf/receivers/{id}/rotate-token` | 200 with the new `token`; the old one stops working |
| `PUT /realms/{r}/ssf/receivers/{id}/disabled` | `{disabled}` -> 204; a disabled receiver gets 403 and no events |
| `GET /realms/{r}/ssf/streams[?receiver=]` | `[{id, receiverId, status, endpointUrl, eventsDelivered, subjectFormat, hasAuthorizationHeader, createdAt}]`; never the header value |
| `DELETE /realms/{r}/ssf/streams/{id}` | 204 |
| `GET /realms/{r}/ssf/outbox` | `{pending, delivered, dead}` counts |
| `POST /realms/{r}/users/{id}/ssf/credential-compromise` | `{credentialType, reasonAdmin?}` -> 204; signals only, 501 when the transmitter is not running |

Admin events: `ADMIN_CREATE|DELETE|UPDATE` with resources `ssf-receiver`, `ssf-receiver-token`, `ssf-receiver-disabled`,
`ssf-stream`, `ssf-credential-compromise`. Auth event `SSF_STREAM_CREATE` (receiver name in the detail).
