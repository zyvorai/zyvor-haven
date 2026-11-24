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
