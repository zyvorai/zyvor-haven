# Federation: "Sign in with Google / Microsoft / your OIDC provider"

haven-idp can broker logins to **upstream OpenID Connect providers**. The login page shows a
`Continue with <name>` button per enabled provider; the user signs in at the upstream, haven-idp
validates the result and then issues its own session and tokens, exactly as for a password login.
Your applications keep talking only to haven-idp.

Supported upstreams: **Google**, **Microsoft Entra ID**, and any **generic OIDC provider** (Okta,
Auth0, Keycloak, another haven-idp...). Flow: authorization code with PKCE (S256) and a nonce.

Not supported (see the end): SAML, GitHub, account-linking UI, storing upstream tokens,
IdP-initiated login.

## Setup

Prerequisite: set `HAVEN_IDP_SECRET_KEY` (`haven-idp keygen`) so upstream client secrets can be
stored (they are encrypted, see "Secrets"). `haven-idp dev` supplies a random key.

In the upstream provider, register an OIDC client ("web application") with this **redirect URI**:

```
https://<your-idp>/realms/<realm>/broker/<alias>/endpoint
```

`<alias>` is the name you choose below (`[a-z0-9-]{1,32}`). Then create the provider through the
Admin API (the console's Federation Hub uses the same calls):

```sh
curl -X POST https://<your-idp>/admin/v1/realms/<realm>/identity-providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{ ... }'
```

### Google

```json
{"alias":"google","displayName":"Google","providerId":"google","enabled":true,"trustEmail":true,
 "config":{"clientId":"123.apps.googleusercontent.com","clientSecret":"GOCSPX-...",
           "hostedDomain":"corp.example","autoCreateUsers":"true"}}
```

The issuer is fixed (`https://accounts.google.com`). `hostedDomain` restricts sign-in to one
Google Workspace domain: it is sent as `hd` and the ID token's `hd` claim must match. Without it any
Google account can sign in.

### Microsoft Entra ID

```json
{"alias":"entra","displayName":"Microsoft","providerId":"microsoft","enabled":true,"trustEmail":false,
 "config":{"tenant":"<tenant-id-guid>","clientId":"<application-id>","clientSecret":"...",
           "autoCreateUsers":"true"}}
```

* **Use a concrete tenant id** (a GUID) for a workforce directory. The issuer is then exactly
  `https://login.microsoftonline.com/<tenant>/v2.0`.
* `tenant` `common` (the default), `organizations` or `consumers` makes the provider
  **multi-tenant**: users of *any* Entra tenant (or personal accounts) can sign in. haven-idp then
  validates the ID token issuer against the token's own `tid` claim, qualifies the account key as
  `<tid>/<sub>`, and **refuses** `linkExistingByEmail`.
* Entra does not send `email_verified`. haven-idp only treats an email as verified when the optional
  claim **`xms_edov`** ("email domain owner verified") is present and true; add it as an optional ID
  token claim in the app registration if you want `trustEmail` to mean anything. Without it, new
  users get an unverified email. The email claim of Entra is mutable and unverified by design: keep
  `trustEmail` off unless you control the tenant.
* Request `email` and `profile` scopes (the default) and, if you use `roleMappings` with `groups`,
  configure the groups claim in the app registration.

### Generic OIDC (Okta, Auth0, Keycloak, haven-idp...)

```json
{"alias":"okta","displayName":"Okta","providerId":"oidc","enabled":true,
 "config":{"issuer":"https://corp.okta.com","clientId":"...","clientSecret":"...",
           "scopes":"openid email profile groups","autoCreateUsers":"true"}}
```

`issuer` must equal the provider's `iss` exactly (no trailing-slash guessing). Discovery is fetched
from `{issuer}/.well-known/openid-configuration` or from `discoveryUrl` if the provider serves it
elsewhere (then `issuer` may be omitted when the URL ends in `/.well-known/openid-configuration`).
The discovery document's `issuer` must equal the configured issuer or the login is refused.

### Config reference

See the table in `internal/idp/admin/SPEC.md`. Highlights: `scopes` (default
`openid email profile`), `usernameClaim` (default `preferred_username`, falling back to the email
local part), `autoCreateUsers` (default **false**), `linkExistingByEmail` (default **false**),
`roleMappings`, `roleSyncMode`. `PUT` replaces the whole provider; sending `"clientSecret":"**********"`
(as `GET` returns it) or omitting it keeps the stored secret.

## What happens at login

1. The user opens `/auth`; the login page shows the buttons (only for enabled providers).
2. `GET /realms/<realm>/broker/<alias>/login?<original query>` validates the original authorization
   request again (client, exact redirect URI, PKCE), stores a **single-use** state and sets a
   `haven_fed` cookie that binds the flow to this browser, then redirects to the upstream.
3. The upstream redirects back to `.../broker/<alias>/endpoint?code&state`. The state is consumed
   whatever happens next; it must match the cookie; it expires after 10 minutes.
4. haven-idp exchanges the code (client authentication `client_secret_basic`, or `client_secret_post`
   if that is all the provider advertises) and validates the ID token: signature against the
   upstream JWKS (key chosen by `kid`; one rate-limited refresh when a new key appears), algorithm
   in `RS256`/`ES256`/`PS256` only (never `none` or `HS*`), `iss`, `aud` (+`azp`), `exp`/`iat`/`nbf`
   with 60 s of clock skew, and the `nonce`.
5. The local user is resolved (below), roles are mapped, and the login completes: the user is
   redirected to your application with an authorization code of haven-idp, which the application
   exchanges at haven-idp's token endpoint as usual. The login event detail is `federated:<alias>`.

**No local second factor** is run for federated logins: the upstream authenticated the user, and
enforcing its MFA is the upstream's job. **This includes a realm's `requireMfa` policy** ([mfa-totp.md](mfa-totp.md)):
it applies to local password logins only, so a realm that must have MFA for everyone has to get it
from its upstream providers (or not enable federation). (The code is structured so a per-provider "also require
local MFA" option can be added; it is not there yet.) A silent SSO re-login uses the haven-idp session.

## Who is the local user? (linking policy)

In this order:

1. **An existing link** `(realm, alias, upstream sub)` selects that user. Email changes upstream do
   not matter. A disabled user is refused.
2. **No link, but a local account has the same email.** By default this is **refused** with a clear
   page: no new account (that would create a duplicate email) and no automatic link. It is linked
   automatically only when **all** of these hold:
   * `linkExistingByEmail` is `"true"`, **and**
   * the provider has `trustEmail: true`, **and**
   * the upstream says the address is verified (`email_verified: true`; for Microsoft `xms_edov`),
   * exactly **one** local account has that email,
   * that account has **no link for this provider yet**, and is enabled.
3. **No link, no account with that email.** If `autoCreateUsers` is `"true"` a user is created:
   unique username (from `usernameClaim`, else the email local part, numeric suffix on collision),
   email set, `emailVerified = upstream verified AND trustEmail`, **no password**, no required
   actions. Otherwise the user sees "no account is linked ... ask an administrator".

> **Account-takeover risk of `linkExistingByEmail`.** It lets whoever controls the upstream
> account with address X sign in as the local account with address X. That is only safe when the
> upstream *proves* ownership of the address (Google with `email_verified`; Entra only with a
> concrete tenant you control and `xms_edov`) and you trust every account of that upstream. Never
> enable it for a provider where users can choose or change their email unverified (self-service
> OIDC servers, multi-tenant Entra), and never together with a provider you do not administer.
> haven-idp refuses the multi-tenant Microsoft combination outright. When in doubt leave it off and
> link users yourself: there is no linking API in this release, but a link is created by the first
> login of an identity whose email is not yet taken.

Realms with `verifyEmail` on still require a verified local email: a federated user whose email is
not verified (upstream unverified or `trustEmail` off) is told to verify it first, as for password
logins.

## Claim to role mapping

```json
"roleMappings": "[{\"claim\":\"groups\",\"value\":\"eng\",\"roles\":[\"developer\"]},
                  {\"claim\":\"realm_access.roles\",\"value\":\"staff\",\"roles\":[\"employee\"]}]"
```

A rule matches when the ID token claim equals the value (string, number or boolean compared as
text) or, for an array claim, contains it. `claim` is a top-level claim name or a dotted path into
nested objects. Roles that do not exist in the realm are skipped (never created). Mappings run on
**every** login, including the first.

* `roleSyncMode: "import"` (default): only **adds** roles the mappings grant. It never removes
  anything, so an administrator's roles and earlier mapped roles stay.
* `roleSyncMode: "sync"`: additionally removes roles that federation added earlier (recorded per
  link) and the mappings no longer grant. A role an administrator assigned is never recorded as
  federation-added, so `sync` never removes it, even if a mapping also grants it.

Only claims in the **ID token** are used (no userinfo call): configure the upstream to include them.

## Secrets

The upstream client secret is encrypted with AES-256-GCM (secretbox), bound to
`idp|<realm>|<alias>`: a ciphertext copied to another provider or realm does not open. It is
**write-only**: the Admin API returns `"clientSecret":"**********"` when one is stored and never
the value; it does not appear in logs, events, audit details or error pages. Without
`HAVEN_IDP_SECRET_KEY`, creating or updating a provider *with* a secret answers 409; listing and
reading keep working; logins of providers with stored secrets fail closed. Rotating
`HAVEN_IDP_SECRET_KEY` follows secretbox's rule (list several keys, newest first). Backups of the
database contain only ciphertext.

## Security properties

* All upstream calls (discovery, JWKS, token endpoint) go through one SSRF-safe client: https only,
  the destination IP is checked at dial time (no loopback, private, link-local, CGNAT, metadata
  ranges; DNS rebinding cannot bypass it), no redirects, no proxy from the environment, timeouts,
  response size limits. A discovery document pointing the token endpoint at a private address
  makes the login fail. (`haven-idp dev` relaxes this so two local instances can talk.)
* The `state` is random, stored only as a hash, single use, expires in 10 minutes and is bound to
  the browser by a cookie: a callback URL planted in another browser (login CSRF / session
  fixation) is refused.
* PKCE and nonce are always sent; the verifier is derived from the state with the server key (set
  `HAVEN_IDP_CSRF_KEY` identically on all replicas, as for the login form).
* Discovery and JWKS are cached 10 minutes (bounded entries); an unknown `kid` triggers at most one
  JWKS refetch per 30 s.
* Rate limit: 30 login starts per 5 minutes per client IP.

## Troubleshooting

Users see a generic page; the reason is in the server log (`oidc: federated login failed ...
kind=`) and in the `LOGIN_ERROR` events (`federated:<alias>:<kind>`):

| kind | meaning |
|---|---|
| `unknown_state`, `state_mismatch`, `browser_mismatch`, `no_state` | expired, replayed or foreign callback; start again from the app (cookies must be enabled) |
| `issuer_mismatch` | discovery `issuer` or the ID token `iss` differs from the configured one (trailing slash? multi-tenant?) |
| `blocked_address` | an endpoint resolves to a private/loopback address (refused by design) |
| `network`, `timeout`, `http_status`, `too_large` | upstream unreachable, slow or misbehaving |
| `token_rejected` | the token endpoint refused the code: wrong client secret, redirect URI not registered upstream, clock |
| `bad_signature`, `bad_alg`, `unknown_key` | ID token not signed by the provider's published keys (or an algorithm outside RS256/ES256/PS256) |
| `bad_audience`, `bad_nonce`, `expired`, `bad_time` | token for another client, replay, or clock skew over 60 s |
| `secret_unreadable`, `no_secret_key` | the stored secret does not open (key changed) or no key is configured |
| `no_account`, `email_exists`, `link_conflict`, `disabled` | linking policy refused the login (see above) |

The provider must request the `email` scope for email linking; `profile` for names.

## Importing from Keycloak

`haven-idp import-keycloak` converts OIDC, Google and Microsoft identity providers to the Admin API
shape (`identity-providers.json` in `--out-dir`). Keycloak masks client secrets in exports, so the
converted providers are **disabled and without secret**: re-enter `config.clientSecret` and enable
them. `linkExistingByEmail` and `autoCreateUsers` are not carried over (both default to false).
GitHub, SAML, other types, identity provider mappers and users' federated identities are reported as
not migrated.

## Not yet

* **SAML** and **GitHub** (GitHub is OAuth2, not OIDC) upstreams.
* No UI to link/unlink an existing user to an upstream identity interactively (an administrator can
  unlink through the Admin API; linking happens through the policy above only).
* Upstream tokens are never stored or exchanged (no "retrieve the Google access token" feature);
  user info comes from the ID token only; no refresh of upstream sessions, no upstream logout.
* **No IdP-initiated login**; every flow starts at haven-idp.
* No per-provider "require local MFA after federated login" yet; no profile sync after the first
  login; no group/organisation provisioning beyond role mappings; no LDAP/SCIM.
* Role mappings read ID token claims only.
