# Device authorization grant (terminals, CI, kubectl)

haven-idp implements the OAuth 2.0 Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)),
so a program without a browser (the `haven` CLI, a build agent, `kubectl` with an OIDC plugin) can ask a person to
sign in on another device. The program shows a short code and a URL; the person opens the URL anywhere, signs in
the normal way, checks the code, and approves; the program receives the same tokens the browser login would have
produced.

It is **off for every client** until you switch it on per client (`deviceFlowEnabled`).

## The flow

```
CLI                              haven-idp                          Browser (any device)
 | POST .../auth/device  ------->  |
 | <- device_code, user_code,      |
 |    verification_uri, interval   |
 |                                 |  <-- GET /realms/{realm}/device?user_code=ABCD-EFGH
 |                                 |      (not signed in) -> normal login at /auth
 |                                 |  --> approval page: client, scopes, code, where/when
 | POST .../token (poll)  ------>  |  <-- Approve / Deny (CSRF-protected POST)
 | <- authorization_pending        |
 | POST .../token (poll)  ------>  |
 | <- id_token, access_token,      |
 |    refresh_token                |
```

### 1. Device authorization request

`POST /realms/{realm}/protocol/openid-connect/auth/device` (form encoded)

| Field | Notes |
|---|---|
| `client_id` | required; public clients send only this |
| `client_secret` / HTTP Basic | confidential clients authenticate exactly as at the token endpoint |
| `scope` | optional, space separated, from `openid profile email roles offline_access`; default `openid` |

Response `200` (JSON, `Cache-Control: no-store`):

```json
{
  "device_code": "…43 chars…",
  "user_code": "BCDF-GHJK",
  "verification_uri": "https://idp.example/realms/acme/device",
  "verification_uri_complete": "https://idp.example/realms/acme/device?user_code=BCDF-GHJK",
  "expires_in": 600,
  "interval": 5
}
```

Errors are RFC 6749 JSON: `invalid_client` (401: unknown or disabled client, bad secret, a public client that sent
a secret), `unauthorized_client` (the client does not have the device flow enabled), `invalid_scope` (unknown scope),
`429 slow_down` (more than 60 requests per IP per 10 minutes), `501 feature_unavailable` (the store has no device
support), `404 realm_not_found`.

### 2. Polling the token endpoint

`POST /realms/{realm}/protocol/openid-connect/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`,
`device_code`, and `client_id` (plus client authentication for confidential clients).

| Error | Meaning | Client action |
|---|---|---|
| `authorization_pending` | the user has not decided yet | keep polling every `interval` seconds |
| `slow_down` | polled faster than the stored interval | add 5 seconds to your interval (the server did the same: it is `interval + 5`, capped at 300) and keep polling |
| `access_denied` | the user pressed Deny | stop |
| `expired_token` | the code expired (10 minutes) | stop, start over |
| `invalid_grant` | unknown, already used, belongs to another client or realm, the approving session ended, or the user is disabled | stop |
| `unauthorized_client` | the client's device flow is off | stop |
| `invalid_client` | client authentication failed | stop |

The first poll is free; a too-fast poll also counts as the last poll, so wait the full interval after a
`slow_down`. On approval the response is the same as for the authorization-code grant: `access_token`,
`id_token` (when `openid` was granted), and a `refresh_token` by the same rules (always with `offline_access`,
otherwise when the realm issues refresh tokens). The ID token carries `sid` and `auth_time` of the approving SSO
session. The refresh token works with `grant_type=refresh_token` for the device client even though it has no
authorization-code flow.

A device code is **single use**: the row is deleted atomically when tokens are issued, so two concurrent polls
yield exactly one token set. A denied code keeps answering `access_denied` until it expires.

### 3. What the person sees

`GET /realms/{realm}/device` shows a field for the code (`POST` with CSRF); `?user_code=` pre-fills it. Input is
case-insensitive and ignores dashes and spaces. If the browser has no live SSO session it is redirected through
the ordinary login (see below) and comes back to an approval page that shows:

* the client's display name (HTML-escaped) and who is signing in,
* the requested scopes in plain words,
* the user code again, so it can be compared with the device,
* where and when the request was made: the **IP address and a short user-agent of the device that started
  it**, and the request time,
* the warning **"Only approve if you started this on your own device."**

Approve and Deny are CSRF-protected form posts (double-submit cookie `haven_device_csrf` bound to the form token,
15 minute lifetime). After the decision a final page is shown; there is no redirect. A decision can be made once:
approved and denied codes cannot be flipped.

## Authentication reuses the real login

The device flow contains **no password check of its own**. When there is no live SSO session, the verification page
redirects to `/realms/{realm}/protocol/openid-connect/auth` as the built-in public pseudo client `haven-device`:

* the client exists only inside the authorization endpoint's client lookup (it is not stored, not listed, not
  visible to the Admin API, and the token endpoint rejects it with `invalid_client`),
* its only redirect URI is `{base}/realms/{realm}/device/continue`,
* PKCE S256 is enforced, and the verifier is never kept: the authorization code it receives can never be redeemed.
  `/device/continue` does not even look at the code (it deletes it for hygiene); it only reads the SSO session
  cookie the login set, and carries the user code through a signed, 15 minute `state`.

So every rule of the normal login applies automatically: password check with the dummy-hash timing defence,
brute-force lockout, disabled users, required email verification, the SSO session, and any extra step registered
through `authStepHooks` (TOTP, passkeys). A user who already has a live SSO session in the realm goes straight to
the approval page without signing in again; the same session checks as silent SSO apply (user exists, is enabled,
email verified when the realm requires it).

Tokens are **bound to the approving SSO session**: the device client is added to the session's client list and the
tokens carry its id as `sid`. Ending the session (logout, admin revoke, password reset) revokes the device's
non-offline refresh tokens and its access/ID tokens stop carrying a live `sid`, exactly as for the code flow.
Refresh tokens with `offline_access` outlive the session, as in the code flow.

## Security properties

* **User code**: 8 characters from `BCDFGHJKLMNPQRSTVWXZ` (no vowels, no `0/O/1/I`), about 36.4 bits, shown as
  `XXXX-XXXX`, generated by rejection sampling from `crypto/rand`. Stored only as sha256 of the normalised code.
* **Device code**: 32 random bytes (base64url), stored only as sha256. Neither value is ever logged or put into an
  audit event.
* **Brute force**: every user-code lookup (entry, verification link, `/device/continue`, Approve/Deny) is limited
  per IP (30 per 10 minutes) and per realm (600 per 10 minutes) with the shared `HitRateLimit`; a limiter error
  fails closed (503). The realm-wide budget keeps a distributed guesser from walking the code space (600 guesses
  per 10 minutes against 2.6e10 codes per active window) at the price that an attacker can temporarily exhaust it
  for honest users.
* **Uniform answers**: unknown, malformed, expired, already approved and already denied codes produce the same
  page and status (400); decisions on them too.
* **Poll isolation**: a poll only sees a code that belongs to the authenticated `client_id` in this realm; another
  client's valid code and an unknown code give the identical `invalid_grant`, and a foreign poll does not change
  the owner's interval.
* **Same realm**: codes are looked up per realm and the SSO cookie is scoped to its realm path, so a session in
  another realm cannot approve.
* **Opt-in**: only clients with `deviceFlowEnabled` may start or poll; turning the flag off kills requests in
  flight.
* **Pages**: `Cache-Control: no-store`, `X-Frame-Options: DENY`, nonce'd CSP with `default-src 'none'` (no script
  at all), all values HTML-escaped.
* **Housekeeping**: expired requests (10 minutes) are removed by the same purge loop as other expired rows
  (every 5 minutes). A poll slightly after expiry gets `expired_token`; after the purge it gets `invalid_grant`.
* The device authorization endpoint is rate limited per IP (60 per 10 minutes) so it cannot be used to fill the
  table.

## Events

`DEVICE_AUTH_REQUEST` (client, IP, scope), `DEVICE_AUTH_REQUEST_ERROR` (client, reason), `DEVICE_APPROVE`,
`DEVICE_DENY` (user, client, approver's IP), `DEVICE_TOKEN` (user, client, polling IP). The usual login events
(`LOGIN`, `LOGIN_ERROR`) are also written by the underlying login, with client `haven-device`.

## Configuration

Per client, default off:

| Where | Setting |
|---|---|
| Admin API (`idp.Client`) | `"deviceFlowEnabled": true`. Client `PUT` is a **full replace**, like `redirectUris`: omitting the key switches the flow off. Rejected (400) together with `serviceAccountsEnabled`. |
| Config as code | `clients[].deviceFlowEnabled: true` (parsed, validated, shown in `plan`, applied, read back by `export`; a service account client cannot enable it) |
| Postgres | migration `0006_device_flow.sql`: `clients.device_flow`, table `device_codes` |

Discovery advertises `device_authorization_endpoint` and adds the grant URN to `grant_types_supported` when the
store supports it. TTL (10 minutes) and interval (5 seconds) are fixed constants for now.

`haven-idp dev` registers the public client `demo-cli` with the device flow on and prints
`haven login --issuer <issuer> --client-id demo-cli`.

## Not yet

* TTL, interval and rate limits are not configurable.
* No admin UI/endpoint to list or revoke pending device requests; they simply expire.
* The in-memory store does not drop device requests when a realm is deleted (Postgres does, by foreign key); they
  expire on their own and are realm-scoped.
* The browser flow itself is covered by Go tests against the handlers, not by a real browser; the page layout is
  plain and unstyled beyond the shared look of the login page.
* No per-client TTL or interval.
* `haven login` (the CLI side) is a separate piece of work.
