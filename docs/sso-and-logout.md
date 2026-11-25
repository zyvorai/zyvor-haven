# SSO sessions and single logout

haven-idp keeps a **single sign-on (SSO) session** per browser. Once a user has signed in to one
application, the next application in the same realm does not ask for a password again. Ending the
session (logout, an admin, a disabled account, a password reset) signs the user out everywhere that
supports it.

## How SSO works

After a successful login the server sets the cookie `haven_sso`:

| Property | Value |
|---|---|
| Content | a random secret; the server stores only a **hash** of it |
| `HttpOnly` | yes |
| `SameSite` | Lax |
| `Secure` | yes on https |
| Scope | one realm (see "Not yet") |

A second authorization request in the same browser finds the session by that cookie and issues a code
without showing the login page.

**Lifetime.** A session has two limits:

- **Idle timeout:** the realm's `SessionIdleTTL` (default 30 minutes). Each use of the session pushes
  it forward.
- **Absolute cap:** 10 hours from the login, never extended.

Whichever comes first ends the session. An expired session is treated as no session: the user sees
the login page. A realm can offer a longer lifetime, see "Keep me signed in".

**Authorization request parameters.**

- `prompt=none` never shows a page. If there is a live session the client gets a code; otherwise it
  gets `login_required`.
- `prompt=login` ignores the existing session and asks for the password again. The new login replaces
  the SSO session.
- `max_age=N` accepts the session only if the user authenticated with a credential at most N seconds
  ago; otherwise the user must log in again.

**Claims.** ID tokens carry `sid` (the session id, the same id the Admin API shows) and `auth_time`
(when the user last authenticated with a credential, not when the session was last used).

## Session controls

Both are per realm and **off until set**:

```
PUT /admin/v1/realms/{r}/session-policy
{
  "maxSessionsPerUser": 3,          // 0 = unlimited (default), up to 1000
  "onLimit": "revoke_oldest",       // or "deny_new"
  "rememberMe": true,
  "rememberIdleSeconds": 604800,    // 0 = 7 days; 1 hour to the maximum
  "rememberMaxSeconds": 2592000     // 0 = 30 days; 1 to 90 days
}
```

The PUT replaces the whole policy: an absent field is off or default.

### Concurrent session limit

The limit counts a user's **live** sessions (not expired, not idle too long). It is applied when a
login creates a session, after every factor has been satisfied.

- `revoke_oldest` (default): the new login succeeds and the sessions created earliest are ended until
  the limit holds. Each is ended like a logout: non-offline refresh tokens revoked, back-channel
  logout sent, a Shared Signals `session-revoked` event, and a `LOGOUT` audit event with detail
  `session_limit`. There is no front-channel logout (that browser is not there).
- `deny_new`: the new login is refused with a "Too many sessions" page and nothing existing is
  touched. The user has to sign out elsewhere, wait for a session to expire, or ask an administrator.
  Combined with "keep me signed in" this can keep a user out for days.
- A browser signing in again replaces its own session and does not count against itself.
- The count and the insert are one atomic step in the store (in PostgreSQL a transaction-level
  advisory lock per user), so parallel logins on several replicas cannot exceed the limit.
- Lowering the limit ends nothing by itself; it applies at the user's next login.
- If the policy cannot be read, the login fails.

### Keep me signed in

With `rememberMe` the login page shows an **unticked** checkbox. Ticked, the session gets the
remember idle window (never shorter than the realm's ordinary one) and the remember absolute maximum,
both bounded as above, and the cookie expires with the session. Unticked, nothing changes.

- The choice is carried across second factor steps in a signed 15 minute cookie bound to the user and
  to the authorization request, and also applies to the passkey button and passkey autofill.
- Turning the option off, or shortening the maximum, applies **at once** to existing remembered
  sessions: they stop working for single sign-on and for their (non-offline) refresh tokens. A
  shorter idle window applies from their next use. (They may still be listed by the Admin API until
  purged or until a new login of that user clears them under a session limit.)
- Federated sign-in has no checkbox and always gets the ordinary lifetime.
- Step-up policy, `max_age`, `prompt=login` and the 10 minute re-authentication of account pages are
  unaffected: a remembered session is not a recent login.

## Single logout

**RP-initiated logout.** `GET /realms/{realm}/protocol/openid-connect/logout`.

- With `id_token_hint` (an ID token this server issued) and a `post_logout_redirect_uri` registered
  for that client, the session is ended at once and the browser is redirected back. `state` is
  returned unchanged.
- Without a usable `id_token_hint`, the server shows a **confirmation page** instead. Ending a session
  needs a deliberate click, so a hostile page cannot sign users out by embedding the URL as an image.

The `haven_sso` cookie is cleared in both cases.

**Back-channel logout.** When a session ends, every client that received a code in that session and
has a `backchannelLogoutUrl` is told, server to server, following
[OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html).

The POST is `application/x-www-form-urlencoded` with one field, `logout_token`, a signed JWT with:

- `iss`: the realm issuer
- `aud`: the client id
- `iat`, `exp` (two minutes after `iat`) and `jti`
- `sid`: the ended session
- `sub`: the user id
- `events`: `{"http://schemas.openid.net/event/backchannel-logout": {}}`
- no `nonce`

The receiving application should verify the signature and these claims, then end its own session
for that `sid` (or `sub`) and answer 200.

Delivery rules:

- **https only.** (Plain http is accepted only for loopback addresses, for local development.)
- **Private-network targets are refused**: loopback (outside dev), link-local, RFC 1918 and similar
  addresses are not contacted, including after DNS resolution.
- **5 second timeout** per attempt.
- Network errors, 5xx and 429 are retried twice (3 attempts in all) with a doubling backoff starting at
  200 ms; other 4xx answers are not retried. A failure never blocks or fails the logout itself: the session is
  already gone.
- Notification is best effort. A client that was down for all attempts is not told again; its own
  session lifetime is the backstop.

**Configuring it.** Set `backchannelLogoutUrl` on the client with the Admin API (create or update
client) or in config as code. Empty means the client is not notified.

## Front-channel logout

[OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) lets
an application clear its own browser state when the user signs out. Register a
`frontchannel_logout_uri` per client:

- Admin API: `PUT /admin/v1/realms/{r}/clients/{id}/frontchannel-logout`
  `{"frontchannelLogoutUrl": "https://app.example/fc-logout"}` (`""` removes it).
- Dynamic client registration: the `frontchannel_logout_uri` metadata field.

The URI must be https (http only for loopback), without credentials or fragment, with a DNS name or
IPv4 address as host, and with the **same scheme, host and port as one of the client's redirect
URIs**. It is checked at registration and again at every logout. Discovery announces
`frontchannel_logout_supported` and `frontchannel_logout_session_supported`.

**When it runs.** Only when a sign-out request ends the session of **the browser that made it**
(the request carried that session's `haven_sso` cookie), after the confirmation click or with a
matching `id_token_hint`. The sign-out page then loads each of that session's applications (at most
20) in a hidden iframe at its URI, with `iss` and `sid` added (always both). With a
`post_logout_redirect_uri` the browser moves on after 5 seconds (an HTTP `Refresh` header, and a
link); without one it stays on "Signed out". When no application of the session has a URI, logout
behaves as before (an immediate redirect or the plain page).

**Security properties.**

- Only this one page may frame anything. Its policy is
  `default-src 'none'; style-src 'nonce-…'; frame-src <the origins of these frames>; base-uri 'none';
  frame-ancestors 'none'`. No wildcard, no scheme source, no script; every other page has no
  `frame-src` at all.
- Frames are `sandbox="allow-scripts allow-same-origin"` (the application needs its own cookies and
  storage), no forms, popups or top navigation. An application on the identity server's **own origin**
  gets `allow-scripts` only, so it cannot reach the sign-out page.
- No `Referer` is sent (the page URL can contain an `id_token_hint`).
- A stolen `id_token_hint` used without the user's cookie ends the session (as before) but renders no
  frames, so it does not reveal which applications the user used or the session's URIs.

**Limits.** Delivery is not confirmed: the identity server cannot see whether a frame loaded. Browsers
that block third-party cookies or partition storage may give the framed page none of the
application's cookies; applications should use `sid` to end the session server side, or rely on
back-channel logout, which stays the dependable mechanism. A framed page that redirects to another
origin is blocked. The application must allow itself to be framed by the identity server. Sessions
ended by an administrator, the session limit, a password reset or a cross-site POST logout (no cookie)
get back-channel logout only.

## What ends a session

| Event | Session | Refresh tokens | Clients notified |
|---|---|---|---|
| User logs out (RP-initiated) | ended | non-offline ones revoked | yes |
| Admin ends it (`DELETE .../sessions/{sid}`) | ended | non-offline revoked | yes |
| Admin ends all of a user's sessions | ended | non-offline revoked | yes |
| User disabled (`enabled` true to false) | all ended | non-offline revoked | yes |
| Admin password reset (`PUT .../password`) | all ended | non-offline revoked | yes |
| User deleted | all ended first | non-offline revoked | yes |
| Session limit, `revoke_oldest` | oldest ended | non-offline revoked | yes (back-channel) |
| Idle or absolute expiry | ignored from then on, purged later | not revoked by expiry | no |
| "Keep me signed in" withdrawn | remembered sessions ignored from then on | their non-offline ones stop working | no |

**What survives.** Refresh tokens issued with the `offline_access` scope are **not** revoked when a
session ends. They are the point of offline access: a background job keeps working after the user
logged out. They end by their own expiry or by explicit revocation. Access tokens already issued stay valid until they
expire (they are short lived); resource servers that need faster cut-off should keep the access token
lifetime short.

## Admin API

All routes are under `/admin/v1` and need an admin token (see the Admin API spec).

| Route | Result |
|---|---|
| `GET /realms/{r}/sessions?userId=&max=` | live sessions, newest first; `max` default 100, cap 500 |
| `GET /realms/{r}/users/{id}/sessions` | live sessions of one user; 404 unknown user |
| `DELETE /realms/{r}/sessions/{sid}` | 204; 404 if unknown or already ended |
| `DELETE /realms/{r}/users/{id}/sessions` | 200 `{"ended": n}`; 404 unknown user |
| `GET\|PUT /realms/{r}/session-policy` | session limit and "keep me signed in" (above) |
| `GET\|PUT /realms/{r}/clients/{id}/frontchannel-logout` | the client's front-channel logout URI |

A session in the list has `id`, `userId`, `username` (empty if the user was deleted), `ipAddress`,
`userAgent`, `start`, `lastAccess`, `expires` (the earlier of the idle and absolute expiry) and
`clients` (client ids that received a code). Expired sessions are hidden even if they have not been
purged yet. The cookie secret and its hash are never returned.

Every end writes an `ADMIN_ACTION` audit event (`session <sid>` or `user-sessions <username>`) when
the realm logs admin events. The event has no cookie data, no token and no address.

The Go `native` client implements the optional `idp.SessionManager` interface for these routes.

## Security notes

- The cookie value is a random secret and only its hash is stored, so a database leak does not yield
  usable cookies.
- `HttpOnly` keeps scripts from reading it; `SameSite=Lax` keeps it off cross-site POSTs.
- Logout without a valid `id_token_hint` asks for confirmation, which stops logout CSRF.
- `post_logout_redirect_uri` must be registered for the client; anything else is not followed.
- Back-channel targets are https only (plain http only for loopback in `haven-idp dev`) and may not point at private networks, which keeps the logout
  mechanism from being used to probe your internal network.
- The `logout_token` is signed with the realm key and has no `nonce`, so it cannot be mistaken for an
  ID token.
- Admin responses and audit events carry no secrets. The IP address and user agent are shown to
  admins only, for the session they belong to.

## Testing and honest limits

Handler and store tests cover the limit (both actions, concurrency on the memory and PostgreSQL
stores), the lifetimes, and the front-channel page and its policy. A run against `haven-idp dev` with
headless Chrome exercised the "keep me signed in" cookie lifetime, both limit actions with
back-channel delivery, and front-channel logout between two loopback applications, including the
browser enforcing `frame-src`. **Not
tested: real third-party applications on separate sites, third-party cookie blocking, Safari or
Firefox.**

## Not yet

- No `check_session_iframe` (session management 1.0); use short access tokens and back-channel logout.
- No per-client or per-user session limits.
- The session policy and the front-channel URI are not part of config as code, realm export or the
  console.
- SSO sessions are per realm only; there is no sharing across realms.
- Expired sessions are purged on a timer rather than immediately (they are ignored and hidden from
  the Admin API in the meantime).
