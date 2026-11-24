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
the login page.

**Authorization request parameters.**

- `prompt=none` never shows a page. If there is a live session the client gets a code; otherwise it
  gets `login_required`.
- `prompt=login` ignores the existing session and asks for the password again. The new login replaces
  the SSO session.
- `max_age=N` accepts the session only if the user authenticated with a credential at most N seconds
  ago; otherwise the user must log in again.

**Claims.** ID tokens carry `sid` (the session id, the same id the Admin API shows) and `auth_time`
(when the user last authenticated with a credential, not when the session was last used).

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
- `iat` and `jti`
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
- Failed deliveries are retried. A failure never blocks or fails the logout itself: the session is
  already gone.
- Notification is best effort. A client that was down for all attempts is not told again; its own
  session lifetime is the backstop.

**Configuring it.** Set `backchannelLogoutUrl` on the client with the Admin API (create or update
client) or in config as code. Empty means the client is not notified.

## What ends a session

| Event | Session | Refresh tokens | Clients notified |
|---|---|---|---|
| User logs out (RP-initiated) | ended | non-offline ones revoked | yes |
| Admin ends it (`DELETE .../sessions/{sid}`) | ended | non-offline revoked | yes |
| Admin ends all of a user's sessions | ended | non-offline revoked | yes |
| User disabled (`enabled` true to false) | all ended | non-offline revoked | yes |
| Admin password reset (`PUT .../password`) | all ended | non-offline revoked | yes |
| User deleted | all ended first | non-offline revoked | yes |
| Idle or absolute expiry | ignored from then on, purged later | not revoked by expiry | no |

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
- Back-channel targets are https only and may not point at private networks, which keeps the logout
  mechanism from being used to probe your internal network.
- The `logout_token` is signed with the realm key and has no `nonce`, so it cannot be mistaken for an
  ID token.
- Admin responses and audit events carry no secrets. The IP address and user agent are shown to
  admins only, for the session they belong to.

## Not yet

- No front-channel logout.
- No `check_session_iframe` (session management 1.0); use short access tokens and back-channel logout.
- No per-client session limits.
- No "remember me" with a longer lifetime.
- Session creation does not yet enforce a maximum number of concurrent sessions per user.
- SSO sessions are per realm only; there is no sharing across realms.
- Expired sessions are purged on a timer rather than immediately (they are ignored and hidden from
  the Admin API in the meantime).
