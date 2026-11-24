# CIBA: a person approves what an agent wants to do

haven-idp implements the poll mode of OpenID Connect Client-Initiated Backchannel Authentication (CIBA Core 1.0).
The main use is an AI agent (or any backend service) that needs a **human to approve one action, out of band**:
the agent names the user, the user gets an email with a link, signs in, sees exactly who is asking for what, and
approves or denies. The agent polls the token endpoint and receives tokens only if the person said yes.

It is **off for every client** until you switch it on per client, and it needs the mail transport (the same one
that sends password-reset and verification mail; no new transport).

## The flow

```
Agent (confidential client)          haven-idp                       User (mail + browser)
 | POST .../ext/ciba/auth --------->  |
 |   login_hint, scope, binding_      |  -- email with approval link -->
 |   message, resource                |
 | <- auth_req_id, expires_in,        |  <-- GET /realms/{realm}/ciba/approve?req=...
 |    interval                        |      (fresh login: password, MFA, step-up)
 |                                    |  --> approval page: client, scopes, message, resources
 | POST .../token (poll) ---------->  |  <-- Approve / Deny (CSRF-protected POST)
 | <- authorization_pending           |
 | POST .../token (poll) ---------->  |
 | <- access_token, id_token          |
```

### 1. Backchannel authentication request

`POST /realms/{realm}/protocol/openid-connect/ext/ciba/auth` (form encoded). The client authenticates exactly as at
the token endpoint (`client_secret_basic` or `client_secret_post`). Public clients cannot use CIBA.

| Field | Notes |
|---|---|
| `login_hint` | required: the user's username or email address. At most 256 characters. |
| `scope` | required, must include `openid`; from `openid profile email roles`. `offline_access` is rejected (see below). |
| `binding_message` | optional, at most 128 characters, no control or formatting characters (newlines, bidi overrides). Shown to the user on the approval page and in the email, labelled as coming from the application. |
| `resource` | optional, repeatable (at most 5): absolute `http(s)` URIs without fragment or userinfo (RFC 8707 indicators). Shown to the user. |
| `requested_expiry` | optional, 1 to 600 seconds; default 120. |

Rejected with `invalid_request`: `login_hint_token`, `id_token_hint`, `user_code`, `request`, `request_uri` (not
supported). Other errors: `invalid_scope`, `invalid_binding_message`, `invalid_target`, `unauthorized_client`
(client not opted in, or public), `invalid_client` (bad credentials), `slow_down` with HTTP 429 (rate limit),
`feature_unavailable` with HTTP 501 (store or mail missing).

Response `200`:

```json
{ "auth_req_id": "...", "expires_in": 120, "interval": 5 }
```

### 2. Approval by the user

The user receives an email naming the client, the binding message, the scopes and resources, and a link to
`/realms/{realm}/ciba/approve?req=<token>`. The token in the link is a different random value from the
`auth_req_id`: whoever sees the email cannot poll for the tokens, and the agent cannot approve its own request.

Opening the link always sends the browser through the **ordinary login** (`/auth` with `prompt=login`, as the
built-in client `haven-ciba`): lockout, email verification, passkeys, TOTP, the step-up policy (evaluated with the
request's real scope, so "sensitive scope" rules apply) all run. A sign-in more than 5 minutes old does not
count, even if the SSO session is alive. Only the user the request was addressed to can decide; another account
gets a 403 page.

The approval page shows the client, the user, a plain-language list of scopes, the binding message, the requested
resources, the network address the request came from and when, and a warning. Approve and Deny are CSRF-protected
POSTs. Approving adds the client to the SSO session, so ending that session (logout, admin revoke) invalidates
what the agent received, as for the device flow.

### 3. Token request (poll)

`POST /realms/{realm}/protocol/openid-connect/token` with
`grant_type=urn:openid:params:grant-type:ciba` and `auth_req_id`, authenticated as the client.

| Answer | Meaning |
|---|---|
| `authorization_pending` | not decided yet; keep polling at `interval` |
| `slow_down` | polled too fast; the interval grew by 5 seconds (max 300). Use the new value. |
| `access_denied` | the user denied |
| `expired_token` | the request expired |
| `invalid_grant` | unknown, used, or another client's `auth_req_id`; user disabled or session ended since |
| `unauthorized_client` | CIBA was switched off for the client, or it is public |
| `200` | `access_token` and `id_token`, **no refresh token** |

Tokens are issued once: the row is deleted by the request that issues them.

There is deliberately no refresh token and no `offline_access`: for the "approve one action" use case the agent asks
again, and the person approves again, for the next action. The access token's lifetime is the realm's.

## No user enumeration

The response to a backchannel request does not depend on the `login_hint`: unknown names, disabled users, users
without an email address, unverified addresses (when the realm requires verification) and ambiguous email hints all
get the same `200` with the same shape and the same interval, and a poll then answers `authorization_pending` until
the request expires. Mail is sent in the background, so response time does not include the mail system. The
per-hint rate limit (below) applies to every string alike.

Honest limit: timing is not constant-time. A hint containing `@` that is not a username costs an extra lookup, and
only an authenticated, opted-in client can call the endpoint at all, within the limits below.

## Security properties

- Only confidential, enabled, **opted-in** clients; checked at the endpoint, the token endpoint and the approval page
  (switching the opt-in off kills pending requests and links).
- `auth_req_id` and the approval token: 256 bits, stored only as sha256; never logged; not in audit detail.
- Single use, expiry (default 120 s, max 600 s), server-enforced polling interval with `slow_down`.
- Decision is an atomic compare-and-set on `pending` and the addressee's user id: one winner among concurrent
  decisions, nobody but the addressee can decide, an unresolved request can never be approved.
- A fresh sign-in (5 minutes) is required to see or decide; a stale session is sent to login again.
- The approval page escapes everything (client name, binding message, resources), has a nonce'd CSP, `no-store`,
  `X-Frame-Options: DENY`. The email strips control characters from the client name.
- Rate limits (fixed 10-minute windows, shared across replicas, fail closed if the store errors): 60 requests per IP;
  5 requests per (client, `login_hint`); 5 approval emails per user across all clients (extra ones are dropped
  silently, the response is unchanged); 30 approval-page loads per IP and 600 per realm (token guessing).
- Audit events (auth events flag): `CIBA_AUTH_REQUEST` (scope and whether the hint resolved; visible to admins only),
  `CIBA_AUTH_REQUEST_ERROR`, `CIBA_APPROVE`, `CIBA_DENY`, `CIBA_TOKEN`.

## Configuration

Needs: a store with CIBA support (memstore, pgstore migration `0019_ciba.sql`) and a mailer
(`HAVEN_IDP_SMTP_*`, as for password reset; `haven-idp dev` uses its in-memory outbox). Without either, the endpoints
answer `501 feature_unavailable`, discovery does not advertise CIBA and the `haven-ciba` login client does not exist.

Discovery adds `backchannel_authentication_endpoint`, `backchannel_token_delivery_modes_supported: ["poll"]`,
`backchannel_user_code_parameter_supported: false` and the CIBA grant type.

## Admin API

```
GET /admin/v1/realms/{realm}/clients/{id}/ciba        -> {"enabled": false}
PUT /admin/v1/realms/{realm}/clients/{id}/ciba        {"enabled": true}
```

Enabling a public client or a service account is `400`. The opt-in is keyed by the client's internal id, so a deleted
and re-created `clientId` starts switched off. See `internal/idp/admin/SPEC.md`.

## Not yet

- **Ping and push modes.** Poll only; `client_notification_endpoint` and `client_notification_token` are not
  implemented.
- **No push notifications** to a phone or authenticator app: the approval request is an email link. An attacker with
  access to the user's mailbox still needs the user's password and second factor to approve, but email delay and
  phishing-style lookalikes are real limits of this channel.
- **Requested resources are shown, not enforced.** `resource` values are recorded and shown to the approver, but the
  issued access token's `aud` is still the client id. A resource server must not treat the displayed resources as a
  token restriction. (Making them the audience needs a change in the shared token issuer.)
- **`login_hint_token`, `id_token_hint`, `user_code`, signed authentication requests** are rejected.
- No `acr_values`; the binding message is not verified by anyone (it is shown labelled as the application's).
- No admin view of pending requests, no per-client lifetime or scope limits, no per-user opt-out.
- The hint lookup for email addresses scans a user search (capped); realms with very many users should hint by username.
- The in-memory (dev) store does not persist CIBA state across restarts.
- Not run against a CIBA conformance suite.
