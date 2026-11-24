# Shared signals: telling other systems what happened to a user

haven-idp is an OpenID **Shared Signals Framework transmitter**. When a session ends, an account is disabled,
a credential changes or a user's token claims change, haven-idp signs a small security event and pushes it to
the systems that registered for it (a SaaS app, a SIEM, a device-trust service), so they can react in seconds
instead of waiting for a token to expire.

## Specifications implemented

All are the final specifications of 29 August 2025.

| Specification | Version | What is implemented |
|---|---|---|
| OpenID Shared Signals Framework | 1.0 | Transmitter metadata, stream management, stream status, subject add/remove, verification event, push delivery |
| OpenID Continuous Access Evaluation Profile (CAEP) | 1.0 | `session-revoked`, `credential-change`, `token-claims-change` |
| OpenID RISC Profile | 1.0 | `account-disabled`, `account-enabled`, `credential-compromise`, `sessions-revoked` (deprecated by RISC 1.0, sent only when asked for) |
| Security Event Token (SET) | RFC 8417 | ES256 JWS signed with the realm key, `typ: secevent+jwt` |
| Push-Based SET Delivery over HTTP | RFC 8935 | `urn:ietf:rfc:8935`, `application/secevent+jwt`, 2xx = accepted |
| Subject Identifiers for Security Event Tokens | RFC 9493 | `opaque`, `email`, `iss_sub` (and the SSF `complex` subject for sessions) |
| Bearer token usage | RFC 6750 | receivers authenticate to the management API with a bearer token |

Event type URIs:

| Event | URI |
|---|---|
| CAEP session revoked | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` |
| CAEP credential change | `https://schemas.openid.net/secevent/caep/event-type/credential-change` |
| CAEP token claims change | `https://schemas.openid.net/secevent/caep/event-type/token-claims-change` |
| RISC account disabled | `https://schemas.openid.net/secevent/risc/event-type/account-disabled` |
| RISC account enabled | `https://schemas.openid.net/secevent/risc/event-type/account-enabled` |
| RISC credential compromise | `https://schemas.openid.net/secevent/risc/event-type/credential-compromise` |
| RISC sessions revoked (deprecated) | `https://schemas.openid.net/secevent/risc/event-type/sessions-revoked` |
| SSF verification | `https://schemas.openid.net/secevent/ssf/event-type/verification` |

## How it works

```
 admin ---- creates a receiver (name, audience, privacy options) ----> gets a token ONCE
 receiver -- Bearer token ---> /realms/{r}/ssf/stream   (create a stream: endpoint, events wanted)
 receiver -- Bearer token ---> /realms/{r}/ssf/subjects/add   (which users it wants to hear about)

 something happens to a user (logout, admin disables, password reset, TOTP removed ...)
    -> signal -> one signed SET per interested stream -> outbox (database)
    -> worker POSTs the SET to the receiver (retries with backoff) -> delivered | dead
```

* **Receiver** = a party the realm admin registered. It owns up to 5 streams. The admin decides whether it gets
  events for *all* users or only for subjects it registers, which event types it may ask for, and whether it may
  ask for **email** subject identifiers.
* **Stream** = one push endpoint plus the event types wanted and the subject format. Receivers create, read,
  update, pause and delete their own streams (and nobody else's).
* **Where the events come from.** A store decorator sees every user update and every session end, whichever code
  path performs them (login lockout bookkeeping is ignored). So the logout endpoint, the Admin API,
  password reset and a future "revoke" path all signal without each being edited:

  | What happens | Event |
  |---|---|
  | one session ended (logout, admin revoke) | `session-revoked`, subject = session + user (complex) |
  | all sessions of a user ended | `session-revoked` per session, and `sessions-revoked` once for streams that ask for it |
  | user disabled / enabled | `account-disabled` / `account-enabled` |
  | password set, reset or changed | `credential-change` (`password`, `create`/`update`/`delete`) |
  | TOTP enrolled / removed / admin reset | `credential-change` (`app`) |
  | passkey registered / removed | `credential-change` (`fido2-platform`; see Not yet) |
  | passkey signature counter went backwards (clone suspected) | `credential-compromise` (`fido2-platform`) |
  | admin reports a breach (`POST .../ssf/credential-compromise`) | `credential-compromise` |
  | roles, email, username or names changed | `token-claims-change` |

* **Delivery.** Each SET is signed once, stored in the `ssf_outbox` table and sent by a worker (`haven-idp
  serve` runs it; several replicas can run it, rows are leased). A POST that gets a 2xx is done. A network
  error, 5xx, 429, 408, 401 or 403 is retried with exponential backoff (10 s doubling to 1 h, up to 10 attempts,
  and never longer than 24 h after the event). Any other status (for example RFC 8935's `400`, "I rejected this
  SET") is final: the row becomes `dead`. A **paused** stream keeps its events (up to 24 h) and receives them
  when it is enabled again; a **disabled** stream receives nothing.

## Security properties

* **No secrets in SETs.** A SET carries the event type, a timestamp, a subject identifier and the members
  CAEP/RISC define. Never a token, a session cookie, a password hash, a TOTP seed or a credential id.
  Session ids are the opaque ids of the SSO session rows (the session cookie is hashed and is not in it).
* **Subject privacy.** Default is `opaque` (the user's id, the same value as `sub` in tokens). `iss_sub` is the
  same data with the issuer. `email` is only possible for receivers the admin marked `allowEmail`. Claims that
  identify a person (`email`, `email_verified`, `preferred_username`, `given_name`, `family_name`) in
  `token-claims-change` go **only** to `email` streams; an opaque stream still hears about role changes.
  A user without an email on an `email` stream falls back to `opaque`.
* **Receiver tokens** are 256-bit random values shown once, stored as sha256 only, looked up by hash and
  compared in constant time. Rotation kills the old token at once. A disabled receiver gets 403 and no events.
  A token only works in the realm of its receiver.
* **The push target is receiver-chosen, so it is treated as hostile (SSRF).** https only (http for loopback
  in `dev`), no credentials, fragments or control characters in the URL, no redirects, no proxy from the
  environment, and the destination IP is checked at dial time, after DNS, against private, loopback,
  link-local, CGNAT, cloud-metadata and reserved ranges (the same `safehttp` policy as back-channel logout and
  federation). Responses are never echoed back anywhere.
* **The receiver's own `authorization_header`** (what haven-idp sends *to* the receiver) is encrypted with
  `HAVEN_IDP_SECRET_KEY` (AES-256-GCM, bound to realm and stream) and never returned by any API or logged.
  Without that key, setting a header is refused (409) rather than stored in the clear.
* **Rate limits** (shared across replicas): 300 management calls per minute per IP and realm, 120 subject
  lookups per minute per receiver, and one verification event per 30 s per stream (`min_verification_interval`).
  The store failing means the request fails closed (503).
* **No account-existence oracle.** `subjects/add` and `subjects/remove` answer the same for a user that exists
  and one that does not (and for an email that matches zero or several users); nothing is recorded for the
  latter. A stream of an `AllSubjects` receiver cannot remove subjects.
* **Off unless fully wired.** The endpoints answer 404 unless the store supports shared signals *and* the
  transmitter is running (otherwise nothing could ever be emitted). `haven-idp serve` and `dev` enable it
  whenever the store supports it; the memory store and Postgres both do.

## Endpoints

Metadata (public): `GET /.well-known/ssf-configuration/realms/{realm}` (SSF 1.0 section 7.2.1, the issuer path
appended) and the same document at `GET /realms/{realm}/.well-known/ssf-configuration`. Behind a path-rewriting
proxy only the second may be reachable.

All other calls need `Authorization: Bearer <receiver token>` and live under `/realms/{realm}/ssf/`:

| Call | Meaning |
|---|---|
| `POST stream` | create a stream (201). Body: `delivery {method: urn:ietf:rfc:8935, endpoint_url, authorization_header?}`, `events_requested?`, `description?`, `haven_subject_format?` (`opaque` default, `iss_sub`, `email`) |
| `GET stream[?stream_id=]` | one stream, or an array of the receiver's streams |
| `PATCH stream` / `PUT stream` | merge / replace (`stream_id` in the body or query). `PUT` needs `delivery.endpoint_url` |
| `DELETE stream?stream_id=` | 204 |
| `GET status?stream_id=`, `POST status` | `{stream_id, status: enabled|paused|disabled}` |
| `POST subjects/add`, `POST subjects/remove` | `{stream_id, subject}` with an `opaque`, `email` or `iss_sub` subject; 200 / 204 |
| `POST verify` | `{stream_id, state?}` queues a verification event, 204 |

`events_requested` may name any event type; unknown ones are ignored. `events_delivered` is what the receiver is
actually allowed and given (requested, limited by the admin's list for that receiver). With no request, a stream
gets everything its receiver may have except the deprecated `sessions-revoked`.

## Admin API

All under `/admin/v1/realms/{realm}/ssf/` (see `internal/idp/admin/SPEC.md`): `POST receivers` (returns the
token once), `GET receivers`, `DELETE receivers/{id}`, `POST receivers/{id}/rotate-token`,
`PUT receivers/{id}/disabled`, `GET streams`, `DELETE streams/{id}`, `GET outbox` (counts of pending, delivered
and dead SETs), and `POST /users/{id}/ssf/credential-compromise` to report a RISC credential compromise.

```bash
# 1. admin: register a receiver (token printed once)
curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  $IDP/admin/v1/realms/acme/ssf/receivers -d '{"name":"siem","allSubjects":true}'
# 2. receiver: create a stream
curl -s -X POST -H "Authorization: Bearer $RX_TOKEN" -H 'Content-Type: application/json' \
  $IDP/realms/acme/ssf/stream \
  -d '{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://siem.example/events"}}'
# 3. receiver: check the path works
curl -s -X POST -H "Authorization: Bearer $RX_TOKEN" -H 'Content-Type: application/json' \
  $IDP/realms/acme/ssf/verify -d '{"stream_id":"...","state":"hello"}'
```

## Configuration

No new settings. `HAVEN_IDP_SECRET_KEY` is needed only if a receiver wants haven-idp to send an
`authorization_header`. The SSRF policy is strict in `serve`; `dev` relaxes it (http to loopback and private targets) like
back-channel logout, and there is no switch for it in `serve`. Postgres migration `0021_shared_signals.sql`.

## Not yet

* **Poll delivery** (RFC 8936). Only push is offered; metadata lists only `urn:ietf:rfc:8935`.
* **Receiver side.** haven-idp does not consume signals from other transmitters.
* **`stream-updated` events**, `inactivity_timeout`, and stream `format`/`txn` members.
* **`token-claims-change` subject.** CAEP says the subject identifies the *token* (`jwt_id`); haven-idp sends
  the user (it cannot know which of a user's tokens a receiver holds). The change is reported once per update,
  not per token, and role grants that expire (time-boxed access) do not signal when they lapse.
* **Passkey credential type.** Passkey events say `fido2-platform` because haven-idp does not record whether a
  passkey is a platform or roaming authenticator.
* **Admin-initiated `account-disabled` reasons** (`hijacking`, `bulk-account`) and `initiating_entity` /
  `reason_admin` on session events: not recorded. A user-initiated logout is signalled as `session-revoked`.
* **Not signalled:** user deletion (RISC `account-purged`), refresh-token reuse detection, brute-force lockout.
* **Persistence in `dev --persist`.** The memory store's snapshot does not include receivers, streams or the
  outbox; they are lost on restart (Postgres keeps them).
* **Delivery ordering and at-least-once.** Events of one stream are sent concurrently and can arrive out of
  order; a crash between a send and recording it re-sends (receivers must dedupe on `jti`). A crash between a
  change and the enqueue loses that signal (the outbox is not in the same transaction as the change).
* **Tested against** haven-idp's own test receiver and `curl`, not against a commercial receiver.
