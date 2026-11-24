# Login fallback and risk-based step-up

Two small, opt-in, per-realm login features (Postgres migration `0013_stepup.sql`; the in-memory store has
them too). Both are **off** until an administrator sets the policy, and both only ever add friction or choose
among factors the user already has. Neither one issues a code or a session on its own.

## 1. "Use another method" on the passkey and TOTP steps

A user who has **both** a passkey and an authenticator (TOTP) is, by design, asked for the passkey first
(phishing resistant). If the passkey is unavailable (lost phone, other browser), the passkey page offers
*Use an authenticator code or recovery code instead*; the code page offers *Use a passkey instead*.

How it works, and what it cannot do:

- The button posts a signed, 10 minute `fallback` proof: "the password step passed for this user, for this
  authorization request, and the user chose method X". The server then renders **the ordinary step page of
  method X**. The code or assertion is checked by exactly the same code as before: TOTP step replay
  protection, recovery codes single use, passkey challenge consumed once, sign-counter regression, per-IP and
  per-user rate limits all unchanged.
- No step can be skipped: the password step has already passed (the proof cannot be forged without the server
  key), and the fallback proves nothing about the second factor. Completing the login still needs a valid
  code, recovery code or passkey assertion.
- It only chooses among **enrolled** methods. The target is re-checked on the click (TOTP confirmed and the
  secret key present; at least one passkey and passkeys on). A user with only one method sees no button.
- The proof is bound to the user, the authorization request (query string) and the target; wrong realm, other
  purpose, other user, tampered, expired or a method other than `totp`/`passkey` are rejected. The realm
  policy `allowFallback` is re-read on the click; a user disabled/locked meanwhile is turned away.
- The click itself is CSRF protected, rate limited per IP (30 per 10 minutes, fail closed on a store error) and
  audited (`MFA_FALLBACK`, detail `to:totp` or `to:passkey`).
- Off by default (`allowFallback: false`): then a user with both factors keeps today's behaviour (passkey
  only, a recovery code cannot be used).

**Security trade-off, stated plainly:** with `allowFallback` on, an attacker who has a victim's password and
can phish a TOTP code can use the TOTP path even though the victim also has a passkey. The passkey-first order
no longer protects against that. If your threat model needs passkey-only users to be immune to phishing, leave
fallback off and use admin reset (`DELETE /users/{id}/mfa`) for lost authenticators.

## 2. Risk-based step-up

A pure function, `core.DecideStepUp(policy, signals) -> {Required, Reasons}`, decides whether the realm policy
asks for stronger authentication. It has no I/O and no clock; the handlers compute the signals. Table tests
cover every rule and boundary (`internal/idp/core/stepup_test.go`).

### Policy (per realm)

| Field | Meaning |
|---|---|
| `enabled` | evaluate signals at all. Off: nothing is evaluated, **no device cookie is set and nothing is stored** |
| `enforce` | act on the decision. `enabled` without `enforce` is **report-only**: the decision is audited (`STEPUP_REPORT`), devices are learned, users are not affected. Use it to roll out and to learn devices before enforcing |
| `onNewDevice` | no known-device record for this user matches the browser's device cookie |
| `onIpChange` | client network differs from the last login's (login) or the session's (SSO) |
| `idleAfterSeconds` | at least this long since the user's last login (login) or the session's last activity (SSO). 0 = off |
| `onMaxAge` | the client sent `max_age` (it asked for fresh authentication) |
| `sensitiveScopes` | scopes that need step-up (only scopes the server knows: `openid profile email roles offline_access`) |
| `sensitiveAuthMaxAgeSeconds` | authentication older than this no longer counts for sensitive scopes (SSO reuse). 0 = every request needs a real login |
| `allowFallback` | section 1 |

### What happens when the policy fires (and `enforce` is on)

- **Silent SSO re-login** (`GET /auth` with a live session): the session is *not* reused. The user gets the
  normal login page and signs in interactively, with their factors; `prompt=none` answers `login_required`.
  This is where cookie theft shows up: a stolen `haven_sso` cookie without the matching `haven_device`
  cookie, or used from another network, no longer silently mints codes.
- **Interactive login**, after the password step: if the user has a factor, the existing passkey/TOTP steps
  already challenge them (always, with or without policy), so nothing weaker is possible. If the user has
  **no** factor the server forces TOTP enrollment now (same enrollment pages as the `requireMfa` policy). If
  that is impossible (no `HAVEN_IDP_SECRET_KEY`) the login is **refused** with 503, never completed on the
  password alone.
- Any error reading the policy or the signals **fails closed**: SSO is not reused, an interactive login gets a
  500 page.

### Signals and how they are computed

- *Known device*: a random 256 bit cookie `haven_device` (HttpOnly, SameSite=Lax, Path `/realms/{realm}`, 400
  days, `Secure` when the issuer is https) set after every completed login while the policy is enabled. The
  server stores only `sha256` of it per (realm, user), with first/last seen, at most 20 per user (least recently
  seen dropped). A cookie known for another user does not count; a malformed one is ignored. It is a signal,
  not a credential: presenting it grants nothing.
- *IP change*: IPv4 /24 or IPv6 /48 prefix compared with the previous login (stored as a salted hash, not the
  address) or, for SSO, with the address recorded on the session. An unparseable address, or no baseline,
  counts as changed.
- *Idle*, *sensitive scope*, *max_age*: from the clock, the session, and the request.
- A user's very first login has no baseline: with `onNewDevice` or `onIpChange` enforced it counts as new.
  Enable report-only first so existing users' devices are learned before enforcing.

### Signals that are NOT used (be honest about the limits)

No geolocation or country, no ASN, VPN, Tor or IP reputation, no user-agent or browser fingerprint, no
impossible-travel, no login velocity or failed-attempt history beyond the existing lockout, no breached
credential signal, no device attestation, no behavioural or ML scoring, no per-client or per-user policy
(realm wide only). Things to know:

- The device cookie is a plain cookie: malware or an attacker who copies the whole browser profile copies it
  too; clearing cookies, a private window or a second browser looks like a new device. Browsers that block
  cookies make every login "new" (and fill the 20-device cap).
- IP comparison uses the address the server sees. Behind a proxy it is only meaningful with `TrustProxy`
  configured correctly; otherwise every user shares the proxy's address and it never changes. Mobile users
  change networks often, so `onIpChange` generates friction.
- The stored IP hash is pseudonymisation, not secrecy: the IPv4 /24 space is small enough to enumerate from
  the hash. The admin API never returns it.
- Step-up does not run for federated (upstream IdP) logins: they end in the same session start but local
  second-factor steps are not run for them today. It does remember the device for them.
- Device-flow (RFC 8628) logins use the normal login page and so get the interactive behaviour.
- Refresh-token use and back-channel calls are not re-evaluated; a step-up decision applies only at
  `/auth`.
- ID tokens carry no `acr`/`amr` showing that step-up happened.

## Admin API

See `internal/idp/admin/SPEC.md` ("Login fallback and step-up").

```sh
# report-only first: learn devices, see what would happen
curl -X PUT $IDP/admin/v1/realms/acme/stepup-policy -H "Authorization: Bearer $T" -d '{
  "enabled": true, "enforce": false, "onNewDevice": true, "onIpChange": true,
  "idleAfterSeconds": 2592000, "sensitiveScopes": ["offline_access"], "sensitiveAuthMaxAgeSeconds": 900,
  "allowFallback": false }'
# later: "enforce": true
curl $IDP/admin/v1/realms/acme/users/$UID/devices            # id, firstSeen, lastSeen
curl -X DELETE $IDP/admin/v1/realms/acme/users/$UID/devices  # forget all of a user's devices
```

Audit events (when the realm logs auth events): `STEPUP_REQUIRED` / `STEPUP_REPORT` with detail
`login:` or `sso:` plus comma separated reasons (`new_device`, `ip_changed`, `idle`, `sensitive_scope`,
`max_age`); `MFA_FALLBACK`. No address, cookie or code is ever in an event.

## Not yet

Per-client or per-user rules, `acr`/`amr` claims, step-up for refresh tokens or token exchange, federated
logins, a user-visible "your devices" page or new-device email notification, geo/ASN/reputation signals,
a trusted-device lifetime separate from the cookie lifetime, an admin view of fallback usage beyond audit events.
Verified with software authenticators and unit tests; a real passkey was not used for the fallback round trip.
