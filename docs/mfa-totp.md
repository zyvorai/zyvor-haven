# Two-step verification (TOTP) and recovery codes

haven-idp can require a second factor at login: a 6-digit code from an authenticator app (RFC 6238
TOTP, HMAC-SHA1, 30 second steps), with 10 single-use recovery codes for a lost phone. Users manage
it on an account page; admins can require it per realm and reset it for a user.

## Turning it on

The feature needs a secret key, because the TOTP seed has to be readable by the server (unlike a
password, it cannot be hashed):

```sh
haven-idp keygen                       # prints a key
HAVEN_IDP_SECRET_KEY=<key> haven-idp serve ...
```

`haven-idp dev` supplies a random per-process key. **Without a key the feature is off** (the
account pages answer 404 and the Admin API routes answer 409 with the key hint), with one
deliberate exception: it never quietly removes a factor someone depends on. If the key is missing
and the realm has `requireMfa` on, or the user has a confirmed TOTP credential, or the store cannot
say, the login is **refused** (HTTP 503, "Two-step verification is required for this account but is
currently unavailable"), the log names `HAVEN_IDP_SECRET_KEY`, and a `LOGIN_ERROR` audit event
`mfa_unavailable` is written. Users who never enrolled in a realm that does not require MFA are
unaffected. Recovery if the key is lost: service-account (client credentials) tokens still work, so
an admin can switch the policy off with `PUT /realms/{r}/mfa-policy` and reset a user's factors with
`DELETE /realms/{r}/users/{id}/mfa`. The same feature-off behavior applies to a store that does not
implement `core.MFAStore` (the in-memory and Postgres stores do; Postgres needs migration `0007`,
applied automatically).

Key rotation: `HAVEN_IDP_SECRET_KEY` takes several comma-separated keys, newest first; the first
seals, any can open (see `internal/idp/secretbox`).

## What users see

**Account page** `GET/POST /realms/{realm}/account/totp` (the user needs a live SSO session in the
realm; there is no link to it yet, applications or the console point users at the URL):

1. *Set up:* the page shows the secret (base32, no padding) and an `otpauth://totp/...` URI. There is
   **no QR code**: encoding one needs a QR encoder that is not in the standard library, and a
   hand-written one without a decoder to test it against did not meet the "small and well tested"
   bar. Type the secret into the app, or paste the URI where the app accepts one.
2. *Confirm:* the user enters a valid code. Only then is TOTP `confirmed` (until then it is never
   asked for at login). The 10 recovery codes (`XXXXX-XXXXX`) are then shown **once**, with a
   "save these now" notice.
3. *Turn off* and *new recovery codes* each need a current code or an unused recovery code. A new set
   invalidates the old one. An unfinished setup can be cancelled without a code.

Starting a setup, turning off and regenerating also need a recent login: if the SSO session's
`AuthTime` is older than 10 minutes the form asks for the account password as well. (The brief for
this feature said to redirect through `/auth` with `prompt=login`; an IdP page has no client and
redirect URI to send the user back with, so the password is asked on the page instead. Wrong
passwords are rate limited like codes.)

**Login.** After the password, a user with a confirmed credential gets a code page that accepts the
authenticator code **or** a recovery code in the same field. A recovery code works once.
If the realm policy `requireMfa` is on and the user has no confirmed credential, the enrollment
page is shown *inside* the login (secret, confirm code, recovery codes, then "continue"): there is
no way to finish the login without it. A silent SSO re-login (a live session) never runs these
steps; it already stands for a fully authenticated user.

## Security properties

- **Seed storage.** 20 random bytes, sealed with AES-256-GCM bound to `totp|{realm}|{userID}`. A
  sealed seed copied to another user or realm does not open (the login then fails closed with a
  server error; tested). Seeds are never logged, never in audit events and never in a response after
  the enrollment pages (tested by scanning every response and the log of a full flow).
- **Replay protection.** Each credential stores `lastUsedStep`. A code from a step at or below it is
  rejected, and the update is an atomic compare-and-set in the store (a conditional `UPDATE` in
  Postgres), so two parallel submissions of one valid code cannot both log in. The check accepts the
  current step and one step either side (clock skew). Codes are compared in constant time.
- **Recovery codes.** 10 codes, 50 bits each, from a 32 symbol alphabet without `0 1 I O`. Only
  sha256 hashes are stored; the plaintext exists once, on the page that shows them. Use is an atomic
  delete (exactly one of N parallel submissions wins). Regenerating replaces the whole set.
- **Brute force.** Every code attempt is counted before it is looked at: 5 per user per 10 minutes
  (counted since the last successful verification) and 30 per client IP per 10 minutes. Once the user
  limit is reached even the correct code is refused until the window passes, from any IP. A store
  error in the limiter fails closed (no login). Failures are audit events (`MFA_FAILED`, detail
  `invalid_code`, never the code). The wrong-code page is identical for TOTP-shaped and
  recovery-shaped input and does not say whether recovery codes exist.
- **Pending proof.** Between the password and the code the browser carries a signed token
  (`signPending`, purpose `mfa`) bound to the user, the realm and the exact authorization request,
  valid 5 minutes. The code page does not accept a code without it; a token from another realm,
  purpose, user or request is rejected. Tokens are bearer proofs of "the password step passed"; they
  grant nothing without a valid code (the "continue after recovery codes" proof is the exception: it
  proves a code was just confirmed for that very credential, and lasts 5 minutes).
- **No half-logged-in session.** Neither the code page nor the enrollment page creates an SSO session
  or an authorization code; a half-finished login cannot be resumed through the SSO cookie or by
  calling the continue endpoint directly.
- **Pages** are `Cache-Control: no-store`, CSRF protected and use a nonce'd CSP.
- Disabled, locked and unverified users never reach the step (existing checks run first) and are
  re-checked when the code is posted.

## Admin API

See `internal/idp/admin/SPEC.md`, section "MFA (TOTP) routes".

| Route | Purpose |
|---|---|
| `GET /realms/{r}/users/{id}/mfa` | `{totpEnrolled, totpPending, recoveryCodesRemaining}`; never a seed or code |
| `DELETE /realms/{r}/users/{id}/mfa` | reset (lost device): removes credential and recovery codes, ends the user's SSO sessions |
| `GET/PUT /realms/{r}/mfa-policy` | `{requireMfa}`; the policy is kept next to the TOTP tables, not in the realm record |

## Audit events

`TOTP_ENROLLED`, `TOTP_DISABLED`, `TOTP_RESET` (admin), `RECOVERY_USED`, `RECOVERY_REGENERATED`,
`MFA_FAILED`; a login completed with a second factor is `LOGIN` with detail `totp` or `recovery`.
Auth events are written when the realm has `AuthEventsLogged`.

## Not yet

- No QR code (see above).
- No link to the account page from anywhere; no account console.
- The code page is one field for TOTP and recovery codes, not a separate toggle.
- `acr`/`amr` claims are not added to tokens; clients cannot ask for or learn that a second factor
  was used.
- Only SHA1/6 digits/30 s (what authenticator apps support); no HOTP, SMS, email or push factors.
- `requireMfa` has no grace period and no per-client or per-role scoping.
- Disabling TOTP is allowed even when the realm requires it; the user is asked to enroll again at the
  next login.
- Deleting a user removes their MFA rows in Postgres (trigger); the in-memory store leaves unreachable
  rows. Deleting a realm cascades in Postgres.
- A user who loses both the device and the recovery codes needs an admin reset.
