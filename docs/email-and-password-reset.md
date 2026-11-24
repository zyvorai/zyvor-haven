# Email verification and password reset

haven-idp can email users two single-use links: one that **verifies the address on file**, one that
**resets a forgotten password**. Both are off until you configure an SMTP server. Without SMTP the
login page shows no "Forgot your password?" link, the `login-actions` pages answer 404, and the admin
send routes answer 409.

## Flows

**Forgot password.** The login page links to
`/realms/{realm}/login-actions/forgot-password`. The user enters a username or email address. If it
matches exactly one account that is enabled and has an email address, a reset link goes to the address
on file. The page gives the same answer in every case.

**Reset.** The link opens `/realms/{realm}/login-actions/reset-password?token=...`, which shows a
form. Submitting a new password (checked against the realm's password policy) changes it, clears any
brute-force lockout, marks the email address verified, ends all of the user's refresh tokens, and
deletes any other outstanding reset links.

**Verify email.** When a realm requires verified email and a user signs in with the **correct**
password but an unverified address, sign-in is refused and a verification link is sent to the address
on file. The link opens `/realms/{realm}/login-actions/verify-email?token=...`; pressing the button
marks the address verified. A **wrong password never triggers an email**, so nobody can use the login
form to spam a mailbox.

Administrators can send either link on demand (see [Admin routes](#admin-routes)). This is also how
users imported from Keycloak with unverified addresses get unblocked
(see [import-from-keycloak.md](import-from-keycloak.md#unverified-emails-check-this-before-cut-over)).

## Security properties

* **No account enumeration.** The forgot-password page returns the same page and status whether the
  account exists, is disabled, has no email, or was rate limited. Mail is sent in the background, so
  response time does not leak either.
* **Single use, stored hashed.** Tokens are 256 random bits. Only a sha256 hash is stored; redeeming
  deletes it. A used, unknown, expired, wrong-purpose or wrong-realm link all give the same "invalid
  or expired" page.
* **A GET never consumes a link.** Mail scanners and link previewers fetch URLs before the human does,
  so the link only shows a form; the token is redeemed on the POST (which also needs a CSRF token).
  A mistyped or policy-failing new password does not burn the link.
* **Bound to the address.** A token records the address it was sent to. If the address on the account
  changes, or the user is disabled or deleted, the link stops working.
* **Expiry.** Reset links last 1 hour, verification links 24 hours.
* **Rate limits.** At most 3 emails per user and purpose in any rolling hour (the 4th attempt is
  refused; earlier links stay valid). The forgot-password form is also limited per client IP (10
  requests per 10 minutes). An undelivered email (SMTP error) deletes its token.
* **Reset ends sessions.** Refresh tokens are revoked on a successful reset, since the old password
  may be compromised.
* **Secrets stay out of logs and API.** The link is never returned by the admin API, written to the
  audit trail, or logged; SMTP failures are logged without the message body.

## Configuration

Set on `haven-idp serve`. Email is enabled when `HAVEN_IDP_SMTP_HOST` is set.

| Variable | Meaning |
| --- | --- |
| `HAVEN_IDP_SMTP_HOST` | SMTP server host name. Empty disables email. |
| `HAVEN_IDP_SMTP_PORT` | Port (typically 587 for `starttls`, 465 for `implicit`, 25 for `none`). |
| `HAVEN_IDP_SMTP_USER` | Username for SMTP authentication. Leave empty for no authentication. |
| `HAVEN_IDP_SMTP_PASSWORD` | Password. Prefer the `_FILE` form. |
| `HAVEN_IDP_SMTP_PASSWORD_FILE` | Path to a file holding the password (for example a mounted Secret). |
| `HAVEN_IDP_SMTP_FROM` | Sender address, for example `Haven <no-reply@example.com>`. |
| `HAVEN_IDP_SMTP_TLS` | `starttls` (default), `implicit` (TLS from the first byte) or `none`. Use `none` only on a trusted network. |

Links are built from the public base URL of haven-idp, so make sure it is the externally reachable
HTTPS address.

## Admin routes

Both need the admin token like every other Admin API route and return **204** with an empty body.
The link goes only to the address on file for the user; it is never in the response.

| Route | Sends |
| --- | --- |
| `POST /admin/v1/realms/{r}/users/{id}/send-verify-email` | verification link |
| `POST /admin/v1/realms/{r}/users/{id}/send-reset-email` | password reset link |

| Status | Meaning |
| --- | --- |
| 400 | user has no email address, or is disabled |
| 401 / 403 | missing or invalid admin token / not an admin |
| 404 | unknown user |
| 409 | email is not configured |
| 429 | more than 3 emails to this user for this purpose in the last hour |
| 502 | the SMTP server rejected or failed the send (no usable link remains) |

Each successful send is recorded as an `ADMIN_ACTION` event (user name only, no link). The Go client
`internal/idp/native` exposes them through the optional `idp.UserMailer` interface.

## Not yet

* No per-realm templates or branding: one built-in text/HTML template per message.
* No per-realm SMTP: one server for the whole haven-idp instance. This is deliberate: per-realm
  SMTP would put mail credentials in the realm model, which config as code exports and the
  console displays.
* The reset link's GET page shows the form without checking the token, so an expired link is only
  reported after the user submits a new password.
* Email-change verification is wired into the Admin API (`PUT /users/{id}`). There is no
  self-service "change my email" page yet.
* Limiter windows are fixed, not sliding: a client can send up to twice the limit across a window
  boundary.

## Also in this release

* **Password-changed notice.** After a reset (by link or by an administrator) the address on file
  gets a notification with the time and how it happened. It never contains a link or the password.
* **Email-change verification.** Changing a user's address through the Admin API marks it
  unverified (unless the request explicitly sets `emailVerified: true`), kills links sent to the
  old address, and sends a verification link to the new one only.
* **Shared limits.** The per-IP forgot-password limit is stored in the database, so it holds across
  replicas and restarts. Keys are hashes of realm and IP; raw addresses are not stored.
