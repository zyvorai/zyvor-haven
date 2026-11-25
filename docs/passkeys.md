# Passkeys (WebAuthn)

haven-idp supports WebAuthn credentials ("passkeys") in two roles:

- **First factor**: a "Sign in with a passkey" button on the login page. The
  browser offers a discoverable credential, the assertion's user handle names the
  user, user verification (PIN, biometric) is **required**, and no password is
  involved.
- **Second factor**: after a correct password, a user who has at least one
  passkey must answer a passkey challenge before any session or code exists.
  User verification is requested as `preferred` (not required) here, because the
  password already proved one factor; if the authenticator verifies the user
  anyway, fine.

Passkeys are managed by the user at
`/realms/{realm}/account/passkeys` and by administrators through the Admin API.

Everything is implemented with the Go standard library: a small CBOR decoder,
COSE key parsing (ES256, RS256, EdDSA) and the registration and assertion
verification of the WebAuthn specification live in `internal/idp/webauthn`. No new
dependency was added.

## Relying party configuration

| Setting | Default |
| --- | --- |
| `HAVEN_IDP_WEBAUTHN_RPID` | host of `HAVEN_IDP_BASE_URL`, without port |
| `HAVEN_IDP_WEBAUTHN_ORIGINS` (comma separated) | `scheme://host[:port]` of `HAVEN_IDP_BASE_URL` |

- An origin must match **exactly** (scheme, host and port). `https://idp.example.com`
  and `https://idp.example.com:8443` are different origins.
- Changing the RP ID later makes existing passkeys unusable (they are bound to it).
  The RP ID must be a registrable suffix of the origin's host, a browser rule.
- Browsers refuse IP addresses as RP IDs. With a loopback base URL
  (`haven-idp dev` uses `http://127.0.0.1:PORT`) the RP ID is `localhost` and both
  `http://127.0.0.1:PORT` and `http://localhost:PORT` are allowed origins; **open
  `http://localhost:PORT` in the browser** to use passkeys in dev (`localhost` is a
  secure context). A non-loopback IP base URL switches passkeys off.
- Passkeys are also off when the store does not implement the passkey store.

## Security properties

- **Challenges** are 32 random bytes inside a signed, 5 minute pending token (the
  token is bound to realm, purpose and, for second factor and registration, the
  user) **and** are single use: every verification attempt first records the
  challenge digest in the store (`passkey_challenges`, unique), so a captured
  registration or assertion cannot be verified twice, even by authenticators that
  always report a signature counter of 0. A store failure fails closed.
- **Origin, RP ID hash, ceremony type, challenge** are checked on every response;
  the challenge comparison is constant time. A `crossOrigin: true` or `topOrigin`
  client data is refused.
- **User presence** is always required; **user verification** is required for
  registration, for passkey-first login, and is requested for second factor.
  Registration requires UV so that every stored passkey can also be used as a
  first factor.
- **Signature counter**: if the stored and the presented counters are both
  non-zero and the presented one is not greater, the (otherwise valid) assertion is
  refused and a `PASSKEY_CLONE_SUSPECTED` event is written. Authenticators that
  always send 0 (most synced passkeys) are allowed. The stored counter is not
  advanced on a refused assertion.
- **Backup eligibility** must not change between registration and login.
- **Account state**: disabled users, users locked out by brute-force protection and
  users with an unverified email in a realm that requires verification cannot sign
  in with a passkey either. Failed passkey attempts do not increase the password
  lockout counter; they are rate limited instead (per IP and per user, fail closed
  when the limiter errors).
- **No oracle**: an unknown credential id, a wrong signature, a wrong user handle,
  an expired or replayed challenge, a disabled account and a rate limit all produce
  the same message ("Passkey sign-in failed..."). The audit event differs.
- **User handle** is a random opaque 32 byte value stored per user, never the
  username or email.
- **Public keys** are stored as the original COSE bytes; they are public values.
  Nothing secret is stored, so `HAVEN_IDP_SECRET_KEY` is not needed.
- **Attestation**: `none` and `packed` *self* attestation (signature by the
  credential key itself, algorithm must match) are accepted. Anything carrying a
  certificate chain (`x5c`), `ecdaaKeyId`, or another format (`tpm`, `android-key`,
  `apple`, ...) is **rejected** with a clear message. The pages always ask the
  browser for attestation `none`, so mainstream authenticators register normally.
- **Account page**: needs a live SSO session, CSRF-protected forms (double submit
  cookie scoped to the page path), `Cache-Control: no-store`, and a CSP that only
  allows the one inline script with that response's nonce. Adding and removing
  passkeys requires a recent authentication (the session's login within 10 minutes,
  or a password or passkey confirmation on the page bound to the session, valid 10
  minutes, rate limited). At most 20 passkeys per user.
- **The only JavaScript** is the static script in `internal/idp/oidc/passkeys_ui.go`.
  No server data is interpolated into it (options travel in a `data-opts`
  attribute and are parsed as JSON); the CSP has no `unsafe-inline`, no external
  script and no `connect-src`: the result of the browser ceremony is posted back
  with an ordinary form. Without WebAuthn support the passkey parts stay hidden.

## Interplay with other second factors

A user is challenged by the **first applicable step only**; the other factor is not asked. The
order is explicit, not an accident of file names: steps carry an order number
(`authOrderPasskey = 50` before the default `100` used by TOTP). So a user who has both a passkey
and a TOTP device is asked for the **passkey**, which is phishing resistant, where a phished
one-time code would not be. (`TestAuthStepOrdering` pins this.)

The cost is availability: a user whose browser or device cannot do WebAuthn is stuck at that step
(the page says so). A realm can offer "use another method" between a passkey and TOTP
([login fallback](login-fallback-and-stepup.md); never in a passkey-only realm); otherwise an admin
has to remove the passkey or reset the user's factors.

## Passkey autofill (conditional UI)

On the login page the username field carries `autocomplete="username webauthn"`
and, when the browser reports `isConditionalMediationAvailable()`, the page
script starts a `navigator.credentials.get` with `mediation: "conditional"`. The
browser then lists the user's passkeys in the field's autofill suggestions;
picking one signs in. Nothing appears otherwise.

- It never blocks password sign-in: the request is passive, every failure is
  silent, and the password form is an ordinary form that the script does not
  touch. Browsers without conditional mediation only get the button.
- The "Sign in with a passkey" button aborts the pending request before it starts
  its own (a page may have only one), and starts autofill again if the user
  cancels the dialog.
- It posts the same form as the button: same CSRF check, same challenge, same
  verification (user verification required). The challenge is **single use** and
  lives **5 minutes**. A passkey picked from a login page that has been open
  longer is refused with the generic message, and the page that answers carries a
  fresh challenge, so the second pick works.
- Only the login page does this. The second-factor step and the account page
  never start a conditional request.
- The CSP did not change: one nonce'd script, no `connect-src`.

## Confirming it is you on the account page

When the sign-in is older than 10 minutes, `/realms/{realm}/account/passkeys`
asks for the password **or** a passkey ("Confirm with a passkey"). The passkey
path requires user verification, accepts only a passkey of the signed-in user,
uses a single-use 5 minute challenge bound to that user **and that session**,
refuses a locked-out account, and shares the password path's rate limit (5 per
user and 10 per address in 10 minutes, together). Both unlock the page for 10
minutes for that session only. Without a registered passkey only the password is
offered.

## Passkey-only for users who have a passkey

A realm option, **off by default**:

```
PUT /admin/v1/realms/{r}/passkey-policy
{"requirePasskeys": false, "passkeyOnly": true}
```

(`requirePasskeys` absent means false, as before; `passkeyOnly` absent leaves it
unchanged.) For a user who has **at least one passkey** it means:

1. No sign-in completes without a passkey. The "use an authenticator code
   instead" fallback is not offered, a one-time or recovery code cannot finish
   the login, and a federated (upstream IdP) sign-in is refused with "Use your
   passkey".
2. Once **every** one of the user's passkeys has completed a sign-in **without a
   password**, the password is not accepted at all. The answer is the ordinary
   "Invalid username or password", the same for a right and a wrong password, and
   the login page shows (to everyone) a note that accounts with a passkey must use
   it.
3. The account passkeys page offers only passkey confirmation.

**Why "every passkey has been used without a password".** Registration asks for a
discoverable credential only as a preference. An authenticator that did not make
one works as a second factor but not from the "Sign in with a passkey" button, so
switching the password off at once could lock its owner out. Until each passkey
has proved it works alone, the password still leads to the passkey step, which is
mandatory. Sign-ins as a second factor and account page confirmations do not
count. Registering another passkey re-opens the password-then-passkey path until
the new one has been used alone.

**Lock-out rules.**

- A user **without** a passkey is never affected, also when passkeys are
  misconfigured.
- A user who loses a device that held a proven passkey cannot fall back to the
  password: an administrator deletes the passkey
  (`DELETE .../users/{id}/passkeys/{credId}`) or turns the option off.
- It fails closed: if the policy cannot be read the login fails, and if the
  relying party configuration becomes unusable, users with a passkey are refused
  (turn the option off to recover).
- Credentials registered before this release count as unproven until used once
  from the button or autofill.

**What it does not do.** It does not end existing sessions, does not remove
password hashes, does not stop password reset (the new password is just not
accepted for those users), and does not force anyone to register a passkey. Wrong
passwords still count towards brute-force lockout, which also blocks passkey
sign-in for the lock-out period. The TOTP account page and the email change page
still ask for the password.

## Realm policy

`PUT /admin/v1/realms/{r}/passkey-policy {"requirePasskeys": true}` makes the
account page refuse to remove a user's last passkey. It does not force users to
register one (no enrolment enforcement yet), and administrators can still delete
anything. (`passkeyOnly` is described above.)

## Events

`PASSKEY_REGISTERED`, `PASSKEY_LOGIN`, `PASSKEY_REMOVED`, `PASSKEY_FAILED` (with a
reason such as `unknown_credential`, `verification_failed`, `rate_limited`),
`PASSKEY_CLONE_SUSPECTED`. Details carry only a 12 character prefix of the
credential id (a public value), never keys or challenges. Admin deletions are
`ADMIN_DELETE passkey <username>`.

## Admin API

See `internal/idp/admin/SPEC.md`:

- `GET /admin/v1/realms/{r}/users/{id}/passkeys`
- `DELETE /admin/v1/realms/{r}/users/{id}/passkeys/{credId}` (does not end sessions)
- `GET|PUT /admin/v1/realms/{r}/passkey-policy`

## Storage

Migration `0008_passkeys.sql`: `passkeys` (unique `(realm, credential_id)`),
`passkey_user_handles`, `passkey_challenges`, `passkey_realm_policy`. The memory
store implements the same `core.PasskeyStore`; the conformance cases are in
`internal/idp/store/storetest/passkeys.go`. Challenge rows are purged lazily when a
new challenge is consumed. Migration `0025` adds `passkey_signin_policies` (the
passkey-only option) and `passkey_passwordless` (which credentials have signed in
without a password; deleted with the credential), behind `core.PasskeyOnlyStore`.
A store without it does not have the option.

## Testing and honest limits

- The verifier is tested with software authenticators built in the test
  (`webauthntest`: real CBOR, authenticator data, ECDSA, RSA and Ed25519
  signatures) including negative cases for every check, a CBOR fuzz test and
  limits tests. The handlers are tested through the real login flow.
- A real end to end run was done against `haven-idp dev` with headless Chrome and
  the DevTools virtual authenticator (`WebAuthn.addVirtualAuthenticator`): register,
  passkey-first login, password plus passkey, removal. A virtual authenticator is
  not real hardware: **no physical security key, platform authenticator, Safari,
  Firefox or phone (hybrid/caBLE) flow was tested.** Cross-device flows depend on
  the browser.
- A second run of the same kind covered conditional mediation (the request starts,
  stays pending without user presence, the virtual authenticator answers it, the
  button aborts it, password sign-in and the second-factor step work while it is
  pending), account page re-authentication and the passkey-only option. The
  virtual authenticator answers a conditional request by itself: **the autofill
  list itself, and picking a passkey from it, were not seen or tested.** The
  refusal of a re-authentication without user verification happened in the
  browser; the server-side check is covered by the Go tests.

## Not yet

- Attestation formats beyond `none` and packed self attestation. There is no FIDO
  Metadata Service, no enterprise attestation and no certificate chain validation.
- Enrolment enforcement; passkey-only accounts (password removal).
- Passkey re-authentication on the other account pages (TOTP, email change), and
  a way to reach the account page without first signing in through an application.
- Requiring a discoverable credential at registration.
- Config as code and console support for the passkey policies.
- Non-minimal CBOR integer encodings are tolerated; algorithms other than ES256,
  RS256 (>= 2048 bit) and EdDSA are refused (no ES384/512, no RS384).
- The challenge marker table has no background purge job beyond the lazy purge.
