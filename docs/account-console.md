# Account console

Every user has a page of their own at `/realms/{realm}/account`: where they are signed in, what has access to
their account, and what happened to it recently. It ties together the pages that already existed for two-step
verification, passkeys, email change and consents.

## Pages

| Page | Path (under `/realms/{realm}`) | What the user can do |
|---|---|---|
| Overview | `/account` | name, email, two-step and passkey status, counts, latest activity |
| Sessions | `/account/sessions` | see every live SSO session ("This device" marked), sign one out, sign out all others |
| Devices | `/account/devices` | see the browsers remembered by [risk-based step-up](login-fallback-and-stepup.md), forget one or all |
| Security | `/account/security` | entry points: password, [email](email-and-password-reset.md), [two-step verification](mfa-totp.md), [passkeys](passkeys.md) |
| Password | `/account/password` | change the password |
| Applications | `/account/applications` | see [consent grants](mcp-clients-and-consent.md), revoke one |
| Agents | `/account/agents` | see the [agent identities](agent-identities.md) the user owns and their credentials, revoke one or all of an agent's |
| Activity | `/account/activity` | the last 50 security events of the user's own account |

A menu beside the content (above it on narrow screens, down to 320 px) links the pages and the sign-out page.
The logout confirmation page, the device and CIBA "done" pages and the older account pages link to the console.

## Getting there

The console needs a **live SSO session** (the `haven_sso` cookie) of an enabled user, with a verified email when
the realm requires one. It has no sign-in form of its own: a user signs in to any application of the realm and
then opens `https://<idp>/realms/<realm>/account`. Without a session every page answers `401` with that
instruction.

## What the actions do

| Action | Effect |
|---|---|
| Sign out a session | the session is removed, its refresh tokens are revoked (not `offline_access` ones) and its applications get a [back-channel logout](sso-and-logout.md). A [Shared Signals](shared-signals.md) transmitter, when running, sends `session-revoked` |
| Sign out all other sessions | the same for every session except the one in use. The current one is ended with **Sign out** |
| Forget a device | the next sign-in from it counts as a new device. It does not sign anything out |
| Revoke application access | the grant ends, the user's refresh tokens for that client are revoked (offline ones included) and a consent receipt is appended. Access tokens already issued live until they expire |
| Revoke agent credential(s) | no new tokens from them. Access tokens already issued live at most 15 minutes |
| Change password | see below |

**Password change.** Needs recent authentication *and* the current password in the form, a new password that
differs from it and satisfies the realm's password policy (including the personal-information rules). Then:

1. the current session gets a **new cookie**, so a copy of the old cookie is useless. The session id (`sid`) stays,
   so the applications in this browser are not signed out of their own sessions;
2. **every refresh token** of the user is revoked, offline ones and those of the current browser included, so
   applications must ask again (silently, through the still-live SSO session);
3. every **other session** is ended with back-channel logout;
4. outstanding password-reset and email-change links are deleted;
5. a notice (no link, no password) is mailed when email is configured.

If the cookie cannot be replaced, the current session is ended too. If any other step fails the page says that the
password changed but not everything was signed out. Agent credentials are separate secrets and are **not** touched.
An account without a local password (federated, or passkey only) has no password form.

## Security properties

- **One user only.** The user id comes from the SSO session and from nowhere else; no parameter names a user. Every
  session, device, grant, agent and credential id in a form is looked up and checked against that user (a credential
  also against the agent). Somebody else's id gets exactly the answer of an id that does not exist (`404`), nothing
  is echoed back, and the submitted value is not logged. Lists are filtered by owner in the store and checked again
  in the handler. Devices are named by a per-user handle, never by the stored cookie hash.
- **Recent authentication** for every change: the session's own sign-in less than 10 minutes ago, or a confirmation
  on the page. The confirmation is a signed, 10 minute proof in an HttpOnly, SameSite=Strict cookie, bound to the
  user **and the session**. It is never weaker than signing in:
    - password, plus a current TOTP or recovery code when two-step verification is on;
    - a user who has a **passkey**, or no password, cannot confirm with a password: they sign out and sign in again.
- **CSRF**: every `POST` needs a double-submit token that is bound to the session (a token from another session, even
  of the same user, is refused). `GET` changes nothing.
- **Rate limits** (shared store counters, **fail closed** with `503` if the store errors): 120 page views per user
  per minute; 30 form posts per user and 60 per client address per 10 minutes; password checks 5 per user and 30 per
  address per 10 minutes. The per-user password counter is the same one the two-step verification page uses. A locked
  account (brute-force protection) cannot confirm. Failed confirmations do not themselves lock the account.
- **Pages**: `Cache-Control: no-store`, `X-Frame-Options: DENY`, CSP `default-src 'none'` with a nonce'd style and
  no script, the shared theme.
- **Activity** shows only an allow-list of event types for the user's own id, as fixed descriptions with time,
  client id and address. The event *detail* is never shown (it can name an administrator or internal ids), and
  administrative audit rows (`ADMIN_*`) never appear.
- **Fail closed**: without a store implementing `core.AccountStore` the console is `404`. Sections whose store is
  absent (devices, applications, agents) are `404` and left out of the menu.

## Audit events

`ACCOUNT_REAUTH`, `ACCOUNT_REAUTH_ERROR`, `ACCOUNT_SESSION_REVOKED`, `ACCOUNT_SESSIONS_REVOKED`,
`ACCOUNT_DEVICE_REMOVED`, `ACCOUNT_DEVICES_REMOVED`, `ACCOUNT_ACTION_ERROR` (refused change: not found, or
confirmation needed), `UPDATE_PASSWORD`, `UPDATE_PASSWORD_ERROR`, and the existing `CONSENT_REVOKE`,
`AGENT_CREDENTIAL_REVOKED` and `RECOVERY_USED`. They are written only when the realm records authentication events;
the activity page says so when it does not.

## Configuration and storage

Nothing to configure. The memory and PostgreSQL stores implement `core.AccountStore`
(`ListUserEvents`, `RotateSessionCookie`); migration `0024_account_events_index.sql` adds the index on
`events (realm, user_id, time)` that the activity page uses. Optional sections follow their own features: devices
need the step-up policy to be enabled to collect anything, applications list only remembered consent grants.

## Admin API

None added. Administrators keep using the session, device, consent and agent routes in
`internal/idp/admin/SPEC.md`.

## Not yet

- No sign-in from the console itself, and no confirmation with a passkey: a passkey user signs in again.
- Applications that never needed consent are not listed under Applications (they appear on their session). There is
  no way here to revoke the offline refresh token of such an application except by changing the password.
- Known devices carry no name or browser: only first and last sign-in and whether it is this browser.
- Agents: no creating, disabling or deleting agents and no issuing credentials; administrators do that.
- No profile editing (name), no account deletion or data export, no notification preferences.
- The older pages (`/account/totp`, `/account/passkeys`, `/account/consents`) keep their own rules: renaming a
  passkey and revoking on `/account/consents` do not ask for recent authentication there.
- Activity has no paging or filtering, shows no location, and is bounded by what the realm records.
- English only: the console is not in the [translation catalogue](branding-and-i18n.md) (it declares `lang="en"`),
  although the realm's logo, name, accent colours and footer links apply (footer link labels follow the browser's
  language). Session and activity times are UTC.
- Behind a reverse proxy under a path prefix the console, like the other account pages, is not supported.
