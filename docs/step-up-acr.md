# Authentication context and step-up (`acr`, `amr`, RFC 9470)

haven-idp puts into ID tokens and access tokens **what actually happened** when the user signed in, lets a client
demand a minimum level, and refuses rather than hand out less than was asked for. It follows
[RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) (OAuth step-up authentication challenge) and the `acr_values`
and `claims` request parameters of OpenID Connect Core.

## Claims

| Claim | Meaning |
|---|---|
| `amr` | the methods haven-idp itself observed (table below) |
| `acr` | the level those methods reach on the realm's ladder |
| `auth_time` | when the user authenticated; never moved by refresh or silent re-login |

| How the user signed in | `amr` | default `acr` |
|---|---|---|
| password | `pwd` | `urn:haven:acr:1fa` |
| password + TOTP code (also right after enrolling it) | `pwd otp mfa` | `urn:haven:acr:mfa` |
| password + recovery code | `pwd recovery mfa` | `urn:haven:acr:mfa` |
| password + passkey, authenticator did not verify the user | `pwd webauthn user mfa` | `urn:haven:acr:phr` |
| password + passkey with user verification | `pwd webauthn user uv mfa` | `urn:haven:acr:phr` |
| passkey alone (passwordless; user verification is mandatory) | `webauthn user uv mfa` | `urn:haven:acr:phr` |
| upstream identity provider (federation) | `fed` | `urn:haven:acr:1fa` |
| silent SSO re-login, device approval, CIBA approval | those of the **original** sign-in of that session | derived from them |

`pwd`, `otp`, `user` and `mfa` are registered values ([RFC 8176](https://www.rfc-editor.org/rfc/rfc8176)).
`recovery`, `webauthn`, `uv` and `fed` are private values: no registered value says the same without claiming more
than was seen. In particular `hwk`/`swk` are not used (without trusted attestation the server cannot tell a hardware
key from a synced one), and nothing the upstream provider says about its own `amr`/`acr` is copied or trusted.

Service accounts (`client_credentials`), agent and workload token exchanges involve no user sign-in: they carry
none of these claims. **userinfo** returns `acr` and `auth_time` of the token; **introspection** returns `acr`,
`auth_time` and `amr` for access tokens, and `acr` and `auth_time` for refresh tokens.

## The ladder

An ordered list of levels, weakest first. A level is reached when `amr` contains every method of at least one
alternative in `anyOf`; reaching a level satisfies all levels below it. The default:

```json
{
  "levels": [
    {"acr": "urn:haven:acr:1fa", "anyOf": [["pwd"], ["fed"], ["webauthn"]]},
    {"acr": "urn:haven:acr:mfa", "anyOf": [["mfa"]]},
    {"acr": "urn:haven:acr:phr", "anyOf": [["webauthn", "mfa"]]}
  ],
  "enrollOnStepUp": false
}
```

Change it per realm with `PUT /admin/v1/realms/{r}/acr-policy` (`DELETE` restores the default). For example, to not
count recovery codes as a second factor, give the middle level `[["pwd","otp"],["webauthn","mfa"]]`; to require
user verification for the top level use `[["webauthn","uv"]]`. Up to 10 levels; values are printable ASCII without
spaces, quotes or backslashes.

## Asking for a level

At the authorization endpoint (also inside a pushed request or a signed request object):

* `acr_values`: space separated, in order of preference; any one of them is enough.
* `claims`: `{"id_token":{"acr":{"essential":true,"values":["..."]}}}`. `value` works like a one-element `values`;
  `userinfo` and `access_token` members are read the same way; `{"essential": true}` without values demands that
  some level is reached. Other members of `claims` are ignored.
* `max_age`: as before; the sign-in must be that recent.

**Every named value is binding**, essential or not (RFC 9470 section 5). When several of these are present, all
must be met. A stronger sign-in satisfies a weaker demand, and the `acr` claim then reports the **requested** value
(the first met value of the `claims` entry, else of `acr_values`); with no demand it reports the highest level
reached.

| Situation | Answer |
|---|---|
| no value is on the realm's ladder | `unmet_authentication_requirements` at once, before any login |
| SSO session meets the demand | silent re-login, original `amr` and `auth_time` |
| session too weak, `prompt=none` | `login_required` |
| session too weak or absent | the login page; the password step is followed by the factor that can reach the level |
| the user's factors cannot reach it | `unmet_authentication_requirements` after the password step; no code |
| user has no second factor, `enrollOnStepUp: true` (or the realm's `requireMfa`) | TOTP enrollment during the login |
| malformed or repeated `acr_values` / `claims` | `invalid_request` |

Rules that keep a demand from lowering security:

* A user who has a passkey is challenged with the passkey. A request parameter never makes the server substitute
  TOTP, and no authenticator is ever added to an account that already has a second factor.
* `enrollOnStepUp` is **off by default**: with it on, someone who knows only the password of a user without a second
  factor can enroll their own authenticator and obtain an `mfa` token. That is also what `requireMfa` does.
* Every authorization code passes one final gate that compares the session's recorded methods with the demand,
  whichever path led there (password, factor steps, the "use another method" button, passkey, federation, consent).
* Federated sign-ins reach only what the ladder gives `fed`. Local second factors are not run after an upstream
  login, so a higher demand through "Continue with ..." fails.
* The device flow cannot enforce a demand: `acr_values` or `claims` on the device authorization request are
  `invalid_request`. [CIBA](ciba.md) accepts `acr_values` and requires the approver to meet them.

Signing in again to step up replaces the browser's SSO session, exactly like `prompt=login`: the old session ends
(its clients get back-channel logout, its online refresh tokens are revoked).

## Refresh tokens and policy changes

The context is fixed at the sign-in and travels inside the code and refresh token strings
(`<random>~<resources>~<context>`; only the sha256 of the whole string is stored, so it cannot be edited).

**A refresh never raises a level, and never silently keeps or lowers one.** At every code exchange and refresh the
grant is checked against the ladder **as it is now**: the `acr` it reports, and whatever the authorization request
demanded, must still be reached by its `amr`. If not (a level removed, tightened or renamed) the request fails with
`400 invalid_grant` ("the authentication level of this grant no longer satisfies the realm policy; sign in again"),
nothing is issued and the token is not consumed; introspection reports such a refresh token as inactive. A ladder
that would now rate the same methods higher changes nothing: the grant keeps its original `acr`. If the policy
cannot be read the request fails (`500`), it is never skipped.

Access tokens already issued keep their claims until they expire.

## For resource servers (RFC 9470)

Check `acr` (and `auth_time` for recency) in the JWT access token or the introspection response. The values are not
numbers: accept the set you mean (for "at least multi factor" with the default ladder: `urn:haven:acr:mfa` or
`urn:haven:acr:phr`; haven-idp reports the value the client asked for, so a client that asked for `mfa` gets `mfa`
even if it used a passkey). When the token is not enough, answer:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A different authentication level is required",
  acr_values="urn:haven:acr:mfa", max_age="300"
```

The client puts `acr_values` and `max_age` into a new authorization request. Send the challenge only to callers
whose token you validated, so requirements are not disclosed to strangers. A DPoP resource uses the same error
and parameters with the `DPoP` scheme.

### haven-idp's own example: the Admin API

On the Admin API's realm the policy may set `adminAcr` and/or `adminMaxAgeSeconds`. **User** tokens (the
`haven-admin` role) must then meet that level, judged from `amr` under the current ladder, and be that fresh, or get
the challenge above. Service account tokens are not affected: they have no user authentication, and they are the way
back in if the requirement is one nobody can meet. Off by default.

```
curl -X PUT -H "Authorization: Bearer $ADMIN" .../admin/v1/realms/platform/acr-policy -d '{
  "levels": [ ... ], "adminAcr": "urn:haven:acr:mfa", "adminMaxAgeSeconds": 900 }'
```

## Discovery

`acr_values_supported` (the realm's ladder, weakest first), `claims_parameter_supported: true` (only the `acr`
member is honoured), and `acr`, `amr` in `claims_supported`. Absent when the store cannot keep the context.

## Storage and upgrade

Pg migration `0022_authn_context.sql`: `realm_acr_policy` and `session_authn` (one immutable row per SSO session,
deleted with it). A store without `core.AuthnStore` leaves the feature off: no `acr`/`amr`, and any demand fails.

On upgrade:

* Sessions created before have no record. They are still reused when nothing is demanded (tokens then carry
  `auth_time` only) and never satisfy a demand. Existing refresh tokens carry no `acr`/`amr` and keep working.
* **Behaviour change:** `acr_values` and `claims` used to be ignored. A client that sends values which are not on
  the realm's ladder now gets `unmet_authentication_requirements`. Remove the parameter or add the values to the
  ladder.
* A failure to record the methods of a login fails that login.

## Not yet

* No per-client or per-scope minimum level (`default_acr_values`); only the request, and the Admin API setting.
* Upstream `acr`/`amr` are neither requested (`acr_values` is not forwarded) nor mapped; no local step-up after a
  federated login.
* A user with both a passkey and another factor cannot be sent to the other factor by a request, even on a custom
  ladder that only that factor satisfies.
* The login page does not say why it is asking again; a failed demand returns to the application.
* On a custom ladder that needs `uv` after a password, the passkey step still asks for user verification as
  "preferred" and refuses afterwards if the authenticator did not perform it.
* No attestation-based `hwk` or AAL mapping; no ACR for token exchange.
* Not run against an OpenID conformance suite or a third-party resource server; tested with the repository's tests
  (software authenticators) and a live `haven-idp dev` run.
