# FAPI 2.0 building blocks: PAR, JAR, RAR, require-PAR, require-DPoP

haven-idp implements the pieces of the FAPI 2.0 Security Profile that live at the authorization and token
endpoints:

* **PAR**, pushed authorization requests ([RFC 9126](https://www.rfc-editor.org/rfc/rfc9126)): the client sends the
  authorization request to `/par` over an authenticated back channel and the browser only carries an opaque
  `request_uri`.
* **JAR**, signed request objects ([RFC 9101](https://www.rfc-editor.org/rfc/rfc9101)), ES256 and PS256, verified
  against keys registered for the client.
* **RAR**, rich authorization requests ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)): `authorization_details`,
  checked against the types registered for the client and carried to the tokens and to introspection.
* Per client **"require PAR"**, **"require signed request"** and **"require DPoP"**, and `dpop_jkt` at the
  authorization endpoint ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) section 10), which `docs/dpop.md` listed as gaps.

**This is not FAPI certification.** haven-idp has not been run against the OpenID Foundation conformance suite and
does not claim a FAPI 2.0 profile. The section "What the FAPI 2.0 Security Profile asks, and where haven-idp stands"
lists what is met and what is not.

Everything is **off until you configure it**: a client without FAPI settings behaves exactly as before. The feature
needs a store with `core.FAPIStore` (memstore and Postgres have it); without it `/par` answers `501`, discovery
leaves the fields out, and `/auth` refuses `request`, `request_uri`, `authorization_details` and `dpop_jkt`
instead of ignoring them.

## Flow

```
client (confidential)                 haven-idp                               browser
 | POST /par  (client auth, params or request=<JWT>, [DPoP proof])
 |----------------------------------->|  checks client, redirect_uri, request object, details, dpop_jkt
 | <- 201 {"request_uri":"urn:ietf:params:oauth:request_uri:...","expires_in":60}
 |
 | redirect the user to /auth?client_id=app&request_uri=...  --------------------------->|
 |                                    | <-- GET /auth?client_id&request_uri  -------------|
 |                                    |  consumes the request_uri (single use), 302 to
 |                                    |  /auth?client_id&fapi_ctx=<handle>  (login continues from there)
 |                                    |  ... normal login, SSO, MFA ...  --> code
 | POST /token (client auth, [DPoP proof for dpop_jkt])
 | <- access token (cnf.jkt), authorization_details, refresh token
```

### PAR endpoint

`POST /realms/{realm}/protocol/openid-connect/par`, form encoded, advertised as `pushed_authorization_request_endpoint`.

| Check | Rule |
|---|---|
| client authentication | required: the client's secret, or the method configured for it (`private_key_jwt`, mutual TLS; see [client-authentication.md](client-authentication.md)). Public clients, unknown, disabled or wrongly authenticated clients get `401 invalid_client`. |
| parameters | `request_uri` is refused. Redirect URI is matched exactly against the client's registration; `response_type` must be `code`; each value at most 8 KiB. |
| request object | when `request` is present, **only** the verified object counts; every other form parameter is ignored (FAPI 2.0 and RFC 9101). |
| `authorization_details` | validated (see RAR), stored canonicalised |
| DPoP | an optional `DPoP` header is validated like at the token endpoint but for the PAR URL (`htu`), with the replay cache; its key becomes the request's `dpop_jkt`. A `dpop_jkt` parameter that disagrees is `invalid_dpop_proof`. |
| rate limit | 120 requests per client address per 10 minutes (`429`); a limiter failure is `500`. |
| response | `201 {"request_uri","expires_in":60}`, `Cache-Control: no-store`. The request_uri has 256 bits of entropy; only its sha256 is stored. |

### Redeeming the `request_uri`

* **Single use and short lived.** The row is deleted when first presented (one atomic delete: exactly one of several
  concurrent presentations wins, in memstore and Postgres); it expires after 60 seconds anyway.
* **Bound to the client.** The `client_id` on `/auth` must be the one that pushed it, otherwise `400`.
* Only `client_id` and `request_uri` travel through the browser. Everything else (redirect URI, state, PKCE challenge,
  scope, nonce, details) comes from the stored request.
* A GET answers `302` to `/auth?client_id=..&fapi_ctx=..`. The **login context** `fapi_ctx` is a second random,
  hashed, client-bound handle valid for 10 minutes so password errors, MFA steps and page reloads work. It is
  **spent when the authorization code is issued**: replaying the URL afterwards is `400`.
* Passing more than one of `request_uri`, `request`, `fapi_ctx` is `400`.
* Failures on `/auth` before the redirect URI is known to be trusted are an HTML error page, never a redirect.

## JAR: signed request objects

A request object is a compact JWS in `request` (at `/par`, or directly at `/auth` for clients that do not require PAR).

| Check | Rule |
|---|---|
| `alg` | `ES256` or `PS256` only. `none`, `HS*`, `RS256`, `EdDSA` are refused. |
| header | no `crit`; `typ` absent or `oauth-authz-req+jwt`; `jwk`, `jku`, `x5u` are ignored (keys are never taken from the object or fetched) |
| keys | the client's registered **inline JWKS** (Admin API, below). EC P-256 and RSA 2048 to 8192 bits, `use` = `sig` or unset, public keys only (a JWK with a private member is ignored). `kid` selects a key; without `kid` exactly one candidate of the right type must exist. |
| `iss` | equals the client_id; a `client_id` member must match too |
| `aud` | contains the issuer URL of the realm (`BaseURL/realms/{realm}`) |
| `exp`, `nbf` | **both required**; `exp` not in the past (60 s skew), `nbf` not in the future (60 s skew), `exp - nbf` at most 1 hour, `exp` after `nbf` |
| content | no `request` or `request_uri` member; only the usual authorization parameters are read; values must be strings (numbers only for `max_age`, an array only for `authorization_details`); duplicate member names are refused |
| failure | always the same opaque `invalid_request_object` (PAR) or an HTML error page (`/auth`); the reason is never given to the caller |

Not done for JAR: `jwks_uri` (no remote key fetch, so no SSRF surface), encrypted request objects (JWE), a `jti`
replay cache for by-value objects at `/auth` (PAR makes them single use; by value an object can be replayed until it
expires, but each replay still needs a login), and `request_object_signing_alg` / per-client algorithm pinning.

## RAR: `authorization_details`

`authorization_details` is a JSON array of objects. Each object needs a `type` that is in the client's
`authorizationDetailTypes` (exact match; a client with an empty list may not send the parameter at all).

* Limits: 8 KiB, at most 10 entries, nesting at most 8, **no duplicate member names** anywhere (a second `"type"`
  would be read differently by different parsers), nothing after the array. Types match
  `^[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}$`.
* haven-idp interprets **only `type`**. The rest of each entry (`actions`, `locations`, `instructedAmount`...) is
  carried unchanged, canonically re-encoded (member names sorted, numbers kept exactly). What a type means is for the
  resource server.
* Error: `invalid_authorization_details` (JSON from `/par`; redirect to the registered redirect URI from `/auth`
  when the request was not pushed).
* Carried to: the code (bound by its hash), the **token response** (`authorization_details`), the **access token**
  (`authorization_details` claim), **introspection** of access and refresh tokens, and **refresh**: the details are
  bound to the refresh token's hash, and the rotated token inherits them. The ID token does not carry them.
* `authorization_details` at the **token endpoint** is refused (`invalid_request`) before anything is consumed;
  narrowing at the token endpoint and `client_credentials` with details are not supported.
* **There is no consent screen.** haven-idp has no consent page for these requests: it trusts the client's registered
  types and shows the user nothing about the details. Do not use RAR for anything where the user must see and confirm
  the detail until a consent step exists.

## Per-client settings

Admin API (`internal/idp/admin/SPEC.md`, section "FAPI building blocks"): `GET/PUT /admin/v1/realms/{r}/clients/{id}/fapi`.

| Field | Effect |
|---|---|
| `requirePar` | `/auth` accepts only a `request_uri` (or its login context). A plain request, or a request object by value, is `400`. Needs a confidential client. |
| `requireSignedRequest` | `/par` and `/auth` accept only a signed request object. Needs `jwks` and a confidential client. |
| `requireDpop` | **every** token request of the client (authorization code, refresh, `client_credentials`, device, any extension grant) needs a valid DPoP proof, otherwise `400 invalid_dpop_proof` before the grant runs (a code is not consumed). All tokens are then DPoP-bound (`cnf.jkt`, `token_type: DPoP`). |
| `jwks` | the public keys that verify request objects (JSON object; validated; never returned in audit events) |
| `authorizationDetailTypes` | allowed RAR types (at most 20) |

* The settings are stored by the client's **internal id** (cascade on delete in Postgres, checked against the live
  client in memstore): deleting a client and creating another with the same `client_id` starts from defaults.
* Reading the settings failing (store error) **refuses the request** (`/auth`, `/par`, token endpoint: `500`;
  identity brokering: refused); defaults are assumed only when the store says "no settings".
* Identity brokering (`/broker/.../login`) rebuilds the authorization request from a plain query and knows nothing
  of request objects or contexts, so it **refuses** requests for clients with `requirePar` / `requireSignedRequest`
  and any request carrying `authorization_details`, `dpop_jkt` or `fapi_ctx`. Federation is therefore not usable
  with those requests yet.

### `dpop_jkt` at the authorization endpoint

`dpop_jkt` (RFC 9449 section 10: the SHA-256 thumbprint of the key the client will use) is accepted at `/auth`, in
a request object, at `/par`, or derived from a `DPoP` proof sent to `/par`. The code is bound to it; redeeming the code
needs a proof from **that** key (missing or other key: `400 invalid_dpop_proof`, the code is not consumed), and the
access token is bound to it as usual. Malformed values are refused. `requireDpop` does not force `dpop_jkt`: a
client that requires DPoP simply must present a proof at the token endpoint.

For confidential clients the refresh token is not key-bound by DPoP itself (RFC 9449 section 5), so `requireDpop`
makes them present *a* proof on refresh, not necessarily the original key; their access tokens are always bound.
Public clients' refresh tokens are bound by the existing DPoP code.

## Discovery

When the store supports it: `pushed_authorization_request_endpoint`, `require_pushed_authorization_requests: false`
(the switch is per client, not per realm), `request_parameter_supported: true`, `request_uri_parameter_supported: true`
(PAR `request_uri`s only; no external URIs are fetched), `require_request_uri_registration: false`,
`request_object_signing_alg_values_supported: ["ES256","PS256"]`, `authorization_details_supported: true`.
`dpop_signing_alg_values_supported` comes from the DPoP feature. The allowed detail types are per client and are not listed.

## Storage

Postgres migration `0018_fapi.sql`: `client_fapi` (per client, `ON DELETE CASCADE`), `fapi_requests` (pushed requests
and login contexts, sha256 of the identifier), `fapi_bindings` (details and `dpop_jkt` of a code or refresh token,
sha256 of the token). Expired rows are ignored on read; `PurgeExpiredFAPI` deletes them (nothing schedules it yet).
`dev --persist` keeps only the per-client settings. Auth events: `PAR`, `PAR_ERROR` and `LOGIN_ERROR
invalid_request_object`, never with request content.

## What the FAPI 2.0 Security Profile asks, and where haven-idp stands

Read against the FAPI 2.0 Security Profile (authorization server requirements). "Met" means implemented and tested
here; it does not mean conformance-tested.

| Requirement | Status |
|---|---|
| Authorization code flow only (`response_type=code`) | **Met** |
| PKCE with S256 for the authorization code, `plain` refused | **Partly.** S256 only, and required for public clients and clients with `requirePKCE`; a confidential client without `requirePKCE` may still omit PKCE. |
| PAR required for authorization requests | **Met per client** (`requirePar`); not a realm-wide switch, and not the default. |
| `request_uri` single use, short lived, bound to the client | **Met** |
| Request objects, if supported: ES256/PS256, `exp`/`nbf` within 60 min, `aud` = issuer | **Met** (EdDSA is permitted by FAPI but not supported here) |
| Sender-constrained access tokens (DPoP) | **Partly.** DPoP works and is enforceable per client (`requireDpop`), but proofs signed with **RS256** are also accepted (FAPI allows PS256, ES256, EdDSA only) and **PS256 proofs are not supported**. |
| Refresh tokens of confidential clients sender-constrained or rotating | **Partly.** Rotation is a realm switch; confidential refresh tokens are not key-bound. |
| Issuer in the authorization response (RFC 9207 `iss`) | **Met** |
| Exact redirect URI matching | **Met**, but `http://` redirect URIs are accepted (FAPI requires https, loopback excepted); not enforced. |
| Authorization codes single use, at most 60 s | **Met** (default 60 s, configurable; single use) |
| **Confidential clients only** | **Not met.** Public clients are supported. |
| **Client authentication with `private_key_jwt` or mTLS** | **Partly.** Both exist and are exclusive per client ([client-authentication.md](client-authentication.md)), but nothing requires them: secret clients are still allowed. Assertions may be signed with **RS256** unless `signingAlg` pins another, and the endpoint URL is accepted as `aud` besides the issuer (FAPI 2.0 asks for the issuer only and no RS256). |
| **RFC 8414 authorization server metadata** (`/.well-known/oauth-authorization-server`) | **Not met.** Only OIDC discovery is served (it carries the new fields). |
| `token_endpoint_auth_signing_alg_values_supported` and related metadata | **Met** (lists RS256, see above) |
| TLS 1.2+ with the FAPI cipher restrictions | **Not verified.** TLS is terminated outside haven-idp. |
| Conformance suite run | **Not done.** |
| FAPI 2.0 Message Signing (JARM, signed introspection responses, non-repudiation) | **Not implemented** (a separate profile) |
| mTLS certificate-bound tokens (RFC 8705) | **Partly.** Per confidential client, when the server has mutual TLS configured; refresh tokens and public clients are not certificate-bound |

RAR is not part of the FAPI 2.0 Security Profile itself; it is here because FAPI-style deployments (payments, open
banking) use it.

## Not yet

* A confidential-clients-only or strong-client-authentication-only realm mode, RFC 8414 metadata, https-only
  redirect URIs, PS256 DPoP proofs and dropping RS256 proofs.
* A realm-wide "require PAR / DPoP" and a policy that makes `requirePkce` follow `requirePar`.
* `jwks_uri` for request objects (client authentication has its own, see
  [client-authentication.md](client-authentication.md)), JWE request objects, `jti` replay cache for by-value
  objects, per-client algorithm pinning for request objects.
* A consent screen that shows `authorization_details`; token-endpoint narrowing; details with `client_credentials`
  and the device grant; `authorization_details_types_supported` in discovery.
* Federation (brokered login) with PAR/JAR/RAR requests. Passkey and MFA steps continue from the login context
  (they post back to the same `/auth` URL) but were not exercised with pushed requests in the tests.
* A scheduled purge of expired rows; an Admin API to list or revoke pending pushed requests.
* Verification with an independent FAPI client or the OpenID conformance suite: every request object and proof in
  the tests and the live run was produced by hand-written code in this repository.
