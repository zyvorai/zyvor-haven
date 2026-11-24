# Dynamic client registration

haven-idp implements OAuth 2.0 Dynamic Client Registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591))
and Client Registration Management ([RFC 7592](https://www.rfc-editor.org/rfc/rfc7592)), so a tool can
register itself as a client instead of an admin clicking through the console.

**Registration always needs an initial access token issued by an admin. There is no anonymous mode, and
this version has no setting to turn one on.**

The registration paths are:

| Call | Path | Authenticated by |
|---|---|---|
| Register | `POST /realms/{realm}/clients-registrations/openid-connect` | initial access token |
| Read / replace / delete | `GET`, `PUT`, `DELETE /realms/{realm}/clients-registrations/openid-connect/{client_id}` | the client's registration access token |

The two tokens are not interchangeable: an initial access token fails on the management URL, and a
registration access token fails on the registration URL.

## Flow

1. An admin creates an initial access token for a realm (Admin API below). It is shown once.
2. The tool `POST`s its metadata with `Authorization: Bearer <initial access token>`. Each successful
   registration uses one of the token's counts.
3. The response (201) carries the `client_id`, the `client_secret` for confidential clients, and a
   `registration_access_token`. Keep them: **the secret and the registration token are returned once and
   never again**, in any response.
4. The tool uses the registration access token to read, update or delete only that client.

```sh
# 1. admin: one token, valid 1 hour, good for 3 registrations
curl -s -X POST https://idp.example/admin/v1/realms/demo/initial-access-tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"expirationSeconds":3600,"count":3,"note":"ci runners"}'
# {"id":"a7c0...","token":"hiat_...","count":3,"expiresAt":"...","note":"ci runners"}

# 2. tool: register a confidential web app that also wants client_credentials
curl -s -X POST https://idp.example/realms/demo/clients-registrations/openid-connect \
  -H "Authorization: Bearer $INITIAL_TOKEN" -H 'Content-Type: application/json' \
  -d '{"client_name":"Reports","redirect_uris":["https://reports.example/callback"],
       "grant_types":["authorization_code","refresh_token","client_credentials"],
       "scope":"openid profile offline_access"}'
# 201 {"client_id":"hc_...","client_secret":"...","client_secret_expires_at":0,
#      "registration_access_token":"hrat_...","registration_client_uri":".../hc_...", ...}

# a public single-page app (PKCE S256, no secret)
curl -s -X POST https://idp.example/realms/demo/clients-registrations/openid-connect \
  -H "Authorization: Bearer $INITIAL_TOKEN" -H 'Content-Type: application/json' \
  -d '{"client_name":"My SPA","redirect_uris":["https://spa.example/cb"],
       "token_endpoint_auth_method":"none"}'

# a native app with a loopback redirect
curl -s -X POST https://idp.example/realms/demo/clients-registrations/openid-connect \
  -H "Authorization: Bearer $INITIAL_TOKEN" -H 'Content-Type: application/json' \
  -d '{"application_type":"native","token_endpoint_auth_method":"none",
       "redirect_uris":["http://127.0.0.1:8123/cb"]}'

# 3. read, replace, delete with the registration access token
curl -s https://idp.example/realms/demo/clients-registrations/openid-connect/hc_XXXX \
  -H "Authorization: Bearer $REGISTRATION_TOKEN"
curl -s -X PUT https://idp.example/realms/demo/clients-registrations/openid-connect/hc_XXXX \
  -H "Authorization: Bearer $REGISTRATION_TOKEN" -H 'Content-Type: application/json' \
  -d '{"client_name":"Reports v2","redirect_uris":["https://reports.example/callback"]}'
curl -s -X DELETE https://idp.example/realms/demo/clients-registrations/openid-connect/hc_XXXX \
  -H "Authorization: Bearer $REGISTRATION_TOKEN"        # 204
```

The registration endpoint is advertised as `registration_endpoint` in the discovery document whenever the
store supports DCR. Advertising it does not make registration open: a call still needs a valid token.

## Accepted metadata

| Field | Rule |
|---|---|
| `client_name` | up to 255 characters, no control characters. Shown on the login page, always HTML-escaped. |
| `redirect_uris` | **Required** for `authorization_code`. At most 10, each at most 2048 characters. `https`, or `http` for `localhost` / loopback IPs only. No `*` anywhere, no fragments, no userinfo, no `javascript:` `data:` `vbscript:` `file:` `blob:`. `application_type: native` may also use a reverse-domain custom scheme (it must contain a dot, for example `com.example.app:/cb`). |
| `application_type` | `web` (default) or `native` |
| `grant_types` | any of `authorization_code` (default), `refresh_token`, `client_credentials`, and `urn:ietf:params:oauth:grant-type:device_code` (see below). `refresh_token` needs `authorization_code` or the device grant. Not `password`, not `implicit`. A public client cannot have `client_credentials`; the device grant cannot be combined with `client_credentials` (a service account has no user to approve a device). Narrowed by the realm policy. |
| `response_types` | `code` only (derived from the grants when omitted) |
| `token_endpoint_auth_method` | `client_secret_basic` (default), `client_secret_post`, or `none`. `none` makes a public client; PKCE S256 is then mandatory. |
| `scope` | space-separated, from `openid profile email roles offline_access` (default `openid profile email`). `offline_access` needs `refresh_token`. |
| `backchannel_logout_uri` | checked with the same rules as the Admin API (`idp.ValidateLogoutURI`) |
| `contacts`, `logo_uri`, `client_uri`, `policy_uri`, `tos_uri` | stored and returned. Contacts: at most 10 short strings. The URIs must be `https` (`http` for loopback). They are not used for anything else. |

Every code-flow client created through DCR, confidential or public, requires PKCE S256.

### The device grant (RFC 8628 clients)

A client that lists `urn:ietf:params:oauth:grant-type:device_code` is created with the device flow switched on
(`core.Client.DeviceFlow`, the same switch as `deviceFlowEnabled` in the Admin API; see [device-flow.md](device-flow.md)).
The usual DCR safety rules apply unchanged: an initial access token is needed and spent, the realm cap counts the
client, secrets and registration access tokens are shown once and stored hashed, and `PUT` re-validates everything
(dropping the grant switches the flow off again, adding it back is checked against the policy again).

- **Opt-in per realm.** The grant is *not* in the default policy and is not added to existing policies. An
  operator allows it with `PUT /registration-policy` and `allowedGrantTypes` containing the URN; until then a
  registration that asks for it is refused with `400 invalid_client_metadata`.
- A device-only client needs no `redirect_uris`, has no authorization-code flow (no login can be started for it at
  `/auth`) and cannot use `client_credentials`. `response_types` stays empty for it.
- Public (`token_endpoint_auth_method: none`) and confidential device clients are both allowed. Combined with
  `authorization_code` the code-flow rules (redirect URIs, PKCE S256) apply as always.
- `refresh_token` and `offline_access` work for device clients on their own.

Unknown fields are ignored and never echoed. `jwks`, `jwks_uri`, `software_statement` and the rest of the
RFC 7591 client metadata that haven-idp does not implement are not stored; `software_statement` is
refused with `invalid_software_statement`.

Errors follow RFC 7591: `400 invalid_redirect_uri`, `400 invalid_client_metadata`,
`400 invalid_software_statement`, `401 invalid_token`, `403 access_denied` (realm cap reached),
`413` (body over 16 KiB), `429 too_many_requests`. Descriptions are fixed text and never contain your
input.

## Response

`client_id` is `hc_` followed by 22 random URL-safe characters. `client_secret` is 32 random bytes and is
stored only as the same sha256 hash the Admin API uses; `client_secret_expires_at` is `0` (secrets do not
expire). `registration_access_token` is stored only as a sha256 hash. `registration_client_uri` is the
management URL. The response also echoes the stored metadata and `client_id_issued_at`.

## Management (RFC 7592)

- Only clients that were created through DCR can be managed this way. A client created by an admin, or a
  `client_id` that an admin deleted and re-created, has no registration record and cannot be read, changed
  or deleted with any registration token.
- Every failure (no token, wrong token, another client's token, an initial access token, unknown
  client, admin-created client) returns the same `401 invalid_token`, so nothing tells them apart.
- `GET` returns the metadata without the secret and without the registration token.
- `PUT` **replaces** the metadata and runs the same validation as registration. It does not rotate
  anything: the client secret and the registration access token stay as they are and are not returned
  again. A client cannot switch between public and confidential, and `client_id`, `client_secret` and
  `registration_access_token` in the body are rejected. A client an admin disabled stays disabled. To get a
  new secret, an admin uses the Admin API's secret regeneration.
- `DELETE` removes the client and its registration record (`204`). Authorization codes and tokens issued
  to it stop working because every grant looks the client up again.

## Admin API

All under `/admin/v1/realms/{r}` (see `internal/idp/admin/SPEC.md`):

| Call | Purpose |
|---|---|
| `POST /initial-access-tokens` `{expirationSeconds, count, note}` | Default 86400 s and 1 use; at most 30 days and 1000 uses. The token is returned once. |
| `GET /initial-access-tokens` | `id`, `note`, `createdAt`, `expiresAt`, `count`, `remaining`. Never the token. |
| `DELETE /initial-access-tokens/{id}` | Revoke. |
| `GET` / `PUT /registration-policy` `{maxClients, allowedGrantTypes?}` | Per-realm cap on DCR clients (default 100; `0` switches registration off) and the grants DCR may hand out. |
| `GET /registered-clients` | The clients created through DCR (`createdVia`, `initialTokenId`), so they can be told from admin-created ones. |

Each registration uses one count of the token atomically (two concurrent registrations on a token with one
count left: exactly one wins). An expired, exhausted, revoked or unknown token all fail with the same
`401 invalid_token`. A registration that fails validation, or hits the cap, gives its count back. Expired
tokens stay in the list until you delete them.

## Security properties

- No anonymous registration; only an admin can mint tokens.
- Initial and registration tokens and client secrets are random and stored only as sha256 hashes; they
  appear once in a response and never in logs, audit events or errors.
- Rate limits per client IP and realm, shared across replicas through the store: 20 registration attempts
  and 60 management calls per minute. Failed attempts count, so token guessing is bounded. If the rate-limit
  store errors, the request is refused (503).
- The request body is capped at 16 KiB.
- The cap on DCR clients is checked before and after creating the client, so concurrent registrations cannot
  exceed it.
- Audit events (when the realm logs auth events): `CLIENT_REGISTER`, `CLIENT_REGISTER_ERROR`,
  `CLIENT_UPDATE_REGISTRATION`, `CLIENT_DELETE_REGISTRATION`. The detail holds only the client type, the
  application type, the initial token's id or an error code.
- DCR state lives in its own tables (migration `0009`); `core.Client` is unchanged.

## Not yet

- No software statements and no JWT-secured registration (`software_statement` is refused).
- No anonymous or open registration mode, and no setting for one.
- No client metadata localisation (`client_name#fr` and friends are ignored).
- No `jwks` / `jwks_uri` / `private_key_jwt` client authentication.
- `scope` is validated and stored, and returned, but it is not enforced per client at the authorization
  endpoint: authorization requests are filtered against the realm's known scopes for every client.
- No registration access token rotation, and no way to ask for one.
- A device client registered through DCR gets the same fixed code lifetime and poll interval as any device client; there is no per-client override.
- Expired initial access tokens are not purged automatically.

## Consent

A client created through registration always goes through the consent screen before it is issued a code, and its
grants are remembered and revocable; see [mcp-clients-and-consent.md](mcp-clients-and-consent.md).
