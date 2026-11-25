# MCP clients and consent

MCP clients (editors, agents, desktop apps) are numerous and rarely pre-registered. This page covers how haven-idp
lets such clients identify themselves without an admin creating each one, and how the user stays in control of what
they are allowed to do:

1. **OAuth Client ID Metadata Documents (CIMD)**: the `client_id` is an https URL that names a JSON document
   ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/),
   used by the [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)).
   **Off by default**, switched on per realm.
2. **A consent screen** for third-party, dynamically registered and CIMD clients, with remembered and revocable
   grants, hash-chained **consent receipts**, an account page for users and an Admin API.
3. **A kill switch** per client or per agent that blocks it and revokes its grants, refresh tokens and (for an agent)
   its credentials.

It is on only when the store supports it (`core.ConsentStore`; memstore and Postgres do). Without it, https
`client_id`s are "unknown client", no consent is asked and the Admin routes answer `501`.

## Client ID Metadata Documents

Realm policy `cimdEnabled: true` is required. Then an authorization request with
`client_id=https://app.example/oauth/client.json` makes haven-idp fetch that URL.

The `client_id` must be an `https` URL (plain `http` only to loopback in `haven-idp dev`), with a path (not just
`/`), no userinfo, no fragment, no `.` or `..` segments and at most 2048 characters. Document, as the spec requires:

```json
{
  "client_id": "https://app.example/oauth/client.json",
  "client_name": "Example MCP Client",
  "client_uri": "https://app.example",
  "redirect_uris": ["http://localhost:8765/callback", "com.example.app:/callback"],
  "token_endpoint_auth_method": "none"
}
```

What is checked, and every failure is "Invalid client" to the browser (the reason goes to the server log only):

| Rule | Detail |
|---|---|
| Fetch | GET through the SSRF-safe client: destination IP checked at dial time (no loopback, private, link-local, CGNAT, metadata addresses), **no redirects followed**, 4 s timeout, body cap 16 KiB, status must be 200 and `Content-Type` JSON |
| Identity | the document's `client_id` must equal the URL **exactly** (string comparison, no normalisation) |
| Redirect URIs | 1 to 10, `https`, `http` to a loopback host, or a private-use scheme with a dot (`com.example.app:`); no fragment, userinfo, wildcard, whitespace or `javascript:`-style schemes; matched **exactly** at `/auth` and at the token endpoint |
| No secrets | a document carrying `client_secret`, `client_secret_expires_at`, `registration_access_token`, `registration_client_uri` or `client_id_issued_at` is refused; `token_endpoint_auth_method` must be absent or `none` (no `client_secret_*`, no `private_key_jwt`) |
| Grants | `grant_types` may only list `authorization_code` and `refresh_token`; `response_types` only `code` |
| Display | `client_name` is cut to 100 characters with control and bidi-override characters removed; `client_uri` is shown as text, never as a link; logos are ignored (the pages allow no images) |
| Host allow-list | optional `cimdHosts`: only these hosts are ever fetched |
| Budget | per IP 20 fetches/minute and per realm 120/minute. Cached documents cost nothing. A store error denies |
| Cache | the result is kept for `Cache-Control: max-age` clamped to 5 min .. 24 h (default 1 h; `no-store` = 5 min). After expiry it is refetched; **if the refetch fails the client is refused** (no stale use) |

The client is materialised as an ordinary, **public, PKCE-required, authorization-code-only** client (no secret,
no password or service-account flow), so the token endpoint needs no special case. A client row that an admin
created with a URL as its id is never treated as CIMD. Disabling the realm opt-in makes https client ids
unresolvable again at `/auth`; tokens already issued are not touched (use the kill switch).

**Never auto-trusted.** A CIMD client always goes through the consent screen. A remembered grant skips the screen for
a CIMD client only if the realm sets `rememberCimd: true` (default `false`: the user is asked every time, because
anyone can publish a document claiming to be any application).

Discovery advertises `client_id_metadata_document_supported: true` for a realm that opted in.

## Consent screen

Consent is asked, before a code is issued, for:

* every CIMD client (always);
* every dynamically registered client (see [dynamic-client-registration.md](dynamic-client-registration.md)) (always);
* every other client too when the realm sets `requireAll: true`, except those listed in `skipClients` (which can
  never exempt a CIMD or dynamically registered client). Admin-created clients are not asked by default.

The screen shows the client name, its identifier, the website it claims (unverified), the exact redirect URI the
browser will return to, each requested scope in words, and the requested `resource` (RFC 8707) values. Buttons:
Allow / Deny. Deny returns `access_denied` to the registered redirect URI; `prompt=none` returns `consent_required`
(never a page); `prompt=consent` forces the screen even when a grant is remembered.

A remembered grant covers a later request only if all of these hold: it is active (not revoked, not expired:
default 90 days, `grantTtlSeconds`), the client's identity is unchanged (a fingerprint of client id, name and
exact redirect URIs: a changed document asks again), and the request asks for no scope or resource beyond it.

`resource` parameters are validated (absolute https URIs, no fragment, at most 16) and recorded in the grant and
the receipt. Binding the `aud` of issued tokens to them is the job of the MCP resource-server work, not of this
feature.

### Security properties

* **CSRF**: the form carries the double-submit CSRF token (HMAC-signed, 15 min, cookie `HttpOnly`, `SameSite=Strict`,
  scoped to the `/auth` path) that the login form uses. A forged or missing token is `403`, nothing is recorded.
* **Decision proof**: the page also carries a signed proof that it was rendered for this user, this SSO session and
  this exact request (client fingerprint, scopes, resources). Posting a decision straight to `/auth` with a stolen
  SSO cookie, another user's proof, or a proof from a different request fails (`403`, or `409` plus a fresh page when
  only the request changed), so the `max_age` / step-up / `prompt=login` checks of silent SSO cannot be skipped.
* **Clickjacking and XSS**: `X-Frame-Options: DENY`, CSP `default-src 'none'; style-src 'nonce-...';
  frame-ancestors 'none'; base-uri 'none'` (no script at all), `Cache-Control: no-store`. Every client-supplied string
  is HTML-escaped (tested with a `<script>` name).
* **No open redirect**: the only redirect target is the exactly registered `redirect_uri`, validated before the page
  is ever shown; errors before that point are error pages, never redirects.
* A decision limit of 60 per user per minute; a store error fails closed. No receipt means no grant: if the receipt
  cannot be written, the grant is rolled back and no code is issued.

## Grants, receipts and the account page

`GET /realms/{realm}/account/consents` (needs the SSO session; CSRF on every POST) lists the user's active grants
with a **Revoke access** button and the last ten consent events. Revoking ends the grant, revokes the user's refresh
tokens for that client and writes a receipt. Access tokens already issued live until they expire (the realm's access
token TTL, 5 minutes by default). A user can only see and revoke their own grants.

**Consent receipts** are append-only rows, one hash chain per realm: `seq`, `time`, `type`
(`grant`, `deny`, `revoke`, `kill`, `unkill`), `userId`, `clientId`, `clientName`, `scopes`, `resources`, `actor`
(the user, or `admin:<subject>`), `detail`, `prevHash`, `hash` (SHA-256 over all fields and the previous hash).
No tokens or secrets are in them. They are also logged as audit events (`CONSENT_GRANT`, `CONSENT_DENY`,
`CONSENT_REVOKE`) when the realm logs auth events. Postgres appends them under a per-realm advisory lock.
`GET .../consent-receipts/verify` walks the chain and reports where it first breaks. Editing or removing a
middle row is detected; **dropping the newest rows is not** detectable from the database alone, so keep the
`headHash` somewhere else if that matters to you.

## Kill switch

`POST /admin/v1/realms/{r}/consent/kill` with `{"clientId": "...", "reason": "..."}` or `{"agentId": "..."}` (the
agent's backing client) does, in this order: record a block (so the client cannot start new authorizations and a
CIMD client is not re-resolved, even if its row is deleted or its document refetched), disable the client row,
revoke every remembered grant and every refresh token of the client, disable the agent and revoke all of its
credentials (see [agent-identities.md](agent-identities.md)), and append a `kill` receipt. It is idempotent, and on
a partial failure it answers `500` with what was done: repeat it.
Access tokens already issued keep working until they expire (at most the access token TTL).
`POST .../consent/unkill` removes the block and re-enables the client row; it does not restore grants or tokens and
does not re-enable a disabled agent (do that with the agent API).

## Admin API

All under `/admin/v1/realms/{r}`; details in `internal/idp/admin/SPEC.md`.

| Route | |
|---|---|
| `GET`, `PUT /consent-policy` | `{cimdEnabled, cimdHosts[], requireAll, skipClients[], rememberCimd, grantTtlSeconds}`; PUT replaces everything |
| `GET /consent-grants?userId=&clientId=&includeEnded=true&limit=` | remembered grants |
| `DELETE /consent-grants/{id}` | revoke (grant, refresh tokens, receipt); 409 if already ended |
| `GET /consent-clients` | CIMD clients seen, with cache expiry |
| `GET /consent-receipts?userId=&afterSeq=&limit=` | receipts, oldest first |
| `GET /consent-receipts/verify` | `{ok, count, headSeq, headHash}` or `{ok:false, error}` |
| `GET /consent-blocks` | kill-switched clients |
| `POST /consent/kill`, `POST /consent/unkill` | as above |

Postgres migration `0017_mcp_consent.sql`: `consent_policies`, `consent_clients`, `consent_grants`,
`consent_blocks`, `consent_receipts`.

## Try it (dev)

```
haven-idp dev            # CIMD may fetch loopback http in dev only
curl -X PUT -H "Authorization: Bearer $ADMIN" -d '{"cimdEnabled":true}' .../admin/v1/realms/demo/consent-policy
```

Serve a document on `http://127.0.0.1:PORT/client.json` whose `client_id` is that URL and start an authorization
request with it.

## Not yet

* Loopback redirect URIs are matched exactly (RFC 8252 allows any port for loopback; a CIMD client with a random
  port must list the port it uses).
* Consent is per client and user, not per scope or per resource server; the user cannot untick single scopes.
* Granted `resource`s are recorded and shown but not yet bound into the issued token `aud`.
* No `software_statement`, signed metadata, `jwks`/`private_key_jwt` for metadata-document clients, or `logo_uri` display.
* No ETag/conditional refetch of documents, no push invalidation; a changed document is picked up at cache expiry.
* The kill switch cannot recall access tokens that were already issued; there is no per-token deny list.
* No consent for the device flow's own approval page, for `client_credentials`, or for token exchange (agents
  authenticate with their own credentials, which the kill switch revokes).
* Receipts are tamper-evident, not tamper-proof: truncating the tail is undetectable without an external copy of the
  head hash; there is no signed export or external anchoring.
* The metadata fetch has a 4 s timeout; a slow document holds that `/auth` request for that long (bounded by the
  fetch budget above). No in-flight de-duplication of simultaneous first fetches of one document.
* Not run against a real MCP client; tested with an httptest metadata server and the dev server.
