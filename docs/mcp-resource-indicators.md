# MCP core: resource indicators and discovery

haven-idp can act as the authorization server of an MCP server (or any resource server): it accepts the OAuth
**resource indicators** of [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) and puts the resource into the access
token's `aud`, and its metadata is what an MCP client needs after it has read the server's
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) protected resource metadata.

Everything is **off until you configure an allow-list**: with no allow-list a `resource` parameter is refused with
`invalid_target` (it is never silently ignored), and requests without `resource` behave exactly as before.

## What it does

A client sends `resource=<identifier>` (repeatable, at most 5) on:

| Request | Behaviour |
|---|---|
| authorization request (`/auth`) | every value must be a valid identifier on the client's allow-list, else the error goes back to the (validated) redirect URI as `error=invalid_target` |
| token request, `authorization_code` | values may only **narrow** what the code was authorized for; none = the whole authorized set |
| token request, `refresh_token` | same: may only narrow the original grant; the new refresh token keeps the **original** set, so a narrowed access token does not shrink the grant |
| device authorization + device token request | same rules (the device code carries the set) |
| pushed (PAR) and signed (JAR) authorization requests | same as the authorization request; PAR repeats the form field, a request object may use a string or an array |
| brokered sign-in ("Continue with ...") | same as the authorization request: the resources are bound after the upstream login |
| consent screen | shows and records the canonical values that the tokens will be bound to ([mcp-clients-and-consent.md](mcp-clients-and-consent.md)) |
| CIBA backchannel request + CIBA token request | values must be on the client's allow-list; the token request may only narrow what the user approved ([ciba.md](ciba.md)) |
| token request, `client_credentials` | values must be on the client's allow-list; none = a plain token |
| token exchange, agent identities | unchanged: `resource`/`audience` must be one entry of the agent's own audience list ([agent-identities.md](agent-identities.md)); the client allow-list is not consulted |
| token exchange / JWT bearer, workload identities | unchanged: `resource` is refused with `invalid_target` ([workload-identity.md](workload-identity.md)) |

The access token then has `aud: ["<client_id>", "<resource>", ...]`. The client id stays in `aud` so that userinfo
and introspection keep working for the same token; **the resource server must check that its own identifier is
in `aud`** (the MCP spec requires this). The ID token's `aud` stays the client id. DPoP composes: a request that
proves a key gets `cnf.jkt` as well as the resource audience.

### Identifier rules

An identifier is an absolute **https** URI: no fragment, no query, no userinfo, no dot segments, printable ASCII,
at most 256 bytes. It is canonicalised before comparison and before it goes into `aud`: scheme and host lower-case,
default port `:443` removed, path untouched (a trailing slash is significant: `https://x.example/mcp` and
`https://x.example/mcp/` are different resources). Plain `http` is not accepted, not even for loopback.

### Allow-list

A JSON file named by `HAVEN_IDP_RESOURCES_FILE` (read at start, restart to change; unknown fields and invalid
identifiers make the server refuse to start):

```json
{
  "realms": {
    "demo": {
      "resources": ["https://mcp.example.com/mcp"],
      "clients": {
        "mcp-inspector": ["https://mcp.example.com/mcp", "https://files.example.com/api"],
        "ci-bot": []
      }
    }
  }
}
```

A client with its own entry uses **exactly that list** (it replaces the realm default; `[]` means none); every
other client of the realm uses `resources`; a realm that is not listed allows nothing. Embedders can supply any
`oidc.Config.Resources` (interface `ResourceAllowList`) instead of the file.

## How the grant is remembered (security properties)

No schema change: the granted set rides inside the code strings themselves. An authorization code, device code
and refresh token is `<random>~<base64url(resources)>` (codes and refresh tokens add `~<context>`, the authentication
context of [step-up-acr.md](step-up-acr.md)) and **only the sha256 of the whole string is stored**.
Consequences:

* The set cannot be altered: changing the suffix changes the hash, so a forged code or refresh token is just an
  unknown token (`invalid_grant`, tested). It is readable by whoever holds the token, which is the client that
  asked for it.
* Re-checked at redemption: every use re-reads the allow-list. A resource removed from the allow-list stops being
  issued on the next refresh (it is dropped); if nothing of the grant is allowed any more the request fails with
  `invalid_target`. Refresh can never widen.
* A refused `resource` on a refresh or device request does not consume the token. An authorization code is
  consumed first (ordinary single-use behaviour).
* Tokens issued before this feature have no suffix and stay valid; they simply carry no resources, so a
  `resource` parameter sent with them is `invalid_target`.
* Introspection returns the `aud` array as is. Opaque-token detection elsewhere in the server counts dots, so
  the separator is `~` (no dot).

## MCP authorization spec: what was checked (spec 2025-11-25)

Read at <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization> on 2026-11-24:

| Spec text | haven-idp |
|---|---|
| "MCP clients MUST include `resource` in authorization and token requests"; value is the canonical URI | accepted on both, canonicalised as above (uppercase scheme/host accepted, as the spec recommends) |
| "MCP servers MUST validate that tokens were issued specifically for them as the audience" | `aud` contains the resource; checking it is the MCP server's job |
| AS metadata via RFC 8414 or OIDC discovery; for an issuer with a path (ours: `https://idp/realms/{realm}`) clients try (1) `/.well-known/oauth-authorization-server/realms/{realm}`, (2) `/.well-known/openid-configuration/realms/{realm}`, (3) `/realms/{realm}/.well-known/openid-configuration` | all three are served with the same document. (1) and (2) are new; they need the host to route those two prefixes to the IdP, which `haven-idp serve` does. Behind a reverse proxy, forward them too, or clients fall back to (3) |
| "AS providing OIDC discovery MUST include `code_challenge_methods_supported`"; clients MUST use S256 | `["S256"]`; `/auth` refuses any other method |
| "authorization servers MUST validate exact redirect URIs"; "redirect URIs MUST be localhost or https" | exact match against the registered list (no port wildcard for loopback, see Not yet) |
| "For public clients, ASs MUST rotate refresh tokens"; "SHOULD issue short-lived access tokens" | rotation (`refreshTokenRotation`) and access token TTL are realm settings; turn rotation on for realms used by public MCP clients (not enforced by this feature) |
| Public clients use `token_endpoint_auth_methods_supported` containing `none` | advertised |
| Client ID Metadata Documents (SHOULD), DCR (MAY) | CIMD: **not supported**, `client_id_metadata_document_supported` is not advertised. DCR: RFC 7591 behind admin-issued initial access tokens, `registration_endpoint` advertised when enabled ([dynamic-client-registration.md](dynamic-client-registration.md)); MCP clients that cannot present an initial access token need a pre-registered client |

Pinned by `TestRFC8414DiscoveryAliasesAndMCPRequirements` (issuer equals the issuer the URL was built from,
S256, endpoints under the issuer, `code` response type, `authorization_code`/`refresh_token` grants, `none` auth
method, `iss` response parameter, the alias routes) and the resource tests in `internal/idp/oidc/resources_test.go`.

## RFC 9728: protected resource metadata is the MCP server's document

RFC 9728 metadata describes the **resource server**, so the MCP server serves it (and sends
`WWW-Authenticate: Bearer resource_metadata="..."` on 401). haven-idp does **not** host such documents (it would
have to be authoritative for URLs it does not own). Point the MCP server's document at a realm:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://idp.example.com/realms/demo"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["openid", "profile", "email"]
}
```

`resource` must equal an identifier in the allow-list of the client, and `authorization_servers` entries are the
realm issuer (`issuer` in the realm's metadata). The client then discovers the endpoints, registers or uses a
pre-registered client, and sends `resource` on both requests.

## Configuration

| Setting | Meaning |
|---|---|
| `HAVEN_IDP_RESOURCES_FILE` | path of the allow-list JSON; unset = resource indicators off |
| `oidc.Config.Resources` | embedders: any `ResourceAllowList` |

## Not yet

* No Admin API or UI for the allow-list and no per-realm persistence: the list is a file read at start (a
  persistent store would need a migration; the `ResourceAllowList` interface is the seam). Config as code
  (`validate/plan/apply`) does not know about it.
* The consent screen and the CIBA approval page show resources, all or nothing; clients that are not asked for
  consent are gated by the allow-list alone. The device flow approval page does not show the resource.
* Loopback redirect URIs are matched exactly: MCP desktop clients that pick a random local port must register the
  URIs they use (RFC 8252 port flexibility is not implemented).
* Client ID Metadata Documents are not supported.
* One audience set per token: the client id is always one of the audiences, and a token for several resources
  is valid at all of them (ask for one resource per token when that matters).
* Not run against a real MCP client; verified with the repository's HTTP tests and a live `haven-idp dev` run
  (see the commit notes). Token exchange (`subject_token_type` agent/workload) is unchanged, see the table above.
