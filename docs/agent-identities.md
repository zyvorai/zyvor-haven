# Agent and MCP identities

AI agents and MCP servers act for a person, but they are not that person and should never hold their password or a
long-lived session. An **agent identity** is a non-human client with an **owner** (a user), a strict allow-list of
scopes, short-lived revocable credentials, and tokens that say who is acting for whom using the RFC 8693 `act`
claim. It is **off** until you register an agent, and off when the store has no support (`501 feature_unavailable`).

## Model

| Thing | What it is |
|---|---|
| Agent | `name`, `kind: "agent"`, a generated `clientId` (`agent-...`), `ownerUserId`, allowed `scopes`, allowed `roles`, allowed `audiences`, `tokenTtlSeconds` (30 to 900, default 300) |
| Backing client | created with the agent: public, no secret, no redirect URIs, every interactive flow off. The "kind" lives on the agent record, not on the client |
| Credential | an opaque secret `hvag_...` (256 random bits), shown **once**; only its sha256 is stored. TTL 60 s to 7 days (default 1 h), scopes (a subset of the agent's), a note. At most 5 active per agent |

An agent can never be given more than its owner: at registration every `roles` entry must be a role the owner holds,
and **at every token issue** the roles in the token are the intersection of the agent's allowed roles and the
owner's roles right then (including time-boxed grants). An agent that lists no roles gets none. If the owner loses a
role, the agent loses it on its next token.

## Getting a token

```
POST /realms/{realm}/protocol/openid-connect/token

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=agent-x7k2...
&subject_token=hvag_...
&subject_token_type=urn:haven:params:oauth:token-type:agent-credential
&scope=mcp:read
&audience=https://mcp.example      (optional; must be in the agent's audiences)
```

Response (`no-store`): `access_token`, `issued_token_type=...:access_token`, `token_type=Bearer`, `expires_in`,
`scope`. No ID token, no refresh token.

Access token claims:

```json
{"iss":"https://idp/realms/r","sub":"<owner user id>","aud":"https://mcp.example","azp":"agent-x7k2...",
 "client_id":"agent-x7k2...","scope":"mcp:read","preferred_username":"alice","exp":...,"iat":...,"jti":"...",
 "act":{"sub":"agent:agent-x7k2...","iss":"https://idp/realms/r"},
 "realm_access":{"roles":["ops"]}}
```

`sub` is the owner (the agent acts on their behalf) and `act.sub` names the agent, per RFC 8693 section 4.1. A
resource server that wants to refuse delegated calls, or to log the actor, looks at `act`.

### Checks, in order (any failure is `invalid_grant` "agent credential rejected", reason only in the audit log)

1. the client is a public, flow-less client bound to an agent (otherwise `unauthorized_client`);
2. the agent is enabled and of kind `agent`;
3. the secret has the `hvag_` prefix and a sane length, and matches a credential **of this agent** (a credential of
   another agent is "unknown");
4. the credential is not revoked and not expired;
5. the owner still exists and is enabled;
6. `scope` (or, omitted, all the credential's scopes) is a subset of the credential's scopes AND the agent's
   current scopes, else `invalid_scope`; `openid` and `offline_access` are never allowed;
7. `audience`/`resource` (at most one) is in the agent's allow-list, else `invalid_target`; default `aud` is the
   agent's client id;
8. the token lifetime is the smallest of the agent TTL, the realm access token TTL and the time the credential has
   left, so a token never outlives its credential.

`actor_token`, `requested_token_type` other than `access_token`, and other `subject_token_type` values are refused.

## Security properties

* **Fail closed** everywhere: unknown, disabled, expired, revoked, orphaned owner, limiter error, store without
  support.
* **Secrets**: stored hashed, shown once, never logged or put in audit detail or errors. Credentials are 256-bit
  random, so they are not guessable; the exchange is still rate limited (60 per minute per realm, client IP and
  client id; `429 slow_down`; a limiter error denies).
* **Revocation**: disabling an agent, revoking a credential, revoking all credentials, deleting the agent, or
  disabling the owner stops new tokens at once. Access tokens already issued are JWTs and stay valid for at most
  their TTL (15 minutes at most; 5 by default).
* **Audit**: `AGENT_CREATE`, `AGENT_ENABLE/DISABLE/DELETE`, `AGENT_CREDENTIAL_ISSUED` (credential id, scopes,
  expiry, acting admin), `AGENT_CREDENTIAL_REVOKED`, and for every token `AGENT_TOKEN` (user = owner, client =
  agent, credential id, scope, audience) or `AGENT_TOKEN_ERROR` with a fixed reason (`disabled`, `malformed`,
  `unknown_credential`, `revoked`, `expired`, `owner_missing`, `owner_disabled`, `scope`, `audience`). Token events
  follow the realm's `authEventsEnabled`, the rest its `adminEventsEnabled`.
* **Retention**: ended credential rows are kept 30 days for audit and then deleted by the existing purge loop.
* `last used` is recorded per credential (best effort).

## Admin API

Under `/admin/v1/realms/{realm}`; mutating calls are audited (see `SPEC.md`).

| Method and path | Purpose |
|---|---|
| `GET /agents[?owner=<userId>]` | list |
| `POST /agents` | `{name, ownerUserId, scopes[], roles[]?, audiences[]?, tokenTtlSeconds?}` |
| `GET /agents/{id}` | read |
| `POST /agents/{id}/enable`, `/disable` | switch |
| `DELETE /agents/{id}` | delete the agent, its credentials and its backing client |
| `GET /agents/{id}/credentials` | list (state `active`, `revoked`, `expired`; never the secret) |
| `POST /agents/{id}/credentials` | `{ttlSeconds?, scopes[]?, note?}` (send `{}` for defaults); returns `secret` once |
| `DELETE /agents/{id}/credentials/{credentialId}` | revoke one (409 if already ended) |
| `POST /agents/{id}/revoke-credentials` | revoke every active credential; returns `{"revoked": n}` |

## Not yet

* Creating, editing and issuing credentials is Admin API only. An owner can list their agents and revoke their
  credentials in the [account console](account-console.md), but cannot create, disable or delete an agent there.
* No RFC 8693 delegation chain: the exchange does not take a user's access token as `subject_token` with the agent
  as `actor_token`, and `act` is not nested. The owner is fixed at registration.
* No consent screen or per-call approval, no per-agent rate limits beyond the exchange limit, no token binding
  (DPoP/mTLS) to stop a stolen access token being replayed within its TTL.
* Agents cannot be re-owned or edited: delete and recreate.
* No introspection-time revocation of already issued access tokens.
* Tested with software-generated tokens and the in-process provider; no real MCP client or server was used.
