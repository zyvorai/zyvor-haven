# Workload identity (no static secrets)

A pod, a CI job or any other workload that already holds a token from a platform it runs on (most commonly a
Kubernetes **projected service-account token**) can trade that token for a short-lived Haven access token. No
client secret is created, stored, rotated or leaked: the platform token is the proof.

It uses the OAuth 2.0 Token Exchange grant ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) and, as an
alternative spelling, the JWT bearer grant ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) section 2.1).
The feature is **off** until you register a workload identity, and off entirely when the store has no support
for it (`501 feature_unavailable`).

## How it works

```
Pod                                   haven-idp                            Cluster issuer
 | read /var/run/secrets/.../token        |
 | POST .../token                         |
 |   grant_type=...:token-exchange        |
 |   client_id=wl-payments                |
 |   subject_token=<projected JWT>        |   (JWKS from an inline document,
 |   subject_token_type=...:jwt           |    or fetched through the SSRF-safe client)
 |   scope=read                           |
 | <- access_token (5-60 min), no refresh |
```

A **workload identity** pins everything about one workload; nothing is matched by pattern:

| Field | Meaning |
|---|---|
| `name` | unique per realm, `[a-z0-9._-]` |
| `clientId` | the workload's client (default `wl-<name>`). Haven **creates** it: public, no secret, no redirect URIs, every interactive flow off. An existing client id is never adopted (409) |
| `issuer` | the token's `iss`, compared exactly (for Kubernetes: the cluster's service-account issuer URL) |
| `jwksUri` **or** `jwks` | where the issuer's public keys come from (exactly one) |
| `audience` | the token's `aud` must contain exactly this. Request it when you project the token (`audience: haven`), so a token minted for another service is useless here |
| `subject` | the token's `sub`, compared exactly: `system:serviceaccount:<namespace>:<serviceaccount>` |
| `scopes` | the allow-list of scopes the workload may ask for; asking for any other scope is `invalid_scope`; omitting `scope` means all of them |
| `ttlSeconds` | lifetime of the issued token, 30 to 3600 (default 600); never longer than the realm access token TTL |

### Keys: `jwks` versus `jwksUri`

* `jwks`: an inline JWKS document (at most 64 KiB; RSA of at least 2048 bits or P-256 EC keys). Use this for
  clusters whose API server is private: copy `kubectl get --raw /openid/v1/jwks`. Nothing is fetched at exchange
  time, so there is no outbound request to attack. Rotate it with a new identity when the cluster rotates keys.
* `jwksUri`: an `https` URL (EKS, GKE, AKS and OIDC discovery buckets publish theirs). It is fetched with the same
  SSRF-hardened client as federation and back-channel logout: no redirects, no proxy, bounded body and time, and
  the destination IP is checked after DNS resolution (loopback, private, link-local, CGNAT, NAT64 and so on are
  refused). Keys are cached 10 minutes, with one rate-limited refresh for an unknown `kid`. The Kubernetes API
  server itself usually requires authentication and sits on a private address, so it cannot be used here.

### Subject token checks (all must pass, else `invalid_grant` with no detail)

* at most 16 KiB, three base64url parts;
* algorithm `RS256`, `PS256` or `ES256` only (`none` and every HMAC algorithm are refused);
* signature verifies against the pinned keys (key type must match the algorithm; `kid` must select one key);
* `iss` equals the configured issuer, `aud` contains the configured audience, `sub` equals the configured subject;
* `exp` is present and not past (60 s skew); `iat` and `nbf` not in the future (60 s skew).

The reason for a rejection is **never** returned to the caller. It is written to the audit log as a fixed label
(`issuer_mismatch`, `bad_audience`, `bad_subject`, `expired`, `bad_signature`, `bad_alg`, `unknown_key`, `bad_url`,
`bad_time`, `bad_token`, `disabled`, `scope`).

### Client checks

The calling client must be enabled, **public**, and have `AuthCodeFlow`, `PasswordFlow`, `DeviceFlow` and
`ServiceAccount` all off. If an administrator turns one of those on for the backing client, the identity stops
working (`unauthorized_client`) instead of silently gaining a second way in. A confidential client (one with a
secret) is refused: workload identity is the no-secret path.

## Request and response

```
POST /realms/{realm}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=wl-payments
&subject_token=<projected token>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&scope=read
```

or `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&client_id=wl-payments&assertion=<token>`.

```json
{"access_token":"...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
 "token_type":"Bearer","expires_in":600,"scope":"read"}
```

Refused with `invalid_request`: `actor_token`, a `requested_token_type` other than `access_token`, an unknown
`subject_token_type`, more than one `subject_token` or `assertion`. `audience` and `resource` are refused
(`invalid_target`) for workload tokens.

Access token claims: `iss`, `sub` = `workload-<clientId>`, `aud` = `<clientId>`, `azp`, `client_id`, `scope`,
`exp`, `iat`, `jti`, `typ=Bearer`, `workload_issuer`, `workload_subject`, and an empty `realm_access.roles`.
There is no ID token and no refresh token: the workload exchanges again.

A Kubernetes pod spec:

```yaml
volumes:
  - name: haven
    projected:
      sources:
        - serviceAccountToken:
            audience: haven
            expirationSeconds: 3600
            path: token
```

## Security properties

* **Fail closed.** Any missing store support, disabled identity, unbound client, bad token or limiter error ends
  in an OAuth error. A rate-limiter failure denies (`server_error`); it never allows.
* **Exact pins.** Issuer, audience and subject are single strings compared in constant time. Wildcards in
  `subject` and `audience` are refused at registration. One client is bound to one subject; a token for another
  service account cannot be used with it.
* **No secret at rest or in logs.** The platform token is never stored or logged. The JWKS is public data.
* **Rate limit.** 60 attempts per minute per (realm, client IP, client id), shared across replicas through the
  store; above that, `429 slow_down`.
* **Audit.** Every issue writes `WORKLOAD_TOKEN` (detail: workload name and granted scope); every rejection writes
  `WORKLOAD_TOKEN_ERROR` (detail: workload name and the fixed reason label). Registration changes write
  `WORKLOAD_IDENTITY_CREATE/ENABLE/DISABLE/DELETE`. Token events follow the realm's `authEventsEnabled`, admin
  events its `adminEventsEnabled`.
* **Short lived, not revocable once issued.** Issued tokens are JWTs and live at most `ttlSeconds`. To cut a
  workload off, disable or delete its identity (no new tokens at once); tokens already issued stay valid until
  they expire. Keep `ttlSeconds` small.

## Configuration

None beyond the registration below. Workload identity needs a store that supports it (`memstore` and Postgres
do; Postgres migration `0015_workload_identities.sql`). The default outbound client enforces the SSRF policy;
`haven-idp dev` relaxes it for loopback only.

## Admin API

All under `/admin/v1/realms/{realm}`, admin-authenticated; mutating calls are audited. See `SPEC.md`.

| Method and path | Purpose |
|---|---|
| `GET /workload-identities` | list |
| `POST /workload-identities` | create `{name, clientId?, issuer, jwksUri\|jwks, audience, subject, scopes[], ttlSeconds?}` (creates the backing client) |
| `GET /workload-identities/{id}` | read (the inline JWKS body is not echoed; `inlineJwks: true`) |
| `POST /workload-identities/{id}/enable` and `/disable` | switch |
| `DELETE /workload-identities/{id}` | delete the identity and its backing client |

## Not yet

* No single-use enforcement of the platform token (`jti`): a projected token can be exchanged repeatedly until its
  own `exp`, which is how kubelet-refreshed tokens are meant to be used. Use a short `expirationSeconds`.
* No claim mapping beyond `sub` (for example matching on `kubernetes.io` claims such as the pod name or node), no
  pattern or group subjects: register one identity per service account.
* No update endpoint: delete and recreate to change the pins, keys or scopes.
* No automatic JWKS rotation for an inline `jwks`; use `jwksUri` where the issuer publishes one.
* Workload tokens carry no roles. Authorization is by scope.
* Only the Kubernetes-style JWT shape was exercised, with software-signed test tokens. It has not been run against
  a real cluster or a cloud issuer.
