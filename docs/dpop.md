# DPoP: sender-constrained tokens

haven-idp implements Demonstrating Proof of Possession ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)).
A client generates a key pair and signs a small JWT (a "proof") for every request. The access token the server
issues is bound to that key, so a stolen token is useless without the private key. For public clients (browsers,
CLIs, mobile apps) the refresh token is bound to the key as well.

DPoP is **opt-in per request**: a client that sends no `DPoP` header gets ordinary bearer tokens exactly as before.
There is no per-client switch yet (see "Not yet").

## What happens

```
client                                         haven-idp
  | POST /token  DPoP: <proof: htm=POST, htu=.../token>
  |----------------------------------------------->|  validates the proof, remembers its jti
  | <- {"token_type":"DPoP","access_token":"...cnf.jkt...","refresh_token":"..."}
  |
  | GET /userinfo
  |   Authorization: DPoP <access_token>
  |   DPoP: <proof: htm=GET, htu=.../userinfo, ath=sha256(access_token)>
  |----------------------------------------------->|  token's cnf.jkt must equal the proof key's thumbprint
```

* **Access token** gets `cnf: {"jkt": "<RFC 7638 SHA-256 thumbprint>"}`; the response says `token_type: "DPoP"`.
  This applies to every grant that issues tokens (authorization code, refresh, device, `client_credentials`).
* **Refresh token** of a **public** client is bound to the key (the binding is stored by the token's sha256).
  Redeeming it needs a proof from the same key; a missing or different key is `400 invalid_dpop_proof` and the
  token is **not** consumed. The rotated refresh token inherits the binding. Confidential clients authenticate
  themselves, so their refresh tokens are not key-bound (RFC 9449, section 5); their access tokens still are.
* **Userinfo** accepts `Authorization: DPoP <token>` plus a proof with `ath`. A bound token presented as
  `Bearer`, without a proof, with another key, with a wrong `ath`/`htu`/`htm`, or with a replayed proof is
  `401` with `WWW-Authenticate: DPoP error="invalid_token" | "invalid_dpop_proof", algs="ES256 RS256 EdDSA"`.
  A token that is *not* bound is refused under the `DPoP` scheme.
* **Introspection** (`/token/introspect`, confidential client) reports `cnf` and `token_type: "DPoP"` for bound
  access tokens and `cnf` for bound refresh tokens. The resource server then checks the request's proof against
  `cnf.jkt` itself (it holds the proof; haven-idp does not).
* **Admin API** never accepts a token that carries `cnf` (it does not verify proofs), so a DPoP-bound admin
  token cannot be used as a bearer token there.
* **Discovery** lists `dpop_signing_alg_values_supported: ["ES256","RS256","EdDSA"]` when the store supports it.

## Proof validation (all must hold, otherwise `invalid_dpop_proof`)

| Check | Rule |
|---|---|
| header count | exactly one `DPoP` header, at most 4096 bytes |
| JWS header | `typ` = `dpop+jwt`; `alg` one of `ES256`, `RS256`, `EdDSA`; `jwk` present; no `crit`; no private members (`d`, `p`, `q`, ...) |
| key | must match `alg`: EC P-256 / RSA (2048 to 8192 bits, odd `e`) / OKP Ed25519; EC points are checked to be on the curve; `none`, `HS*`, `ES384`, `PS*` are refused |
| signature | verified with the embedded `jwk` |
| `jti` | present, at most 256 characters, **not seen before** for this key (replay cache, see below) |
| `htm` | equals the request method |
| `htu` | equals the endpoint URL built from the server's configured base URL (scheme and host case-insensitive, query and fragment ignored). The `Host` header is never trusted. |
| `iat` | within 60 seconds of the server clock in either direction |
| `ath` | on resource requests: equals base64url(sha256(access token)) |
| `nonce` | only when `HAVEN_IDP_DPOP_NONCE=1`, see below |

Anything that fails is rejected; a DPoP header is never silently ignored. At the token endpoint the error is
`400 {"error":"invalid_dpop_proof"}`; error descriptions are fixed text and never contain the proof.

**Replay cache.** After the signature checks pass, `sha256(jkt | jti)` is stored per realm for 2 minutes and a
second use is rejected (exactly one of several concurrent uses wins, in memstore and in Postgres). Only the hash is
stored. If the store cannot remember the proof the request fails (`500 server_error`), never open. A store that has
no DPoP support (a custom `core.Store` without `core.DPoPStore`) rejects every request that carries a proof and
leaves `dpop_signing_alg_values_supported` out of discovery. Remembering proofs costs storage, so each client
address may present at most 1200 valid proofs per 10 minutes (`429`); if the rate limiter itself fails the request
fails.

**Nonces (optional).** With `HAVEN_IDP_DPOP_NONCE=1` every proof must carry a server nonce. A proof without a valid
one gets `400 use_dpop_nonce` (resource endpoints: `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"`) and a
`DPoP-Nonce` header; the client retries with that nonce. Nonces are stateless (HMAC of realm and a 5 minute bucket,
the current and the previous bucket are accepted) and keyed by `HAVEN_IDP_CSRF_KEY`, so **set that key when you run
several replicas**, otherwise a nonce from one replica is not valid on another and clients just retry.

## Example (curl and openssl cannot sign JWTs easily; use any client library)

```
POST /realms/demo/protocol/openid-connect/token
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwiandr...   (htm=POST, htu=https://idp.example/realms/demo/protocol/openid-connect/token)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=...&redirect_uri=...&client_id=app&code_verifier=...
```

## Configuration

| Setting | Effect |
|---|---|
| (none) | DPoP is on whenever the store supports it (memstore and Postgres do). Clients opt in by sending a proof. |
| `HAVEN_IDP_DPOP_NONCE=1` | require server nonces |
| `HAVEN_IDP_BASE_URL` | the `htu` of every proof must match it, so it must be the URL clients really use (behind a proxy, the public URL) |

Postgres: migration `0014_dpop.sql` adds `dpop_proofs` and `dpop_refresh_bindings` (hashes only). Expired rows are
ignored on read and replaced on insert; `PurgeExpiredDPoP` deletes them (nothing schedules it yet).

## Security properties and what they rely on

* A stolen access token or refresh token (public client) is useless without the private key.
* A captured proof is single use and short lived, and is tied to one method and one URL (and one token, via `ath`).
* No custom crypto: only `crypto/ecdsa`, `crypto/rsa`, `crypto/ed25519`; no new dependencies.
* The first token request is not proof of anything beyond key possession: whoever redeems an authorization code
  with a proof gets tokens bound to that key. PKCE protects the code itself.

## Not yet

* A realm-wide "DPoP required" and the `dpop_bound_access_tokens` client metadata of dynamic registration.
  A per-client "require DPoP" and `dpop_jkt` at the authorization endpoint exist now, see
  [fapi-par-jar-rar.md](fapi-par-jar-rar.md).
* DPoP on the revocation endpoint, on dynamic client registration and for client authentication (`private_key_jwt`
  is not implemented at all).
* Resource servers other than userinfo must verify proofs themselves (use introspection `cnf`).
* Bound refresh tokens of a confidential client (not required by the RFC), and mTLS certificate binding (RFC 8705).
* A scheduled purge of expired replay-cache rows; algorithms other than ES256, RS256, EdDSA (no PS256, ES384).
* Live check with an independent DPoP client library: all proofs in the tests and the live run were produced by
  hand-written code in this repository.
