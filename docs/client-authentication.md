# Strong client authentication: private_key_jwt and mutual TLS

A client secret is a password: it travels with every request and whoever copies it can be the client.
haven-idp lets a client authenticate by proving possession of a **private key** instead:

* **`private_key_jwt`** ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523), OpenID Connect Core section 9): the
  client signs a short, single-use JWT for each request.
* **`tls_client_auth`** and **`self_signed_tls_client_auth`** ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)):
  the client presents a certificate on the TLS connection.
* **Certificate-bound access tokens** (RFC 8705 section 3): the access token carries `cnf.x5t#S256` and only works
  together with that certificate.

Everything is **off until you configure it**. A client without an authentication setting behaves exactly as
before (secret by `client_secret_basic` or `client_secret_post`, or no secret for a public client). Mutual TLS is
additionally off for the whole server until you say where client certificates come from.

## The rule: one method, no fallback

Once a client has a method, that is the only way it authenticates, on **every** endpoint that authenticates
clients: token, introspection, revocation, pushed authorization requests (`/par`), CIBA
(`/ext/ciba/auth`) and device authorization (`/auth/device`).

* A `private_key_jwt` or mutual TLS client is refused with a secret (even the right one), with only its
  `client_id`, and even if an administrator later marks it public.
* Switching a client to one of these methods **deletes its secret**. Regenerating a secret answers `409` while the
  method is set, and removing the setting does not bring the old secret back.
* If the settings cannot be read, the request fails (`500`). haven-idp never assumes "no method".
* `client_secret_basic` and `client_secret_post`, when set explicitly, are enforced too (the other form is refused).
* Every failure is the same `401 invalid_client`. The server log has a fixed reason label (for example `replay`,
  `aud`, `untrusted_chain`), never credential material.

## Configure a client

Admin API (`internal/idp/admin/SPEC.md`, section "Client authentication"):

```sh
# {id} is the client's UUID
curl -s -X PUT https://idp.example/admin/v1/realms/demo/clients/$ID/authentication \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"method":"private_key_jwt","jwksUri":"https://app.example/jwks.json","signingAlg":"ES256"}'
```

| Field | Used by | Meaning |
|---|---|---|
| `method` | all | `client_secret_basic`, `client_secret_post`, `none` (public clients), `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` |
| `jwks` / `jwksUri` | `private_key_jwt`, `self_signed_tls_client_auth` | exactly one: inline public keys, or an https URL. Self signed needs `x5c` (the certificate) in the key |
| `signingAlg` | `private_key_jwt` | optional: accept only this algorithm |
| `tlsSubjectDn`, `tlsSanDns`, `tlsSanUri`, `tlsSanIp`, `tlsSanEmail` | `tls_client_auth` | exactly one: what the certificate must say |
| `certificateBoundTokens` | any confidential client | bind access tokens to the certificate of the token request |

`GET` returns the settings, `DELETE` removes them. The admin client the console uses must keep its secret (`409`).

## private_key_jwt

The client sends, instead of a secret:

```
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<signed JWT>
client_id=<optional, must equal sub>
```

Sending a `client_secret` or an `Authorization` header as well is `400 invalid_request`.

| Check | Rule |
|---|---|
| size | at most 8 KiB, compact JWS |
| `alg` | `ES256`, `PS256`, `RS256` (RSA 2048 to 8192 bits) or `EdDSA` (Ed25519). `none` and `HS*` are never accepted. `signingAlg` narrows it to one |
| header | no `crit`; `typ` absent, `JWT` or `client-authentication+jwt` (so a DPoP proof or request object does not work); `jwk`, `jku`, `x5u` are ignored |
| key | only from the client's registration; with several candidates a `kid` is required |
| `iss`, `sub` | both exactly the `client_id` |
| `aud` | the issuer, the token endpoint URL, or the URL of the endpoint being called. As an array, **every** entry must be one of these. Prefer the issuer alone |
| `exp` | required, not passed (60 s clock skew), at most 10 minutes ahead |
| `iat`, `nbf` | optional; not in the future; `exp - iat` at most 10 minutes |
| `jti` | required, at most 256 characters, **single use** |
| other claims | `response_type`, `redirect_uri`, `request`, `htm`, `htu` are refused (that is not a client assertion) |
| duplicates | duplicate JSON member names are refused |

**Replay cache.** After the signature and claims pass, `sha256(client | jti)` is stored per realm until the
assertion can no longer be accepted; a second use fails on any endpoint, and of several concurrent uses exactly one
wins (memstore and Postgres). If the store cannot record it, the request fails. A forged assertion records nothing,
so it cannot burn a real `jti`. Each client and address may spend 3000 assertions per 10 minutes (`429`).

A minimal assertion payload:

```json
{"iss":"reports","sub":"reports","aud":"https://idp.example/realms/demo",
 "jti":"6f1c...random","iat":1795000000,"exp":1795000060}
```

## Client keys from `jwks_uri`

* `https` only (the Admin API of `haven-idp dev` also allows `http` to loopback; dynamic registration never does).
* Fetched with the same SSRF-safe client as federation and metadata documents: the destination address is checked at
  dial time (private, loopback, link-local and similar are refused), no redirects, no proxy from the environment,
  TLS 1.2 or newer, 5 second timeout, 64 KiB, at most 20 keys. Only a `200` counts. Keys with private members are
  never used.
* Cached for 5 minutes. A copy older than that is **never** used: if the URL cannot be read then, authentication
  fails.
* An unknown `kid` (or an unknown certificate) triggers a refetch, but one URL is fetched at most once per 30
  seconds, successful or not, so strangers cannot make haven-idp hammer a client's server. A key rotation is
  therefore picked up within 30 seconds of the first request that uses the new key. Publish the new key before
  you start signing with it.
* The cache and the 30 second limit are per replica.

## Mutual TLS

### Where the certificate comes from (read this first)

haven-idp believes a client certificate **only** when the deployment states its source. There is no default.

| Setting | Effect |
|---|---|
| `HAVEN_IDP_TLS_CERT_FILE`, `HAVEN_IDP_TLS_KEY_FILE` | haven-idp serves HTTPS itself (otherwise plain HTTP, as before). Certificates are read at start |
| `HAVEN_IDP_MTLS=direct` | with the two above: ask TLS clients for a certificate. The handshake proves they hold its key |
| `HAVEN_IDP_MTLS_PROXY_HEADER` | the header in which a TLS-terminating proxy forwards the client certificate |
| `HAVEN_IDP_MTLS_TRUSTED_PROXIES` | required with the header: addresses or CIDRs of the proxies (`/0` is refused) |
| `HAVEN_IDP_MTLS_CA_FILE` | PEM trust anchors for `tls_client_auth`. Without it that method is off |

Contradictory or half settings (direct and header together, a header without proxies, a CA without a mode) stop the
server at start.

**The threat of a certificate header.** A certificate is public. Anyone who can get a request with that header to
haven-idp *from a trusted address* can claim to be any certificate-authenticated client and can use any
certificate-bound token whose certificate they have seen. haven-idp cannot tell a proxy's header from a forged
one. Use the header only when all of this holds:

1. the proxy terminates the client's TLS and **requires proof of possession** (it forwards only the certificate of
   its own handshake; for nginx, `ssl_verify_client optional_no_ca` or `optional` does this);
2. the proxy **sets or deletes the header on every request**, on every virtual host and path that reaches haven-idp,
   including requests without a certificate;
3. nothing but the proxy can connect to haven-idp from the trusted addresses (network policy or a dedicated
   interface; a CIDR that covers other pods, jobs or users is not enough);
4. the link between proxy and haven-idp cannot be tampered with.

haven-idp enforces what it can: the header is ignored unless the TCP peer (never `X-Forwarded-For`) is in the list,
exactly one header value is accepted, it must contain exactly one certificate, and in every other mode the header is
not read at all.

```nginx
# nginx in front of haven-idp
ssl_verify_client optional_no_ca;                 # haven-idp verifies the chain itself
location /realms/ {
    proxy_set_header X-Client-Cert $ssl_client_escaped_cert;   # empty when there is none: nginx then sends no header
    proxy_pass http://haven-idp:8081;
}
```

Accepted header forms: URL-encoded PEM (nginx `$ssl_client_escaped_cert`), base64 DER, and the
[RFC 9440](https://www.rfc-editor.org/rfc/rfc9440) `Client-Cert` byte sequence `:base64:`. Envoy's
`x-forwarded-client-cert` format is not understood. The nginx snippet above is illustrative: it was not run against
haven-idp.

In `direct` mode the server requests (does not require) a certificate on every connection, so browsers that have
personal certificates may prompt users to pick one. Serve browsers from a separate name behind a proxy if that
matters.

### `tls_client_auth` (PKI)

The certificate must be within its validity period, chain to a certificate in `HAVEN_IDP_MTLS_CA_FILE` (the system
roots are never used), allow client authentication (extended key usage), and match the one configured identifier:

* `tlsSubjectDn`: the subject in [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514) string form, compared exactly,
  attribute order included. For the usual attributes this prints it:
  `openssl x509 -in client.pem -noout -subject -nameopt RFC2253` (strip `subject=`). Attributes outside
  CN, SERIALNUMBER, C, L, ST, STREET, O, OU and POSTALCODE are written as OID and hex DER; prefer a SAN then.
* `tlsSanDns` (case-insensitive, no wildcard matching), `tlsSanUri`, `tlsSanIp`, `tlsSanEmail`.

In `direct` mode intermediates sent by the client are used to build the chain. A proxy header carries only the leaf,
so put the intermediates into the CA file. **Revocation (CRL, OCSP) is not checked**: use short-lived
certificates, or disable the client.

Every CA in the file can vouch for any client that is matched by name. List only CAs that issue names you control.

### `self_signed_tls_client_auth`

The client registers its certificate as `x5c` of a key in `jwks` or `jwks_uri`. The presented certificate must be
byte for byte one of those and within its validity period. No CA is involved.

The request in both methods carries `client_id` and no other credential (a `client_secret` or `Authorization` header
is refused).

## Certificate-bound access tokens

With `certificateBoundTokens` (RFC 8705 `tls_client_certificate_bound_access_tokens`), for any confidential client
and any authentication method:

* the token endpoint refuses a request without a valid client certificate **before** a code or refresh token is
  consumed (`400 invalid_request`);
* access tokens carry `cnf: {"x5t#S256": "<base64url SHA-256 of the certificate>"}`, `token_type` stays `Bearer`.
  The certificate need not be CA issued for binding;
* every grant is checked: if a grant would hand such a client an unbound token, the request fails;
* **userinfo** accepts the token only with that certificate; the Admin API refuses all bound tokens;
* **introspection** reports `cnf`, so your resource server can compare it with the certificate on its own TLS
  connection. **haven-idp cannot do that for you**: a resource server that ignores `cnf` treats the token as a
  plain bearer token;
* with DPoP on the same request the token carries both `jkt` and `x5t#S256`, and both are enforced.

A refresh binds the new access token to the certificate of that refresh request; refresh tokens of confidential
clients are protected by client authentication, not bound to a certificate (RFC 8705 section 7.1). Public clients
cannot use certificate binding here.

## Dynamic client registration

A registration may ask for `private_key_jwt`, `tls_client_auth` or `self_signed_tls_client_auth` with the RFC
metadata names (`jwks`, `jwks_uri`, `token_endpoint_auth_signing_alg`, `tls_client_auth_subject_dn`,
`tls_client_auth_san_dns|uri|ip|email`, `tls_client_certificate_bound_access_tokens`). Such a client gets **no
secret**. TLS methods are refused when the server has no mutual TLS (and `tls_client_auth` without a CA file). An
RFC 7592 update may rotate keys or move a secret client to a key method; it can never move a key or certificate
client back to a secret, nor switch certificate binding off. An update otherwise replaces the authentication
settings (a Basic or POST pin an administrator added is removed). Secret methods chosen at registration are not
pinned to Basic or POST (only settings for key or certificate methods or for certificate binding are stored and
enforced).

## Discovery

With a store that supports it: `private_key_jwt` is added to `token_endpoint_auth_methods_supported`,
`introspection_endpoint_auth_methods_supported` and `revocation_endpoint_auth_methods_supported`, with the matching
`*_auth_signing_alg_values_supported: ["ES256","PS256","RS256","EdDSA"]`. With mutual TLS on,
`self_signed_tls_client_auth` (and `tls_client_auth` when a CA file is set) and
`tls_client_certificate_bound_access_tokens: true` are added.

## Storage

Postgres migration `0023_client_auth.sql`: `client_auth` (per client, `ON DELETE CASCADE`, public keys only) and
`client_assertions` (sha256 of client and `jti`, with expiry; purged every 5 minutes by `haven-idp serve`). A store
without `core.ClientAuthStore` offers none of this and refuses every assertion. `dev --persist` keeps the settings.

## Not yet

* `client_secret_jwt` (secrets are stored hashed, so HMAC assertions cannot be verified).
* Certificate revocation checking (CRL, OCSP), a reload of the TLS certificate or CA file without restart,
  `mtls_endpoint_aliases`, Envoy `x-forwarded-client-cert`, certificate chains in the proxy header.
* Certificate binding for public clients and their refresh tokens.
* A realm-wide "require strong client authentication" switch; the console has no screen for these settings.
* Configuration as code, export/import and Time Machine undo do not carry these settings: a client recreated by
  them has no method and no keys until you set them again.
* A deployment without `HAVEN_IDP_MTLS*` still accepts a `tls_client_auth` setting in the Admin API; that client
  simply cannot authenticate.
* The Helm chart and the Kubernetes controller do not set any of the TLS variables.
* The jwks cache and fetch limit are per replica.
* Not tried with an OAuth client library, a real reverse proxy, or the OpenID conformance suite. A local run used
  assertions signed with PyJWT, certificates made with `openssl`, and a script in place of the proxy.
