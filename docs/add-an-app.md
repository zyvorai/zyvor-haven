# Add an app (wizard and Test login)

`haven-idp dev` serves an "Add an app" wizard and a live OIDC debugger in the
playground at `/dev/`. It is DEV MODE ONLY: the server is in-memory and
loopback-only, and the page must never be exposed.

## Flow

1. Start `haven-idp dev` and open `/dev/`.
2. **Add an app.** Pick a type, give it a name and redirect URI(s):
   * Single-page app: public client, PKCE S256, no secret.
   * Web server: confidential client; a secret is generated.
   * CLI or native: public client, loopback redirect only (`http://127.0.0.1:PORT`).
   * Machine-to-machine: confidential service account, `client_credentials`, no redirect URIs.
3. The client is registered through the Admin API. For confidential clients the
   generated secret is shown **once**, with a copy button. It is held in page
   memory only: not in storage, the URL, a snippet, the timeline, or any later
   server response, and the server does not log it. "Discard" wipes it; a reload
   loses it (regenerate it through the Admin API if you need another).
4. **Snippets** for Go (go-oidc + oauth2), Node (openid-client), Python
   (authlib), Rust (openidconnect), kubectl with kubelogin, nginx +
   oauth2-proxy, a browser SPA (oidc-client-ts) and curl, with issuer, client id
   and redirect URI filled in. Secrets always come from the
   `OIDC_CLIENT_SECRET` environment variable, never inline.
5. **Test login** runs authorization code + PKCE S256 in a popup that returns to
   the playground callback, then shows decoded ID and access tokens and a
   checklist. Each row is PASS, FAIL, INFO or SKIP and names the input that was
   wrong plus a concrete fix:
   redirect_uri registered, PKCE, state, iss vs discovery, aud, exp/iat (with a
   clock-skew note, 60 s tolerance), nonce, at_hash, signature (WebCrypto
   ES256 against the JWKS), `sid`/`auth_time` (INFO when absent, never FAIL),
   userinfo `sub` equals the id_token `sub`, and refresh (offline_access is
   requested). Machine-to-machine apps get a client_credentials check instead.

Tick "Also register this page" (default) so the playground callback
(`http://<host>/dev/`) is added to the client's redirect URIs; without it Test
login stops with a redirect_uri FAIL and does not start a login.

## How the backend works

The browser never holds the admin credential. `POST /dev/api/clients` (served by
`internal/idp/devui`) reads the `haven-admin` secret from the same 0600 file
`haven-idp dev` writes (`dev.json`), obtains a `client_credentials` token and
calls `POST /admin/v1/realms/{realm}/clients`. The request is refused unless:
the Host is loopback (DNS-rebinding guard), `X-Haven-Dev: 1` is present (forces
a CORS preflight that is never granted), `Origin` equals the page origin,
`Sec-Fetch-Site` (if sent) is `same-origin`, and the body is `application/json`
of at most 16 KiB. The admin secret is only sent to a loopback issuer.

Redirect URIs must be `https`, or `http` for `localhost`, `127.0.0.1` or `[::1]`;
no wildcards, fragments, credentials or whitespace. The same rule runs in the
UI (`lib.js`) and on the server (`ValidateRedirect`), tested against one shared
vector file.

## Honest limits

* Dev only. Nothing here applies to `haven-idp serve`; there is no production wizard.
* Test login needs the page origin to equal the issuer origin (use
  `127.0.0.1`, not `localhost`, if the issuer says `127.0.0.1`): the page's CSP
  allows `connect-src 'self'` only.
* An IdP-side error page (for example an unregistered redirect_uri) is shown in
  the popup instead of redirecting back; the debugger then reports that the
  popup closed without a response. The redirect_uri check is made up front from
  the URIs this wizard registered.
* The clients are created in memory and vanish on restart. The wizard cannot edit
  or delete a client.
* The admin realm is assumed to be the issuer's realm (the `dev` default).
* Snippets are templates: the Go, Node, Rust and Python ones are checked for
  syntax where tools exist (Go, Node, Python) and for escaping of hostile values,
  but are not compiled against the libraries. Rust is not compiled at all.
  Library APIs move; check each library's current docs.
* `sid` and `auth_time` are informational until SSO sessions land everywhere.
