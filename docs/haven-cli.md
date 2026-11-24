# The `haven` command-line client

`haven` logs a person in to haven-idp (or any OIDC provider that supports the
[OAuth 2.0 Device Authorization Grant, RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628))
from a terminal, keeps the credentials safe on disk, and hands them to other
tools: scripts (`haven token`), `kubectl` (`haven exec-credential`), CI.

It is a single static binary with no third-party dependencies and no
interactive prompts other than "open this URL".

## Install

```sh
make build-haven                 # -> bin/haven
# or
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o haven ./cmd/haven
```

It builds for linux, darwin and windows (`GOOS=windows`: see "Not yet" for the
one difference).

## Prerequisite: a public client with the device grant

Register a **public** client (no secret) that is allowed the
`urn:ietf:params:oauth:grant-type:device_code` grant, and `offline_access` if
you want refresh tokens. The client id is what you pass as `--client-id`.

## Commands

| Command | What it does |
|---|---|
| `haven login --issuer URL --client-id ID` | Device flow login, stores credentials |
| `haven token [--id-token] [--min-validity 60s]` | Prints a fresh access (or ID) token to stdout, nothing else |
| `haven whoami [--json]` | Shows the ID token claims and the userinfo answer |
| `haven logout` | Revokes the refresh token at the server (best effort), deletes local credentials |
| `haven exec-credential --issuer URL --client-id ID` | kubectl exec credential plugin |
| `haven version`, `haven help` | |

Common flags: `--profile NAME` (default `default`; keep several logins side by
side), `--ca-file PEM`, `--insecure-http`, `--allow-cross-origin-endpoints`.
`login` also takes `--scope` (default `openid offline_access profile email`)
and `--no-browser`.

### Login

```text
$ haven login --issuer https://idp.example.com/realms/platform --client-id haven-cli
To sign in, open this page in any browser:

    https://idp.example.com/realms/platform/device

and enter the code:

    ABCD-EFGH

The code expires in 10m0s.
Opening your browser; the code is pre-filled.
Waiting for you to approve the sign-in (Ctrl-C to cancel)...

Logged in as alice <alice@example.com>
```

`haven` tries `open` (macOS) or `xdg-open` (Linux with a display) on
`verification_uri_complete`; with `--no-browser`, or when that fails, nothing
else changes. It then polls the token endpoint honouring the server's
`interval`, adds 5 s on `slow_down`, keeps waiting on `authorization_pending`,
and stops with exit 1 on `access_denied`, `expired_token` or when the local
deadline passes. Ctrl-C cancels cleanly and stores nothing. Tokens are never
printed.

### Scripts and CI

```sh
curl -H "Authorization: Bearer $(haven token)" https://api.example.com/v1/things
```

`haven token` prints exactly one line (the token) on stdout; diagnostics go to
stderr. It refreshes first when the token expires within `--min-validity`
(default 60 s). When there is no session, or the refresh token was rejected
(`invalid_grant`; the dead credentials are deleted), it exits **3** with a hint
to run `haven login`.

Device flow needs a human, so CI cannot log in by itself. Two patterns work:
log in once on a workstation and ship the credentials file as a CI secret
(a refresh token with rotation: the job must be the only user of that copy), or
use a service-account client with the client-credentials grant, which is
outside `haven`'s scope. Never put a token on a command line (it shows up in
`ps` and shell history); capture `haven token` into a variable or pipe it.

### kubectl

Point the Kubernetes API server at haven-idp (`--oidc-issuer-url`,
`--oidc-client-id`, usually `--oidc-username-claim=preferred_username`), run
`haven login` once, then use the exec plugin in your kubeconfig:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: prod
    cluster:
      server: https://k8s.example.com:6443
users:
  - name: alice
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        interactiveMode: Never
        command: haven
        args:
          - exec-credential
          - --issuer=https://idp.example.com/realms/platform
          - --client-id=haven-cli
          # - --profile=prod        # when you keep several logins
          # - --ca-file=/etc/haven/ca.pem
contexts:
  - name: prod
    context: {cluster: prod, user: alice}
current-context: prod
```

`exec-credential` prints the `ExecCredential` JSON with the **ID token** and
its `exp` as `expirationTimestamp`, refreshing as needed. It never prompts
(`kubectl` captures stdout): if you are not logged in it exits 3 with
"run `haven login`" on stderr, so `interactiveMode: Never` is accurate. It also
refuses a profile that was logged in to a different issuer or client.

## Credentials

`$XDG_CONFIG_HOME/haven/credentials.json` (default `~/.config/haven/`), keyed by
profile: issuer, client id, scopes, access/ID/refresh tokens and expiries.
Directory `0700`, file `0600`, written atomically (temp file + `fsync` +
rename). If an existing file or directory is group/world accessible, `haven`
warns on stderr and tightens it instead of refusing (a stray umask should not
lock you out; the tokens were already there). A file that is not valid JSON, or
is not a regular file, is refused.

Refresh-token **rotation** means each refresh token works once. Refreshing
therefore happens under an advisory file lock (`credentials.lock`, `flock`) and
the profile is re-read after the lock is taken, so any number of concurrent
`haven token` / `kubectl` invocations refresh exactly once and all return the
same new token.

## Security notes

- Plain `http://` issuers are refused unless the host is loopback
  (`localhost`, `127.0.0.0/8`, `::1`) or you pass `--insecure-http`, which warns
  loudly every time.
- The discovery document's `issuer` must equal the issuer you passed (mix-up
  defence). The device, token, userinfo, revocation and JWKS endpoints must be
  https (or loopback http) and have the **same origin** as the issuer, unless
  `--allow-cross-origin-endpoints` (which still never allows non-loopback plain http).
- The HTTP client has 30 s timeouts, TLS 1.2+, a 1 MiB response cap, never
  follows a redirect of a POST (token, device, revocation) and only follows
  same-origin redirects for GETs. `--ca-file` adds a private CA to the system
  pool; `login` remembers it in the profile.
- ID tokens are validated: `iss`, `aud` (and `azp`), `exp`, and the signature
  against the issuer's JWKS (ES256 and RS256 only; `none` and HMAC are refused).
  If the provider publishes no `jwks_uri`, claims are still checked and `login`
  warns that the signature was not verified; `whoami` states the verification
  result in its output and JSON (`id_token_signature_verified`). `nonce` is not
  checked: the device flow has no nonce parameter, so none is ever sent.
- Tokens are never accepted as flags, never logged, never in error messages and
  never printed by `login`, `whoami` or `logout`. Only `token` and
  `exec-credential` write a token, to stdout only. Server-provided text shown
  to you has control characters stripped.
- The device code and refresh token travel in POST bodies only.
- `whoami` also checks that the userinfo `sub` equals the ID token `sub`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error (network, server refused, denied/expired login, bad credentials file, cancelled) |
| 2 | usage (bad flags, refused insecure issuer, invalid profile name) |
| 3 | not logged in / session no longer refreshable: run `haven login` |

## Not yet

- No client-credentials / service-account mode and no non-interactive login.
- No Windows cross-process lock: on Windows the lock only serialises threads of
  one process, so two `haven` processes refreshing at the same instant can race
  (and lose the rotated refresh token). Windows is compile-checked, not exercised.
- No OS keychain storage (macOS Keychain, libsecret); tokens are in a 0600 file.
- No `nonce` or `at_hash` checks, no JWKS caching (one fetch per login/refresh/whoami).
- Exercised against the real `haven-idp dev` device endpoint (login with approval, `token`, `whoami`,
  `exec-credential`, `logout`; no token in any output or server log). Not run against other providers:
  the unit tests use an in-test fake IdP that follows RFC 8628.
- No shell completion; no PKCE authorization-code (browser redirect) login.
