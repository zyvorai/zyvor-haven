# Keycloak realm importer (contract)

Goal: move a Keycloak realm to haven-idp with users able to sign in with their
EXISTING passwords. Three pieces, built separately against this document.

## 1. Password formats (package `internal/idp/password`)
Stored hashes (`core.User.PasswordHash`) are self-describing strings. Supported:
* `$argon2id$v=19$m=<KiB>,t=<n>,p=<n>$<salt>$<hash>`: the native format (exists today).
* `$argon2i$v=19$m=<KiB>,t=<n>,p=<n>$<salt>$<hash>`: standard PHC, verified with `argon2.Key`.
* `$pbkdf2-sha1$i=<iter>$<salt>$<hash>`, `$pbkdf2-sha256$...`, `$pbkdf2-sha512$...`:
  salt and hash are standard base64 WITHOUT padding; the derived key length is
  `len(decode(hash))`; PBKDF2-HMAC with the named hash (`crypto/pbkdf2`).
Keycloak's argon2 `d` variant and unknown algorithms are rejected.

API (exact signatures):
```go
// ValidateEncoded checks structure and limits WITHOUT any password: known
// scheme, base64 parses, salt 8..64 bytes, hash 16..128 bytes, pbkdf2 iterations
// 1000..2_000_000, argon2 m <= 1<<20 KiB, t <= 20, p <= 16. Hostile input must
// never cause a large allocation or long computation.
func ValidateEncoded(encoded string) error

// KeycloakCredential is the relevant part of a Keycloak password credential.
type KeycloakCredential struct {
	Algorithm  string              // "pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512", "argon2"
	Iterations int                 // hashIterations
	Salt       string              // base64 (std, padded) as in the export
	Value      string              // base64 hash as in the export
	Extra      map[string][]string // additionalParameters (argon2: memory, parallelism, type, version, hashLength)
}
// FromKeycloak converts to the encodings above ("pbkdf2" = HMAC-SHA1).
func FromKeycloak(c KeycloakCredential) (string, error)
```
`(*Hasher).Verify(pw, encoded)` dispatches on the prefix; it returns
`(ok, needsRehash)` with `needsRehash == true` for EVERY non-current scheme or
weaker-than-current argon2id parameters, so the OIDC login path (which already
rehashes when asked) upgrades the user to the current argon2id on first login.
Verification is constant-time in the compare and runs the full derivation even
for a wrong password.

## 2. Server side (`internal/idp/admin`, `internal/idp/native`)
`POST /admin/v1/realms/{r}/users/import` body `{"users":[idp.ImportUser...]}`
(max 1000 users and 8 MiB per request). Per user: validate username (same rules
as user create), `ValidateEncoded(passwordHash)`, roles must exist (unknown role =>
that user errors, nothing else changes for them), groups by path must exist.
Existing username => counted as `skipped` (never modified). One bad user does not
fail the batch. Response 200 `idp.ImportResult`. Admin event `ADMIN_IMPORT` with a
count only (no usernames, no hashes). Never log or return hashes. Metrics:
`AdminOp(realm, "user", "action", ok)`. `native.Client` implements
`idp.UserImporter` by chunking into batches of 500.

## 3. Converter and CLI (`internal/idp/kcimport`, `cmd/haven-idp`)
```go
type Options struct{ Realm string /* override target realm name; default = export's realm */ }
type Result struct {
	Spec   *configcode.Spec  // realm settings, roles, groups, clients
	Users  []idp.ImportUser
	Report Report
}
func Convert(r io.Reader, o Options) (*Result, error)   // accepts a full or partial Keycloak export; a JSON array of one realm is accepted too; size cap 512 MiB streamed users, never log content
```
`Report` lists, per category, what was mapped and every Warning{Code, Where,
Message}: nothing is dropped silently. CLI (offline, reviewable steps):
* `haven-idp import-keycloak -f EXPORT.json [--realm NAME] [--out-dir DIR] [--format text|json]`
  writes `DIR/realm.yaml` (configcode file, mode 0644) and `DIR/users.json`
  (mode 0600: contains password hashes; refuses to overwrite) and prints the report.
  `-f -` reads stdin; without `--out-dir` it only prints the report (dry run).
* `haven-idp import-users -f users.json --realm NAME [--dev | --url ... connection flags as `plan`]`
  pushes users through `idp.UserImporter`, prints counts only.
Typical flow: `import-keycloak` -> review -> `apply -f realm.yaml` -> `import-users`.

### Mapping rules
* Realm: registrationAllowed->selfRegistration, verifyEmail->emailVerificationRequired,
  bruteForceProtected, sslRequired->transportSecurity, passwordPolicy (keep only
  length/digits/upperCase/lowerCase/specialChars terms; warn for every other term),
  accessTokenLifespan->accessTokenSeconds, ssoSessionIdleTimeout->sessionIdleSeconds,
  eventsEnabled->authEvents, adminEventsEnabled->adminEvents, revokeRefreshToken->
  refreshTokenRotation. Unset in the export => unmanaged (nil).
* Roles: realm roles except built-ins (`offline_access`, `uma_authorization`,
  `default-roles-*`); composite roles => warning and imported without composition.
* Groups: top-level only; sub-groups => warning (nested paths unsupported).
* Clients: skip Keycloak built-ins (account, account-console, admin-cli, broker,
  realm-management, security-admin-console); SAML clients, bearerOnly clients and
  clients using authorization services are skipped with a warning. implicit flow
  and direct access grants (password grant) are turned off with a warning.
  Wildcard redirect URIs and origins are dropped with a warning (a client left
  with no redirect URI is still emitted, flagged). Confidential clients get NEW
  secrets on apply: the report says so and names them (secrets in the export are
  never read into the output).
* Users: skip service-account users; map enabled/emailVerified/requiredActions
  (only UPDATE_PASSWORD, VERIFY_EMAIL kept, others warned); realmRoles->roles,
  groups paths; password credential -> `PasswordHash` via `FromKeycloak` (new
  `secretData`/`credentialData` JSON-string format AND the legacy
  `hashedSaltedValue`/`salt`/`hashIterations`/`algorithm` fields); OTP/WebAuthn/other
  credentials, attributes, federated identities and user federation => counted
  warnings. Users without a usable password import without one (they must reset).
* Not migrated, always reported with counts: identityProviders, userFederation
  providers/components, authenticationFlows, clientScopes/protocolMappers,
  requiredActions config, authorization services, events/event listeners, themes,
  internationalization.
