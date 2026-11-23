# Import a Keycloak realm (with passwords)

`haven-idp import-keycloak` converts a Keycloak realm export into a haven-idp realm file and a user
list, and tells you everything it could not carry over. Users keep signing in with their **existing
passwords**: their Keycloak password hashes are re-encoded, not reset.

The whole flow is offline and reviewable:

```text
Keycloak export  ->  import-keycloak  ->  realm.yaml + users.json  ->  apply  ->  import-users
```

## 1. Export the realm

Use Keycloak's full export, which includes users and their credentials:

```bash
# on a Keycloak host (stop the instance or use a separate one for dir/file export)
kc.sh export --realm corp --users realm_file --file corp-export.json
```

The admin console's "Partial export" works too but contains **no users**: you get the realm file and
clients, and must provision users another way. A JSON array holding one realm is accepted as well.
Exports up to 512 MiB are streamed; the raw document is never held in memory.

## 2. Convert

```bash
haven-idp import-keycloak -f corp-export.json                    # dry run: report only
haven-idp import-keycloak -f corp-export.json --out-dir ./corp   # writes the files
haven-idp import-keycloak -f - --format json < corp-export.json  # machine-readable report
```

| Flag | Meaning |
|---|---|
| `-f FILE` | the export (`-` reads stdin) |
| `--realm NAME` | target realm name (default: the export's realm, lower-cased) |
| `--out-dir DIR` | write `DIR/realm.yaml` (0644) and `DIR/users.json` (0600) |
| `--format text\|json` | report format |

Without `--out-dir` nothing is written. The command refuses to overwrite existing files. `users.json`
contains password hashes: treat it like a database backup and delete it after the import.
Exit code is 0 on success and 1 on any error.

### Sample report

```text
Keycloak import report for realm corp

Mapped:    2 roles, 2 groups, 4 clients
Users:     6 (4 with an importable password, 2 without: they must reset)

NEW client secrets are generated on apply for: billing-svc, legacy-wiki
(secrets in the export are never copied; update each application)

Not migrated (no haven-idp equivalent):
  authentication flows     2
  identity providers       2
  user federation          1
  ...

Warnings by code:
  client.saml_skipped                  1
  client.wildcard_redirect             2
  realm.policy_term_dropped            3
  user.otp_not_migrated                1
  user.password_unsupported            1
  ...
```

Every skipped or altered item has a stable machine code (use `--format json` and the `warningCounts`
map in CI). Per-item details are listed for the first 25 occurrences of each code; counts are exact.

## 3. What maps and what does not

| Keycloak | haven-idp |
|---|---|
| `registrationAllowed`, `verifyEmail`, `bruteForceProtected`, `sslRequired`, token lifetimes, events, refresh-token rotation | realm settings (unset in the export = unmanaged) |
| `passwordPolicy` | only `length`, `digits`, `upperCase`, `lowerCase`, `specialChars`; every other term gives `realm.policy_term_dropped` |
| realm roles | roles; built-ins (`offline_access`, `uma_authorization`, `default-roles-*`) skipped; composite roles imported **without** their composition (`role.composite_dropped`) |
| groups | top-level groups only; sub-groups dropped (`group.subgroups_dropped`) |
| OIDC clients | clients; built-in Keycloak clients skipped |
| users | username, email, names, enabled, emailVerified, realm roles, top-level group membership, password |

Skipped with a warning: SAML clients, bearer-only clients, clients using authorization services,
service-account users (haven-idp creates them with the client). Implicit flow and direct access grants
(password grant) are turned off. Wildcard redirect URIs and web origins, and anything that is not
absolute `https` (or `http` on loopback), are dropped; a client left with no redirect URI is still
emitted but flagged `client.no_redirect_uri`, so you can fix it before go-live.

Not migrated, always reported with counts: identity providers and brokered identities, user
federation (LDAP/AD), authentication flows, client scopes and protocol mappers, required-action
configuration, authorization services, events and listeners, themes, internationalization, client
roles, custom user attributes, and OTP/WebAuthn/other credentials (users must re-enroll).

## 4. Passwords and first login

Keycloak stores passwords as PBKDF2 (SHA-1/256/512) or argon2 hashes. The importer re-encodes each
one into haven-idp's self-describing format (`$pbkdf2-sha256$i=...$salt$hash`, `$argon2id$...`).
No password is ever known to the tool and nothing is re-hashed at import time.

On a user's first successful sign-in, haven-idp verifies the password against the imported hash and,
because that scheme is not the current one, **rehashes it to the current argon2id** in the same
request. After one login the user is fully on native hashing; nobody is asked to do anything.

Users who cannot keep their password import without one and must use the reset flow:
no password credential (`user.no_password`), an unsupported algorithm such as Keycloak's argon2 `d`
variant, or unreadable data (`user.password_unsupported`, `user.password_unreadable`). Required
actions `UPDATE_PASSWORD` and `VERIFY_EMAIL` are kept; others are dropped with a warning.

### Unverified emails: check this before cut-over

If the Keycloak realm has **Verify email** on (`verifyEmail: true`), Keycloak lets a user with an
unverified address sign in and then verify by mail. haven-idp has **no email-verification flow yet**,
and it refuses to sign in an unverified user whenever the realm requires verified email, so after the
import those users could not sign in at all. The password check passes first; the refusal comes
after it (the `haven_idp_logins_total{result="unverified"}` metric counts them).

The report names every affected user (enabled, with a password, email not verified) with the code
`user.email_unverified_blocked`. Your options:

* **Verify them out of band**, then re-export, or
* **`--trust-emails`**: mark every imported email as verified. This asserts that each address really
  belongs to its user, which the importer cannot check, so it is never the default and the report
  records that you used it (`user.emails_marked_verified`). Users without an email address stay
  unverified.
* **Set `emailVerificationRequired: false`** in `realm.yaml` if verified email is not a requirement
  for you.

## 5. Apply, then import users

```bash
haven-idp validate -f corp/realm.yaml
haven-idp plan     -f corp/realm.yaml --url https://idp.example.com --admin-realm platform
haven-idp apply    -f corp/realm.yaml --secrets-file ./corp-secrets.txt --url ... --admin-realm platform
haven-idp import-users -f corp/users.json --realm corp --url ... --admin-realm platform
```

`import-users` takes the same connection flags as `plan` (`--dev`, `--url`, `--admin-realm`,
`--client-id`, `--env-file`), reads `users.json` (a JSON array or `{"users":[...]}`), sends batches
of 500 and prints counts only: created, skipped (the username already existed; existing users are
never modified) and failed, with the usernames of failures and a reason, never a hash. Exit code
0 means all good, 1 an error, 4 that some users failed (fix them and re-run: re-running is safe).
It refuses to run against a provider that cannot import users.

## The confidential-secret caveat

Client secrets in the export are never read into any output. Each confidential client gets a **new**
secret when `apply` creates it, written to `--secrets-file` (mode 0600). The report lists these
clients as `newSecretClients`. Update every relying application with its new secret during cut-over.

## Rollback

Nothing in Keycloak is changed. To abandon the migration, point applications back at Keycloak
(see [Migrate from Keycloak](migrate-from-keycloak.md#rollback)) and delete the haven-idp realm.
Users who already signed in on haven-idp changed only their haven-idp hash; their Keycloak
passwords are unaffected, but any password changed on haven-idp after cut-over is not carried back.
Delete `users.json` and the export once you are done: both contain credential material.
