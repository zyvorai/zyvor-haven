# Keep dev data across restarts (`dev --persist`)

`haven-idp dev` is in memory: every restart gives you an empty realm. With `--persist DIR` the users, clients,
roles, groups, signing keys, sessions and the other durable rows survive restarts, so tokens you already issued
keep verifying and the test accounts you created are still there.

```
haven-idp dev --persist ~/.haven-dev
```

It is for development only. It does not make the in-memory store a database: there is no locking between
processes, no migration path, and the data is stored unencrypted (see below).

## What is stored

`DIR/state.json` holds one JSON snapshot of the store, and `DIR/secret.key` holds the key that seals TOTP seeds
and federation secrets (it must persist with the data, otherwise those rows could not be decrypted after a
restart).

| Persisted | Not persisted (short-lived) |
| --- | --- |
| realms, users (incl. password hashes), clients, roles, groups | authorization codes |
| signing keys (private keys!) | device codes, WebAuthn challenges |
| refresh tokens, SSO sessions, audit events, emailed action tokens | rate-limit windows, federation login state |
| TOTP credentials and recovery-code hashes, passkeys, federation providers and links | |
| dynamic client registration, time-boxed role grants and policies | |

Rows that expired while the process was down are dropped when the snapshot is loaded.

The dev credentials (test user password, admin client secret) still live in your user config directory as before,
so `haven-idp plan --dev` and friends keep working. If they no longer match the persisted test user (for example
after `--reset-creds`) the test user's password is updated at start. No other user is touched.

## How it is written

* A background saver writes a snapshot every 2 seconds **if something changed**, and once more on shutdown
  (Ctrl-C, SIGTERM). A hard kill can lose up to 2 seconds of changes.
* Writes are atomic: temp file in the same directory, `fsync`, rename, `fsync` of the directory. A crash leaves
  the previous snapshot, never a half-written one.
* Files are mode `0600`, the directory `0700`. An existing directory that other users can access is **refused**
  (`chmod 700` it or pick a new one); its permissions are never changed for you. A `secret.key` readable by
  others is refused too.
* A snapshot that cannot be parsed, or that has an unsupported format version, stops the start with the file
  name in the message. It is never replaced silently: move it aside to start fresh.

## Security properties

* The snapshot contains password hashes (argon2id), **private signing keys** and sealed secrets, and the key to
  open the sealed secrets sits next to it. Anyone who can read the directory can impersonate the realm. Do not
  put it in a shared folder, a synced folder or version control, and never use dev data in production.
* `--persist` only works in `dev`, which listens on loopback. `serve` has no such option; production uses
  PostgreSQL.
* Nothing from the snapshot is logged. The start-up warning names the directory only.

## Adding a feature store

Feature stores keep their rows in side tables of `memstore`. The built-in ones (MFA, passkeys, federation,
dynamic client registration, role grants) are registered in `internal/idp/store/memstore/persist.go` with
`RegisterPersist`. A test (`TestEveryStoreFieldIsAccountedFor`) fails when a new field is added to the store
without being declared persisted or ephemeral, so a new feature cannot be silently left out.

## Not yet

* One process per directory is assumed. Two `dev --persist` processes on the same directory overwrite each
  other (last writer wins); there is no lock file.
* Whole-file snapshot, no journal: very large dev data sets make every change rewrite the file.
* No encryption of the snapshot and no `--persist` for `init`/`serve --memory`.
* Changing the base URL or realm name of a persisted directory is not handled: delete the directory instead.
