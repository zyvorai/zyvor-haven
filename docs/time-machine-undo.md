# Time Machine undo (native backend)

[Time Machine](identity-ops.md#time-machine) takes recovery points of a realm and shows what changed since
(`GET /api/v1/time-machine/snapshots/{id}/diff`). Undo turns a **selected part of that change set** back,
against a haven-idp realm, through the Admin API. It is available only when the console runs on the native
backend; on Keycloak it answers 501.

## What counts as a change, and what undo does

The diff lists names. Undo works on exactly those entries:

| Entry in the diff | Undo does | Notes |
| --- | --- | --- |
| client **added** since the snapshot | deletes it | the console's own admin client is never deleted |
| client **removed** | recreates it from the snapshot | a confidential client gets a **new** secret: snapshots never held it. Regenerate and distribute it |
| user **added** / **removed** | deletes / recreates (no password: set one or send a reset link) | `service-account-*` users are skipped, they follow their client |
| role or group **removed** | recreates it | |
| role or group **added** | nothing: reported `unsupported` | the Admin API has no role or group delete |
| identity provider **added** / **removed** | deletes / recreates | secrets are not in snapshots: set the client secret again |
| role mapping or group membership **removed** | grants it again | the user and the role/group must exist (select them too) |
| role mapping or group membership **added** | nothing: reported `unsupported` | the Admin API cannot remove mappings |

An object that exists in both the snapshot and the live realm but was **edited** is not part of the diff, so
undo does not revert edits. Passwords, sessions and secrets are not recoverable from a snapshot.

## Preview, then apply

`POST /api/v1/time-machine/snapshots/{id}/undo` (console session required).

```json
{ "all": true }
```
or
```json
{ "changes": [ { "kind": "user", "name": "carol", "change": "added" },
               { "kind": "client", "name": "grafana", "change": "removed" } ] }
```

`kind` is `client`, `user`, `role`, `group`, `provider` or `access`; `change` is `added` or `removed`, as the
diff reports it. Anything that is not in the current diff is rejected with 400, so a request cannot name
arbitrary objects. At most 500 entries.

**This is a dry run unless you say otherwise.** The answer is the ordered plan (`planned`, `skipped`,
`unsupported` per step) and the live fingerprint:

```json
{ "dryRun": true, "executable": 4, "plan": { "snapshotId": "...", "liveFingerprint": "9f2c...", "steps": [ ... ] } }
```

To apply, repeat the same selection with `"dryRun": false` and that fingerprint:

```json
{ "all": true, "dryRun": false, "liveFingerprint": "9f2c..." }
```

* Without a fingerprint: 400 ("preview first").
* If the realm changed since the preview: 409, nothing is done. Preview again. A plan therefore only ever runs
  against the state the operator looked at, and cannot be replayed.
* If nothing in the selection can be undone: 422.
* Steps run in dependency order (roles, groups, providers, clients, users, grants, then deletions). The first
  failing step stops the run: it is marked `failed`, the rest `not_run`, status 502. There is no rollback; the
  result says exactly what happened. Backend error bodies are not echoed, only the status code.
* One undo runs at a time (409 otherwise).

The response also carries `undoId`, `outcome` (`completed` or `failed`) and `remainingChanges`, the size of the
diff after the undo (it stays above zero while unsupported entries remain).

## Audit

* **Journal.** Before the first change, a record is written to `HAVEN_DATA_DIR/time-machine-undo/<id>.json`
  (mode 0600) with the acting console user, snapshot, realm, fingerprint and the plan, then completed with the
  per-step results. If that first write fails nothing is changed. `GET /api/v1/time-machine/undos[?realm=]`
  lists the records, newest first. Records hold names and statuses only, never secrets.
* **IdP events.** Every step is an ordinary Admin API call by the console's service client, so haven-idp
  records its own `ADMIN_*` events (and the audit stream, if configured) for each create and delete.

## Not yet

* No revert of edits (only added/removed names are tracked), and no undo of role/group deletion or mapping
  removal until the Admin API grows those routes.
* No per-step selection UI in the console, no scheduled or automatic undo, and no undo of an undo (take a new
  snapshot before a large one).
* The journal is files on the console host, not in the IdP's event store, and it is not hash-chained.
