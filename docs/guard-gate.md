# Guard as an admission gate

haven-idp scores risky Admin API writes with Haven Guard **before** it applies them. A write that
would introduce a new finding at or above a severity threshold is refused with an explanation of what
to fix. Pre-existing findings never block an unrelated edit, so an already-risky realm can be repaired
step by step.

This is the same protection that `haven-idp config apply` gives configuration files (see
[Relation to config as code](#relation-to-config-as-code)), extended to edits made through the API or
the console.

## What is gated

| Route | Gated |
|---|---|
| `PUT /admin/v1/realms/{r}` (realm settings and hardening) | yes |
| `POST /admin/v1/realms` (realm create) | yes (a new realm is compared against "nothing") |
| `POST /admin/v1/realms/{r}/clients` (client create) | yes |
| `PUT /admin/v1/realms/{r}/clients/{id}` (client update) | yes |
| client delete, secret regeneration | no |
| users, roles, groups, sessions, realm import | no |

## How a decision is made

1. Guard (`internal/posture`, rules HAVEN001 to HAVEN023) evaluates the realm **before** and
   **after** the proposed write. A client write evaluates the whole realm, because some rules look
   across clients (for example HAVEN021).
2. Findings are compared by rule, realm and client. A finding is **new** if it is in the after state
   but not in the before state. Evidence is not part of the key: a client that already has HAVEN002
   and gains a second insecure redirect URI has no new finding (it is the same rule on the same
   client).
3. Active waivers are applied to both states first (below). Expired waivers do nothing.
4. New findings with severity at or above the threshold are the **blocking** set. Pre-existing
   findings, new findings below the threshold, and fixes never block.

The comparison is `configcode.DiffFindings`, the function `config apply` also uses.

## Configuration

| Variable | Values | Default |
|---|---|---|
| `HAVEN_IDP_GUARD` | `off`, `warn`, `enforce` | `warn` |
| `HAVEN_IDP_GUARD_THRESHOLD` | `critical`, `high`, `medium`, `low` | `high` |
| `HAVEN_IDP_GUARD_WAIVERS` | path to a waiver file | none |
| `HAVEN_IDP_GUARD_NO_OVERRIDE` | `1` denies overrides to service accounts | off |

Unknown values stop `haven-idp serve` at startup. (If a bad mode ever reaches the handler it is
treated as `enforce`, and a bad threshold as `high`, never as "off".) The waiver file is read on
every evaluation, so edits take effect without a restart; it is also validated at startup.

### Modes

**off**: nothing is evaluated.

**warn** (default): the write is applied. If it adds blocking findings, the response carries
`X-Haven-Guard: findings=1 max=high` and the realm event log gets a `GUARD_WARN` event whose detail
lists rule ids only (`kind=realm rules=HAVEN014`).

```
$ curl -i -X PUT .../admin/v1/realms/acme -d '{"realm":"acme","enabled":true,"sslRequired":"none"}'
HTTP/1.1 204 No Content
X-Haven-Guard: findings=1 max=high
```

**enforce**: the write is refused with HTTP 422, nothing is stored, and a `GUARD_BLOCK` event is
recorded.

```
HTTP/1.1 422 Unprocessable Entity
X-Haven-Guard: findings=1 max=high
{"error":"guard_blocked",
 "findings":[{"ruleId":"HAVEN014","severity":"high","title":"Realm does not require TLS",
   "resource":"realm/acme","detail":"sslRequired=none",
   "fix":"Set the realm SSL requirement to external or all."}],
 "message":"this change would introduce findings at or above the high threshold; ...",
 "override":"repeat the request with header X-Haven-Guard-Override: <reason, 10-300 characters>; the override is audited"}
```

### Overrides

In `enforce`, repeat the request with `X-Haven-Guard-Override: <reason>` (10 to 300 characters). The
write is applied, the response has `X-Haven-Guard: findings=1 max=high override=1`, and a
`GUARD_OVERRIDE` event is **always** recorded with the caller (`user:<id>` or `client:<id>`), the
rule ids and the reason. An override whose event cannot be stored is refused. A bad reason is `400
guard_override_invalid`. The header is ignored in `warn` and `off`, and when there is nothing to
override nothing is recorded.

Any authenticated admin caller may override. Set `HAVEN_IDP_GUARD_NO_OVERRIDE=1` to deny overrides
to service accounts (`403 guard_override_denied`); human admin users can still override. The reason
is stored verbatim, so do not put secrets in it.

### Waivers

Waivers use the same file as `haven-audit --waivers` (`internal/posture/waiver.go`): version 1,
each waiver names a rule, a single realm, an optional client (`*` for any), reason, approver and an
expiry (at most a year away). A waiver for another realm or another rule does not apply; an expired
waiver does not apply.

```json
{"version":1,"waivers":[{"ruleId":"HAVEN014","realm":"lab","reason":"internal lab, no external traffic",
  "approver":"security@example.com","expires":"2026-12-31"}]}
```

### Failure behaviour

If evaluation fails (store error, unreadable or invalid waiver file, or a panic, which is contained):

- `enforce` fails **closed**: `500 {"error":"guard_unavailable"}`, nothing stored. A valid
  `X-Haven-Guard-Override` still lets the write through (recorded as `GUARD_OVERRIDE` with
  `rules=unavailable`).
- `warn` fails **open**: the write is applied and the error is logged.
- `off` never evaluates.

Internal error text is logged, never returned.

## Dry run and current findings

Ask before writing, from a UI or CI. Nothing is applied.

```
POST /admin/v1/realms/{r}/guard/evaluate
{"kind":"realm","body":{"realm":"acme","enabled":true,"sslRequired":"none"}}
{"kind":"client","body":{"clientId":"web","publicClient":true,"redirectUris":["http://x.example/cb"],...}}
```

The body is exactly what the write route takes. A `client` whose `clientId` exists in the realm is
evaluated as an update, otherwise as a create; a `realm` that does not exist is evaluated as a
create. The answer is the same `GuardVerdict` the real write would be judged by (`mode`,
`threshold`, `allowed`, `blocked`, `new`, `fixed`, `waived`). The dry run works in every mode,
including `off`.

`GET /admin/v1/realms/{r}/guard` returns the realm's current findings after waivers, with the waived
ones and their reasons, for the console.

Go callers: `idp.GuardEvaluator` (implemented by `native.Client`) wraps the dry run.

## Relation to config as code

`haven-idp config apply` already refuses a configuration file that adds findings at or above its
`--threshold`. That gate only sees changes that go through the file. The admission gate covers
direct API and console edits with the same definition of "new finding"
(`configcode.DiffFindings`), so both paths agree. They are configured separately: the file gate by
its flags, the admission gate by the variables above. An `apply` talks to the Admin API, so with
`enforce` it passes through both gates; use the same threshold on both to avoid surprises.

## Honest limits

- Only realm create/update and client create/update are gated. Users, roles, groups, sessions, client
  delete, secret regeneration and realm **import** are not. Import can create a weak realm.
- Findings come from the Guard rules as they exist. Several critical or high client rules (wildcard
  redirects or origins, implicit flow, password grants on public clients, public service accounts)
  cannot be produced by the Admin API at all because its validation rejects them first, so in
  practice the reachable blocking rules are HAVEN014 (no TLS) and HAVEN002 (insecure redirect) at
  the `high` threshold, and the medium and low realm hardening rules at lower thresholds. No
  reachable rule is `critical`.
- "New" ignores evidence: a worse value of an already-flagged rule is not blocked.
- Overrides are a policy choice, not a control against a malicious admin who can also change the
  environment. The audit trail is the control. `GUARD_*` events are in the realm event list; they do
  not appear in the Admin API `events` route, which shows `ADMIN_*` only.
- A race between two concurrent writes can let both pass (each is judged against what it read).
- Realms and clients created before the gate was switched on are not re-judged.
