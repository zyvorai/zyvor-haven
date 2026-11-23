---
hero:
  eyebrow: POLICY AS CODE
  title: Organisation policy for realms
  lead: >-
    Haven Guard ships fixed rules. A policy file lets you add your own
    declarative rules, evaluated offline against a realm export and reported
    next to the built-in findings.
---

A policy is a JSON document of assertions. Each rule says what must be true;
every realm or client where it is false yields one finding with the rule id
`POLICY-<id>`. The same file gates CI through the existing `--fail-on`
threshold and appears in SARIF output.

```bash
go run ./cmd/haven-audit --input realm.json --policy examples/policies/org-baseline.json
```

## Format

```json
{
  "version": 1,
  "rules": [
    {"id": "ORG-TOKEN", "severity": "medium", "title": "Access tokens must live 15 minutes or less",
     "path": "accessTokenLifespan", "op": "lte", "value": 900,
     "remediation": "Lower the access token lifespan."},
    {"id": "ORG-HTTPS", "severity": "high", "title": "Redirect URIs must be HTTPS",
     "scope": "client", "path": "redirectUris[]", "op": "matches", "value": "^https://"}
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | `[A-Za-z0-9][A-Za-z0-9_-]{0,39}`, unique in the file |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `scope` | `realm` (default) or `client`; built-in Keycloak clients are skipped unless `includeBuiltin` is true |
| `path` | Dot path into the export, up to 8 segments; `name[]` selects every array element |
| `op` | `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`, `notIn`, `contains`, `notContains`, `matches`, `present`, `absent`, `nonEmpty` |
| `value` | Scalar (list for `in`/`notIn`, RE2 pattern for `matches`); not allowed for `present`/`absent`/`nonEmpty` |
| `optional` | A missing path passes instead of failing |

A missing path is a violation (fail closed) unless `optional` is set. A value
of the wrong type fails the comparison. For `[]` paths the rule is checked per
element and an empty array passes, except `present`, which needs at least one.

## Limits and safety

- The file may not exceed 256 KiB, 200 rules, 8 path segments or 300 bytes of
  title/remediation; unknown JSON fields and trailing data are rejected.
- Patterns use Go RE2 (linear time, no backtracking) and are capped at 256
  bytes. Lists hold at most 200 scalars. At most 50 findings are emitted per
  rule and evidence strings are cut at 120 bytes.
- Paths naming credential material (`secret`, `credential`, `password`,
  `privateKey`, `apiKey`, `token`, `value`) are rejected when the policy is
  loaded, so a policy cannot be used to read or print secrets. `passwordPolicy`
  and `accessTokenLifespan` are configuration, not secrets, and are allowed.
- A policy is data: nothing in it is executed.

Policy findings change the score, counts and `--fail-on` result but not the
Guard fingerprint, which keeps tracking configuration only.

An example baseline lives at `examples/policies/org-baseline.json`.
