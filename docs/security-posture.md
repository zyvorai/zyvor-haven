---
hero:
  eyebrow: SECURITY POSTURE
  title: Haven Guard
  lead: >-
    Haven Guard audits the security-relevant configuration of realms
    and OIDC clients. It is intentionally deterministic: the same
    realm/client configuration produces the same findings, score, and
    SHA-256 fingerprint.
  highlights:
    - {value: "23", label: "Deterministic rules, HAVEN001–023, across four severity tiers"}
    - {value: "SHA-256", label: "Fingerprint for pinning a baseline and detecting drift"}
    - {value: "3", label: "CI exit codes: 0 clean, 1 error, 2 findings over threshold"}
    - {value: "6", label: "Built-in administrative client IDs excluded from findings and counts"}
---

Haven Guard audits the security-relevant configuration of realms and OIDC clients. It is intentionally deterministic: the same realm/client configuration produces the same findings, score and SHA-256 fingerprint.

<div class="compare-cards" markdown="1">

- **Live console API**
  `GET /api/v1/security/posture` (plus `?realm=`, `?baseline=sha256:...`, `?includeMaster=1`, and a `/sarif` variant) inside the normal Haven console session. `master` is excluded from an all-realm scan unless `includeMaster=1` is set.
- **Offline audit (CLI)**
  `go run ./cmd/haven-audit --input realm.json` against an exported realm JSON document — plain, `--format json`, or `--format sarif` output, with `--fail-on` to gate CI on a severity threshold.

</div>

## Live console API

```text
GET /api/v1/security/posture
GET /api/v1/security/posture?realm=my-tenant
GET /api/v1/security/posture?baseline=sha256:...
GET /api/v1/security/posture?includeMaster=1
GET /api/v1/security/posture/sarif
```

`master` is excluded from an all-realm scan unless `includeMaster=1` is supplied. A specific `realm=master` request still scans it.

The API requires the normal Haven console session.

## Offline audit

Export a realm JSON document containing the realm properties and `clients` array, then run:

```bash
go run ./cmd/haven-audit --input realm.json
```

JSON output:

```bash
go run ./cmd/haven-audit --input realm.json --format json --fail-on none
```

SARIF output:

```bash
go run ./cmd/haven-audit \
  --input identity/realm.json \
  --format sarif \
  --fail-on none > haven-guard.sarif
```

When `--input` is a repository-relative file path, Haven Guard includes that file as the SARIF result location so GitHub code scanning can display the findings. The live `/sarif` API remains useful as a portable report but does not invent a repository file location.

CI gate:

```bash
go run ./cmd/haven-audit --input realm.json --fail-on high
```

Exit codes:
- `0`: scan succeeded and did not cross the configured threshold
- `1`: input/configuration/runtime error
- `2`: scan succeeded but findings crossed `--fail-on`

## Waivers and the known-findings gate

Two CI features keep Guard adoptable on a realm that is not clean yet.

**Waivers** (`--waivers waivers.json`) record accepted risks. Every waiver needs a reason, an approver and an expiry (`YYYY-MM-DD`, valid through the end of that UTC day, at most a year ahead):

```json
{"version": 1, "waivers": [
  {"ruleId": "HAVEN014", "realm": "lab", "reason": "Lab realm behind a TLS-terminating proxy", "approver": "sec@example.com", "expires": "2027-03-31"}
]}
```

A waiver matches one rule in one realm. `clientId` omitted matches realm-level findings only; `"*"` matches any client. Waived findings leave the counts, score and `--fail-on` gate and are listed under `waived` in JSON. When a waiver expires, its finding comes back and the waiver appears under `expiredWaivers`; waivers that match nothing appear under `unusedWaivers` so stale exceptions get removed. Waivers never change the fingerprint.

**Known findings** (`--write-known known.json`, then `--known known.json`) save today's findings as a baseline and make `--fail-on` gate only on findings that are not in it, so a legacy realm can adopt Guard and still fail on regressions. A finding is identified by rule, realm, client and evidence, so a new offending value on an already flagged client counts as new. The report lists them under `newFindings`.

```bash
go run ./cmd/haven-audit --input realm.json --write-known known.json --fail-on none   # once
go run ./cmd/haven-audit --input realm.json --known known.json --waivers waivers.json --fail-on high
```

## Policy, diff and access review

- `--policy policy.json` adds your own declarative rules to the audit: [Policy as code](policy-as-code.md).
- `haven-audit diff before.json after.json` compares two realm exports field by field, ignoring server-generated ids and redacting every value under a credential-bearing key (`secret`, `password`, `credential`, `token`, `certificate` and similar), so the output is safe to paste into a pull request. Exit code `0` identical, `2` differences, `1` error. Documents are capped at 32 MiB and 24 levels of nesting.
- `haven-audit diff --ignore GLOB` (repeatable; `*` matches any run of characters, a pattern also covers everything below the path it names) drops noisy paths, and `--format markdown` prints a fenced diff block for a pull-request comment.
- `haven-audit --format markdown` writes a table for a PR comment or `$GITHUB_STEP_SUMMARY`; `--format junit` writes JUnit XML (one suite per realm, one failed case per finding, waived findings as skipped cases carrying the waiver reason) for GitLab, Jenkins and Azure DevOps test reports.
- `haven-audit rules [--format text|json|markdown]` lists the built-in rules; `haven-audit explain HAVEN029` prints one rule with its fix.
- `haven-audit access-review --input snapshot.json` reports privileged and stale accounts: [Access review](access-review.md).

## Rules

| ID | Severity | Check |
|---|---|---|
| HAVEN001 | critical | wildcard redirect URI |
| HAVEN002 | high | non-loopback HTTP redirect URI |
| HAVEN003 | high | wildcard web origin |
| HAVEN004 | high | public client + Direct Access Grants |
| HAVEN005 | high | public auth-code client without PKCE S256 |
| HAVEN006 | high | implicit flow enabled |
| HAVEN007 | high | public client + service accounts |
| HAVEN008 | medium | confidential client + Direct Access Grants |
| HAVEN009 | medium | bearer-only client with interactive grants |
| HAVEN010 | medium | standard-flow client without redirect URI |
| HAVEN011 | medium | self-registration without email verification |
| HAVEN012 | medium | brute-force protection disabled |
| HAVEN013 | low | disabled/stale application client retained |
| HAVEN014 | high | realm `sslRequired=none` |
| HAVEN015 | medium | realm has an empty password policy |
| HAVEN016 | medium | password policy minimum length below 12 (or no `length()` term) |
| HAVEN017 | medium | access token lifespan above one hour |
| HAVEN018 | low | SSO session idle timeout above 24 hours |
| HAVEN019 | medium | user events not recorded |
| HAVEN020 | low | admin events not recorded |
| HAVEN021 | medium | refresh tokens not rotated while an enabled public client exists |
| HAVEN022 | low | SSO session maximum lifespan above 30 days |
| HAVEN023 | low | offline session idle timeout above 90 days |
| HAVEN024 | low | login events kept forever (`eventsExpiration=0` while events are on) |
| HAVEN025 | medium | refresh token reuse allowed (`refreshTokenMaxReuse` above 0 with rotation on) |
| HAVEN026 | low | brute-force lockout allows more than 10 failures |
| HAVEN027 | low | offline sessions have no maximum lifespan |
| HAVEN028 | low | client has Full Scope Allowed (every user role in its tokens) |
| HAVEN029 | medium | `offline_access` is a default client scope |
| HAVEN030 | medium | client access token lifespan override above one hour |

HAVEN014-027 read optional realm settings (`eventsExpiration`, `refreshTokenMaxReuse`, `failureFactor`, `offlineSessionMaxLifespanEnabled`, `sslRequired`, `passwordPolicy`, `accessTokenLifespan`, `ssoSessionIdleTimeout`, `ssoSessionMaxLifespan`, `offlineSessionIdleTimeout`, `eventsEnabled`, `adminEventsEnabled`, `revokeRefreshToken`). A realm export or API response that omits a setting produces no finding for it: Guard does not guess. These settings are not part of the fingerprint, so existing baselines stay valid; use `--policy` for enforced settings drift (see [Policy as code](policy-as-code.md)).

Clients with these built-in administrative IDs (`account`, `account-console`, `admin-cli`, `broker`, `realm-management`, `security-admin-console`) are excluded from client counts and findings. They only appear in realms brought over from another server; see [Import a Keycloak realm](import-from-keycloak.md).

## Fingerprint / drift

The fingerprint includes security-relevant realm state plus application-client grant modes, redirect URIs, web origins, PKCE settings and service-account state. Lists are sorted before hashing, so ordering changes do not create false drift.

To pin a baseline:

1. Get a clean report.
2. Store `fingerprint` in Git, a release record, or the Guard UI baseline.
3. Send it back as `baseline=sha256:...`.
4. `drifted: true` means the security-relevant state changed.

A fingerprint tells you **that** state changed. Findings and the future Realm Time Machine diff tell you **what** changed.
