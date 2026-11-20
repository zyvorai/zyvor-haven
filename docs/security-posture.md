---
hero:
  eyebrow: SECURITY POSTURE
  title: Haven Guard
  lead: >-
    Haven Guard audits the security-relevant configuration of Keycloak
    realms and OIDC clients. It is intentionally deterministic: the same
    realm/client configuration produces the same findings, score, and
    SHA-256 fingerprint.
  highlights:
    - {value: "13", label: "Deterministic rules, HAVEN001–013, across four severity tiers"}
    - {value: "SHA-256", label: "Fingerprint for pinning a baseline and detecting drift"}
    - {value: "3", label: "CI exit codes: 0 clean, 1 error, 2 findings over threshold"}
    - {value: "6", label: "Built-in Keycloak clients excluded from findings and counts"}
---

Haven Guard audits the security-relevant configuration of Keycloak realms and OIDC clients. It is intentionally deterministic: the same realm/client configuration produces the same findings, score and SHA-256 fingerprint.

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

Built-in Keycloak clients (`account`, `account-console`, `admin-cli`, `broker`, `realm-management`, `security-admin-console`) are excluded from client counts and findings.

## Fingerprint / drift

The fingerprint includes security-relevant realm state plus application-client grant modes, redirect URIs, web origins, PKCE settings and service-account state. Lists are sorted before hashing, so ordering changes do not create false drift.

To pin a baseline:

1. Get a clean report.
2. Store `fingerprint` in Git, a release record, or the Guard UI baseline.
3. Send it back as `baseline=sha256:...`.
4. `drifted: true` means the security-relevant state changed.

A fingerprint tells you **that** state changed. Findings and the future Realm Time Machine diff tell you **what** changed.
