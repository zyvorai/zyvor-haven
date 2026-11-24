---
hero:
  eyebrow: ACCESS REVIEW
  title: Access recertification
  lead: >-
    Find privileged and stale accounts in a realm, check break-glass
    coverage, and record who certified or revoked each account. Haven records
    decisions; it never changes access in the identity server.
---

Access Review reads the same data as [Time Machine](identity-ops.md): users,
realm-role mappings and group memberships.

## What it flags

| Flag | Meaning | Risk |
|---|---|---|
| `privileged` | A realm role or group whose name contains `admin`, `administrator`, `owner`, `superuser`, `root`, `impersonation`, or a `manage-*` role | medium |
| `disabled-with-access` | Disabled user that still holds roles or groups (stale access) | medium |
| `privileged-unverified-email` | Enabled privileged user without a verified email | high |
| `privileged-pending-actions` | Enabled privileged user with pending required actions | high |
| `break-glass` | Username matches the break-glass pattern (default `break-glass*`, `emergency*`, `bg*`) | informational |

Break-glass checks warn when no break-glass account exists, when fewer than
two are enabled, when one is disabled, or when one holds no privileged role.
Two cloud-only emergency accounts is the Microsoft Entra guidance
([source](https://learn.microsoft.com/azure/active-directory/roles/security-emergency-access)).
Break-glass accounts cannot be revoked through a campaign.

Service accounts are out of scope. Client-role mappings and composite roles are
not expanded: a user can hold admin access through a path this report does not
show.

## Offline

```bash
go run ./cmd/haven-audit access-review --input snapshot.json            # text
go run ./cmd/haven-audit access-review --input snapshot.json --format json --fail-on none
```

`snapshot.json` is a Time Machine snapshot. Exit codes: `0` no high-risk
account, `1` error, `2` high-risk accounts found (`--fail-on none` disables
it). `--break-glass` takes an RE2 pattern of at most 128 bytes.

## Console API

```text
GET  /api/v1/access-review?realm=acme[&breakGlass=<RE2>]   live report, nothing stored
GET  /api/v1/access-review/campaigns[?realm=acme]
POST /api/v1/access-review/campaigns                        {"realm":"acme"}
GET  /api/v1/access-review/campaigns/{id}
POST /api/v1/access-review/campaigns/{id}/decisions        {"username","action","note"}
POST /api/v1/access-review/campaigns/{id}/close
```

A campaign covers every account that holds roles or groups. Decisions are
`certify`, `revoke` (a note is required) or `defer`. The reviewer is always the
authenticated session user. A decision can be changed until the campaign
closes; earlier decisions stay in the append-only history. A campaign closes
only when every account is certified or revoked. The response lists
`revokeWorkItems`: the accounts an administrator must change in the identity server (Admin API or console).

Campaigns are JSON files (mode 0600) under `HAVEN_DATA_DIR/access-reviews`,
capped at 500 stored campaigns and 20,000 users per realm. Without
`console.persistence` they do not survive a pod restart. The console page is
**Access Review** in the sidebar.
