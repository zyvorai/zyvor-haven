# Config as code

Describe a realm in one YAML file, preview the change, and apply it. Every
change passes through Haven Guard first, so a pull request cannot quietly make a
realm less secure.

```
haven-idp validate -f realm.yaml      # offline: file check + Guard score of a fresh realm
haven-idp plan     -f realm.yaml      # diff against the live realm + Guard verdict
haven-idp apply    -f realm.yaml      # plan, ask, apply
haven-idp export   acme > realm.yaml  # live realm as a file
```

Try it locally with `haven-idp dev` and add `--dev` to `plan`, `apply` and
`export`. See `examples/config/realm-secure.yaml` and `realm-risky.yaml`.

## File format

| Field | Meaning |
|---|---|
| `apiVersion`, `kind` | `haven.zyvor.dev/v1`, `Realm` |
| `realm` | Realm name (`^[a-z0-9][a-z0-9._-]{0,62}$`) |
| `displayName`, `enabled` | Optional |
| `settings.selfRegistration`, `emailVerificationRequired`, `bruteForceProtection` | Booleans |
| `settings.transportSecurity` | `none`, `external`, `all` |
| `settings.passwordPolicy` | e.g. `length(12) and digits(1)` |
| `settings.accessTokenSeconds`, `sessionIdleSeconds` | Positive integers |
| `settings.authEvents`, `adminEvents`, `refreshTokenRotation` | Booleans |
| `roles[]` | `name`, `description` |
| `groups[]` | `name` |
| `clients[]` | `clientId`, `name`, `enabled`, `public`, `serviceAccount`, `authCodeFlow`, `requirePKCE`, `redirectUris`, `origins` |

A setting you leave out is unmanaged: an existing realm keeps its value, a new
realm gets a secure default. Public clients require PKCE; this cannot be turned
off. Roles, groups and clients in the file are created or updated. Live
clients that are not in the file are left alone unless you pass `--prune`, which
deletes them. In v1 `--prune` removes **clients only**: roles and groups are
never deleted (the identity backends have no delete for them), and a role's
description is not compared or updated. Built-in and admin clients are never
pruned. Users are out of scope.

## Workflow

1. Edit the file, run `validate` (no server needed).
2. `plan` shows `+` create, `~` update (`field: old -> new`), `-` delete, then
   Guard's view: score before and after, new findings, fixed findings.
3. `apply` shows the same and asks `Apply these changes? [y/N]`. Without a
   terminal it refuses unless `--auto-approve` is given.

Guard blocks an apply when it would introduce a finding at or above
`--fail-on` (default `high`; `none` disables). `--allow-findings` overrides the
block and prints a warning.

## Connection

`--dev`, or `--url` / `HAVEN_IDP_URL`, `--admin-realm` / `HAVEN_IDP_ADMIN_REALM`,
`--client-id` / `HAVEN_IDP_ADMIN_CLIENT_ID` (default `haven-admin`),
`HAVEN_IDP_ADMIN_CLIENT_SECRET` or `HAVEN_IDP_ADMIN_CLIENT_SECRET_FILE`, and
`--env-file`. `--format json` gives machine-readable output.

## Secrets

Files never contain secrets and neither does any output. The generated secret
of a newly created confidential client exists only at creation time: pass
`--secrets-file PATH` and `apply` writes `clientId=secret` lines there (mode
0600, an existing file is never overwritten, checked before anything is
changed). Without it the secrets are discarded and `apply` tells you how many;
regenerate them for those clients. If writing fails, the command says so and
exits 1: regenerate the secrets.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK (for `plan --check`: no drift) |
| 1 | Error, declined, or refused without `--auto-approve` |
| 2 | `plan --check`: drift between file and live realm |
| 3 | Blocked by Haven Guard (`validate`, `plan`, `apply`) |

## GitOps example

```yaml
name: realm
on:
  pull_request: { paths: ["realm.yaml"] }
  push: { branches: [main], paths: ["realm.yaml"] }
  schedule: [{ cron: "0 6 * * *" }]   # drift detection
jobs:
  realm:
    runs-on: ubuntu-latest
    env:
      HAVEN_IDP_URL: ${{ vars.HAVEN_IDP_URL }}
      HAVEN_IDP_ADMIN_REALM: platform
      HAVEN_IDP_ADMIN_CLIENT_SECRET: ${{ secrets.HAVEN_ADMIN_SECRET }}
    steps:
      - uses: actions/checkout@v4
      - run: haven-idp validate -f realm.yaml
      - name: Plan (fails on Guard block)
        if: github.event_name == 'pull_request'
        run: haven-idp plan -f realm.yaml
      - name: Drift check (exit 2 = drift)
        if: github.event_name == 'schedule'
        run: haven-idp plan -f realm.yaml --check
      - name: Apply
        if: github.event_name == 'push'
        run: haven-idp apply -f realm.yaml --auto-approve --secrets-file "$RUNNER_TEMP/secrets.env"
