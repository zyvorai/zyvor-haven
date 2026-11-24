# haven-idp and haven on macOS

`haven-idp` runs as a server on macOS (Apple silicon and Intel) and the `haven`
CLI works on Macs. Both are single static binaries (CGO off, no new
dependencies). This page covers install, running as a launchd service, a
PostgreSQL for a single node, the optional Keychain integration, and what has
not been tested.

## Install

Pick one:

```sh
# 1. Build from source (Go from go.mod). Both architectures:
make build-darwin                      # bin/darwin-{arm64,amd64}/{haven-idp,haven}
# or just this machine:
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o haven-idp ./cmd/haven-idp
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o haven     ./cmd/haven

# 2. Homebrew (zyvorai tap), once the formula is published:
brew install zyvorai/tap/haven

# 3. The installer package (universal binaries into /usr/local/bin):
#    packaging/macos/build-pkg.sh builds it unsigned; signing and notarization
#    are manual steps, see `packaging/macos/README.md` in the repository.
```

CI cross-builds `haven-idp` and `haven` for `darwin/arm64` and `darwin/amd64`
on every change and runs the macOS-relevant tests on a macOS runner.

Try it first, in memory, loopback only: `haven-idp dev`.

## Run it as a service (launchd)

`haven-idp install-service` writes a launchd property list and loads it.
Create the config first (the env file is the only place secrets live):

```sh
haven-idp init --dir "$HOME/Library/Application Support/haven-idp" \
  --base-url https://idp.example.com        # writes haven-idp.env, mode 0600
haven-idp install-service                   # user LaunchAgent, loaded now
haven-idp service-status
haven-idp uninstall-service
```

### User LaunchAgent (default)

No root needed. It starts when you log in, runs as you, and launchd restarts it
if it exits (`KeepAlive`, 10 s throttle). It does not run while nobody is logged
in; use the daemon below for a headless Mac.

| What | Where |
|---|---|
| plist | `~/Library/LaunchAgents/dev.zyvor.haven-idp.plist` (0644, no secrets) |
| data dir, env file | `~/Library/Application Support/haven-idp/` (created and kept 0700; the env file must be 0600 or install refuses) |
| log (stdout and stderr, JSON lines) | `~/Library/Logs/haven-idp/haven-idp.log` (directory 0700) |
| launchd domain | `gui/<uid>`; the process runs with `umask 077` |

Flags: `--label` (default `dev.zyvor.haven-idp`), `--env-file`, `--data-dir`,
`--log`, `--binary` (default: the running binary), `--env NAME=VALUE`
(repeatable, non-secret only), `--force` (replace a different installed plist),
`--no-load`, `--print` (show the plist, write nothing).

`install-service` refuses to run as root, refuses an env file readable by other
users, and refuses a label that launchd already loaded from a different plist.
`uninstall-service` unloads the service only when launchd reports it was loaded
from our plist; it leaves the data directory, env file and logs alone.
`service-status` exits non-zero unless the service is running.

### System LaunchDaemon (boot time, headless)

```sh
haven-idp install-service --system --user _haven --env-file /path/to/haven-idp.env
```

This only **generates** `dev.zyvor.haven-idp.plist` in the current directory
(or `--out`) and prints the exact `sudo` commands to create the data directory,
install the env file and plist, and bootstrap it. haven-idp never runs `sudo`.
The daemon runs as `--user`, an unprivileged account you create (never root; the
command rejects `root`), with data in `/Library/Application Support/haven-idp`
(0700) and its log at `/var/log/haven-idp.log`. `uninstall-service --system`
likewise prints the commands (`sudo launchctl bootout system/LABEL`, `sudo rm`).

A daemon cannot read your login Keychain. Give it its secrets as 0600 files
(`HAVEN_IDP_SECRET_KEY_FILE`, `HAVEN_IDP_BOOTSTRAP_PASSWORD_FILE`, ...) owned by
the service account.

### What is in the plist

`Label`, `ProgramArguments` (`haven-idp serve --env-file ...`), `WorkingDirectory`,
`RunAtLoad`, `KeepAlive`, `ThrottleInterval`, `Umask`, `StandardOutPath` /
`StandardErrorPath`, `UserName` (daemon only) and optionally an
`EnvironmentVariables` dict. Values are XML-escaped; control characters and
invalid UTF-8 are refused. `--env` refuses names that look like secrets
(`*SECRET*`, `*PASSWORD*`, `*TOKEN*`, `*_KEY`, `*DSN`, ...) and URLs with an
embedded password, because the plist is world-readable and shown by
`launchctl print`. Names ending in `_FILE` or `_KEYCHAIN` are fine: they point
at a secret, they are not one. Everything else belongs in the env file.

## PostgreSQL for a single node

`haven-idp serve` needs `HAVEN_IDP_DSN` (PostgreSQL) unless `HAVEN_IDP_DEV=1`.

**Homebrew PostgreSQL** (the supported way to run a production-style single node):

```sh
brew install postgresql@16 && brew services start postgresql@16
createdb haven_idp
psql haven_idp -c "create role haven_idp login password '...'"
psql haven_idp -c "grant all on database haven_idp to haven_idp; grant all on schema public to haven_idp"
# in haven-idp.env (`init` writes a CHANGE_ME password; replace it, or delete the
# password from the URL and let the Keychain supply it, see below):
#   HAVEN_IDP_DSN=postgres://haven_idp@127.0.0.1:5432/haven_idp?sslmode=disable
```

Migrations run automatically on start (advisory-locked). Back up with
`pg_dump haven_idp`; losing the database loses users, clients and signing keys.
Use TLS (`sslmode=require` or better) as soon as PostgreSQL is not on loopback.

**`haven-idp dev --persist DIR`** keeps users, clients and keys in files under
`DIR` so a laptop demo survives restarts. **It is not a production database:**
it is a dev convenience (single process, plain files, no replication or
backup story, loopback only, meant to be thrown away). Do not point real users
at it. For anything you would be unhappy to lose, use PostgreSQL.

## Keychain (optional)

Two secrets can come from the macOS login Keychain instead of a file, through
the `security` tool (no cgo, no dependencies). Opt in per secret in the env file:

```sh
# store the secrets (-w last: security prompts, nothing lands in argv or history)
security add-generic-password -s haven-idp.secret-key  -a haven-idp -w
security add-generic-password -s haven-idp.db-password -a haven-idp -w

# haven-idp.env
HAVEN_IDP_SECRET_KEY_KEYCHAIN=1          # item "haven-idp.secret-key" (or a custom service name)
HAVEN_IDP_DB_PASSWORD_KEYCHAIN=1         # item "haven-idp.db-password", inserted into HAVEN_IDP_DSN
```

Generate the key with `haven-idp keygen` and paste it at the prompt. When the
item is configured and found it is used; if it is not (not macOS, item missing,
Keychain locked, `security` fails) haven-idp prints a warning that names the item
but never a secret, and falls back to `HAVEN_IDP_SECRET_KEY(_FILE)` and the
password in the DSN. A password already present in the DSN wins over the
Keychain, so remove the `CHANGE_ME` that `init` writes. Secrets are not logged and are not in any error message.

## The haven CLI on a Mac

`haven login` / `haven token` work as on Linux (see [haven-cli.md](haven-cli.md)).
By default tokens are in `~/.config/haven/credentials.json` (0600, directory
0700; `XDG_CONFIG_HOME` is honored). On a Mac you can opt in to the Keychain:

```sh
haven login --issuer https://idp.example.com/realms/platform --client-id haven-cli --keychain
```

The tokens then live in the login Keychain (service `haven-cli`, account = profile
name, split across items because `security -i` lines are limited to about 4 KiB);
`credentials.json` keeps only non-secret metadata and `"keychain": true`. If the
Keychain is not available, `--keychain` warns and uses the file. A profile that
was stored in the Keychain and is opened where there is none (for example the
config directory copied to Linux) fails closed with a message asking you to log
in again. `haven logout` removes the Keychain items; logging in again without
`--keychain` moves the tokens back to the file and deletes the items. macOS may
ask once whether `security` may access the item: choose "Always Allow".

## Not tested / not done

- Only the **user LaunchAgent** path was run for real, on one Mac (install,
  status, KeepAlive restart after killing the process, uninstall) with a throwaway
  label. The system LaunchDaemon path is covered by unit tests of the generated
  plist and printed commands; the `sudo` steps were **not** executed and a daemon
  was never loaded.
- Intel (`darwin/amd64`) is cross-compiled in CI but was not run on Intel hardware.
- The Keychain wrapper was exercised against the real `security` tool, including
  items larger than one `security -i` line. Locked-keychain and access-prompt
  behavior, and Keychain use from a LaunchAgent started at login before first
  unlock, were not tested.
- The Homebrew formula and `brew services` stanza are templates: not audited with
  `brew audit`, not published, not installed.
- The installer package is built unsigned and unnotarized (it was only inspected
  with `pkgutil`); signing, notarization and installing it are manual
  (`packaging/macos/README.md` in the repository).
- No `launchd` socket activation, no log rotation (rotate with `newsyslog` or
  truncate the log while stopped), no automatic backup of `dev --persist`, no
  Windows/Linux Keychain equivalent (`--keychain` is macOS only).
- macOS file systems are usually case-insensitive; nothing in haven-idp or the CLI
  keys a file name on a realm or profile name (profiles live in one JSON file),
  and Keychain account names are case-sensitive, so `Work` and `work` stay distinct.
