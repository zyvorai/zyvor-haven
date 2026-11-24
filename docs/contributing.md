---
hero:
  eyebrow: CONTRIBUTING
  title: Contributing to Haven
---

Thanks for helping improve Haven. This guide covers local development, documentation, and how to submit changes.

---

## Before you start

- Run commands from the **repo root** (directory containing `Makefile`, `cli/haven`, `scripts/`).
- Haven is under the Zyvor Production Licence v2.0. By contributing, you agree your changes are licensed under the same terms.
- Add the standard SPDX header to new source files — see [LICENSE headers](LICENSE_HEADERS.md).
- Follow the [Code of Conduct](https://github.com/zyvorai/haven/blob/main/CODE_OF_CONDUCT.md).
- Report security issues privately — see [SECURITY.md](https://github.com/zyvorai/haven/blob/main/SECURITY.md). Do not file public issues for vulnerabilities.

### Developer Certificate of Origin (DCO)

Every commit must be signed off with a `Signed-off-by` line that certifies you have the right to submit the contribution under the Zyvor Production Licence v2.0 (see [developercertificate.org](https://developercertificate.org/)):

```bash
git commit -s -m "your message"
```

Example trailer:

```text
Signed-off-by: Your Name <you@example.com>
```

Use the same name and email as your GitHub account. PRs without DCO sign-off will not be merged.

---

## Development setup

### Identity plane (local cluster)

```bash
./deploy/operators/install.sh
make dev
make wait
make doctor
make admin
```

Issuer: `http://auth.127.0.0.1.nip.io/realms/platform`. No cluster needed to try the identity server itself: `go run ./cmd/haven-idp dev`.

### Console (Go + React)

```bash
make ui-install          # once
make ui-dev              # Vite → http://localhost:5173
go run ./cmd/haven-console
```

### Tests

```bash
make console-test        # Go tests in internal/
go test ./...
```

### Controller

```bash
make controller-build
make controller-deploy   # requires cluster + CRDs
```

Full operator reference: [CLI](cli.md) · deployment paths: [Runbook](runbook.md).

---

## Documentation

Documentation lives in `docs/` and is published with MkDocs Material.

| Task | Command |
|---|---|
| Preview locally | `make docs-serve` → http://127.0.0.1:8000 |
| Build static site | `make docs-build` → `site/` |
| Doc index | [README.md](README.md) |

### Writing docs

- Use **repo root** in examples, not machine-specific paths.
- Put lab host URLs in [lab-host.md](lab-host.md); link from other pages instead of duplicating tables.
- Cross-link related pages with relative paths (`[Runbook](runbook.md)`).
- Keep operational content in runbook/tutorials; keep design rationale in architecture/ux.
- Update `mkdocs.yml` nav when adding a new doc page.

Published site (after merge to `main`): **https://zyvorai.github.io/haven/**

---

## Pull requests

1. Fork and branch from `main`.
2. Keep changes focused — one logical change per PR when possible.
3. Update docs if you change behavior, CLI flags, deploy paths, or env vars.
4. Run relevant checks before opening the PR:

   ```bash
   make console-test
   make docs-build    # if docs changed
   ```

5. Open a PR with:
   - **What** changed (brief)
   - **Why** (motivation or bug)
   - **Test plan** (commands run, screenshots for UI)

Commit messages: imperative mood, concise subject (`docs: add MkDocs site`, `fix: wait for the CNPG cluster before starting haven-idp`).

---

## Remote lab host

For console work against the shared lab:

```bash
./scripts/deploy-remote.sh <ephemeral-ip> operator
```

Endpoints and OIDC wiring: [lab-host.md](lab-host.md).

---

## Questions

- Architecture and scope: [Architecture](architecture.md), [Roadmap](roadmap.md)
- User-facing manuals: [Haven manual on zyvor.dev](https://zyvor.dev/docs/haven-manual)
- Conduct: [CODE_OF_CONDUCT.md](https://github.com/zyvorai/haven/blob/main/CODE_OF_CONDUCT.md)
- Security: [SECURITY.md](https://github.com/zyvorai/haven/blob/main/SECURITY.md)
