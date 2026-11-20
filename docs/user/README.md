---
hero:
  eyebrow: USER GUIDE
  title: Haven — User Documentation
---

**Haven** is identity for the private cloud — Keycloak + Postgres as one plane, operated from the Haven console.

| You want to… | Open |
|--------------|------|
| Install and sign in | [Getting Started](getting-started.md) |
| Learn the shell | [Using the Dashboard](using-the-dashboard.md) |
| Screen-by-screen UX | [Page-by-page guides](pages/README.md) |
| Look up any route | [Complete page index](PAGE_INDEX.md) |
| Deploy / auth / ports | [Admin basics](admin-basics.md) |
| Change passwords | [Passwords](passwords.md) |
| Multi-step recipes | [Common workflows](workflows.md) |

## Printable PDFs

```bash
set -a; source scripts/user-docs/product.env; set +a
node scripts/user-docs/build-user-pdfs.mjs
```

Output lands in [`pdf/`](pdf/).

## Product at a glance

```text
  Console   →  http://<host>:30742/          (NodePort UI + /api/v1)
  Login     →  http://<host>:30742/login
  Keycloak  →  http://<host>:30180/admin     (typical NodePort)
  Issuer    →  http://<host>:30180/realms/master
  Health    →  GET /api/v1/health
```

Never publish lab IPs — use `<host>`.
