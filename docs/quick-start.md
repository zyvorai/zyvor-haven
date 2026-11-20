# Quick start

From a clone to a running Keycloak + Postgres plane, plus the remote lab console and local UI.

[Back to the README](https://github.com/zyvorai/haven#readme) · [Documentation map](documentation-map.md)

---

## Local cluster

```bash
git clone https://github.com/zyvorai/haven.git
cd haven

# 1. Operators (once per cluster)
./deploy/operators/install.sh

# 2. Postgres + Keycloak
make dev
make wait
make doctor
make admin
```

| | |
|---|---|
| Keycloak Admin | `http://auth.127.0.0.1.nip.io/admin` |
| Bootstrap secret | `platform-initial-admin` in namespace `identity` |
| First realm | `make realm-import` (optional) |

```bash
# Remote lab console
./scripts/deploy-remote.sh <ephemeral-ip> operator
# → http://<ephemeral-ip>:30742/login  — docs/lab-host.md

# UI local
make ui-install && make ui-dev   # http://localhost:5173
```
