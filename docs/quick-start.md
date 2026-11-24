# Quick start

From a clone to a running identity plane (haven-idp + Postgres), plus the local console UI.

[Back to the README](https://github.com/zyvorai/haven#readme) · [Documentation map](documentation-map.md)

---

## No cluster

```bash
go build -o haven-idp ./cmd/haven-idp
./haven-idp dev                          # prints an issuer URL, a test user and an admin secret
./haven-idp dev --persist ~/.haven-dev   # keep the data between restarts
```

## Local cluster

```bash
git clone https://github.com/zyvorai/haven.git
cd haven

# 1. Operators (once per cluster): CloudNativePG and cert-manager
./deploy/operators/install.sh

# 2. Postgres + haven-idp
make dev
make wait
make doctor
make admin
```

| | |
|---|---|
| Issuer | `http://auth.127.0.0.1.nip.io/realms/platform` |
| Admin user | `admin` in realm `platform` |
| Admin password | `make admin` prints the `kubectl` command to read secret `platform-idp` (key `admin-password`) in namespace `identity` |

```bash
# UI local
make ui-install && make ui-dev   # http://localhost:5173
```

More: [Getting started](getting-started.md) · [Deploy haven-idp (native)](deploy-native.md) · [Lab host](lab-host.md).
