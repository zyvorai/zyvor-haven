---
hero:
  eyebrow: PRODUCTION OVERLAY
  title: Production overlay
---

This overlay is a **shape**, not a one-command install. It will not become Ready until you supply three things the compose path cannot invent:

1. **Database password** — run `./hack/gen-prod-secrets.sh` (or External Secrets). The committed value is `REPLACE_ME_BEFORE_APPLY`.
2. **TLS secret `platform-tls`** — see `deploy/overlays/prod/tls.yaml.example`. Apply after a ClusterIssuer exists.
3. **CNPG CA ConfigMap `platform-db-ca`** — run `./hack/sync-cnpg-ca.sh` after the Cluster is healthy. Required because Keycloak sets `db-tls-mode: verify-server`.

Manifests live in [`deploy/overlays/prod/`](https://github.com/zyvorai/haven/tree/main/deploy/overlays/prod).

---

## Apply order

```bash
./hack/gen-prod-secrets.sh            # writes /tmp secrets; apply them
kubectl apply -k deploy/overlays/prod
kubectl -n identity wait cluster/platform-db --for=condition=Ready --timeout=600s
./hack/sync-cnpg-ca.sh
kubectl apply -f deploy/overlays/prod/tls.yaml.example   # after editing issuer
```

Or via Makefile: `make secrets-prod`, `make prod`, `make sync-ca`.

---

## Backups

Not included in the base overlay. A `ScheduledBackup` with `method: barmanObjectStore` is rejected unless the Cluster has an object store or CNPG-I plugin `ObjectStore`.

See [Backups](backups.md).

---

## Related

- [Getting started → Production overlay](getting-started.md#production-overlay)
- [Runbook → Path C](runbook.md#path-c)
