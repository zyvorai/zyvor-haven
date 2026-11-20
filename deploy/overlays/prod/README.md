# Production overlay

> **Docs:** [production-overlay.md](https://zyvorai.github.io/haven/production-overlay/) · [backups.md](https://zyvorai.github.io/haven/backups/)

This overlay is a **shape**, not a one-command install. It will not become Ready until you supply three things the compose path cannot invent:

1. **Database password** — run `./hack/gen-prod-secrets.sh` (or External Secrets). The committed value is `REPLACE_ME_BEFORE_APPLY`.
2. **TLS secret `platform-tls`** — see `tls.yaml.example`. Apply after a ClusterIssuer exists.
3. **CNPG CA ConfigMap `platform-db-ca`** — run `./hack/sync-cnpg-ca.sh` after the Cluster is healthy. Required because Keycloak sets `db-tls-mode: verify-server`.

## Apply order

```bash
./hack/gen-prod-secrets.sh            # writes /tmp secrets; apply them
kubectl apply -k deploy/overlays/prod
kubectl -n identity wait cluster/platform-db --for=condition=Ready --timeout=600s
./hack/sync-cnpg-ca.sh
kubectl apply -f deploy/overlays/prod/tls.yaml.example   # after editing issuer
```

## Backups

Not included. A `ScheduledBackup` with `method: barmanObjectStore` is rejected unless the Cluster has an object store (legacy in-tree, deprecated in CNPG 1.26+) or a CNPG-I plugin `ObjectStore`.

See [backups.md](https://zyvorai.github.io/haven/backups/) (published docs) or `backup/README.md` in this directory.
