# Production overlay

> **Docs:** [production-overlay.md](https://zyvorai.github.io/haven/production-overlay/) · [backups.md](https://zyvorai.github.io/haven/backups/)

This overlay is a **shape**, not a one-command install. It will not become Ready until you supply two things the compose path cannot invent:

1. **Secrets** — run `./hack/gen-prod-secrets.sh` (or External Secrets) before applying. It creates `platform-db-app`, `platform-idp-db` (username, password, dsn) and `platform-idp` (csrf-key, secret-key, admin-password, admin-client-secret); it never overwrites and never prints values. The overlay commits no secrets, so applying it cannot clobber real ones.
2. **TLS secret `platform-tls`** — see `tls.yaml.example`. Apply after a ClusterIssuer exists.

The NetworkPolicy `platform-idp` assumes the gateway namespace is labelled `app.kubernetes.io/name: gateway`, Prometheus runs in `monitoring` and an OTLP collector in `observability`; adjust to your cluster.

## Apply order

```bash
./hack/gen-prod-secrets.sh            # creates the secrets in the cluster
kubectl apply -k deploy/overlays/prod
kubectl -n identity wait cluster/platform-db --for=condition=Ready --timeout=600s
kubectl -n identity rollout status deployment/platform-idp
kubectl apply -f deploy/overlays/prod/tls.yaml.example   # after editing issuer
```

## Backups

Not included. A `ScheduledBackup` with `method: barmanObjectStore` is rejected unless the Cluster has an object store (legacy in-tree, deprecated in CNPG 1.26+) or a CNPG-I plugin `ObjectStore`.

See [backups.md](https://zyvorai.github.io/haven/backups/) (published docs) or `backup/README.md` in this directory.
