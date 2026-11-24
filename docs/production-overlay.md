---
hero:
  eyebrow: PRODUCTION OVERLAY
  title: Production overlay
---

This overlay is a **shape**, not a one-command install. It will not become Ready until you supply two things the compose path cannot invent, and you should configure a third:

1. **Secrets**: run `./hack/gen-prod-secrets.sh` (or External Secrets) before applying. It creates `platform-db-app`, `platform-idp-db` (username, password, dsn) and `platform-idp` (csrf-key, secret-key, admin-password, admin-client-secret); it never overwrites existing secrets and never prints values. The overlay commits no secrets.
2. **TLS secret `platform-tls`**: see `deploy/overlays/prod/tls.yaml.example`. Apply after a ClusterIssuer exists.
3. **Backups**: not in the base overlay; see below.

The NetworkPolicy `platform-idp` assumes the gateway namespace is labelled `app.kubernetes.io/name: gateway`, Prometheus runs in `monitoring` and an OTLP collector in `observability`; adjust to your cluster. `haven-idp` connects to Postgres with `sslmode=require`, so no CA ConfigMap is needed.

Manifests live in [`deploy/overlays/prod/`](https://github.com/zyvorai/haven/tree/main/deploy/overlays/prod).

---

## Apply order

```bash
./hack/gen-prod-secrets.sh            # creates the three secrets in the cluster
kubectl apply -k deploy/overlays/prod
kubectl -n identity wait cluster/platform-db --for=condition=Ready --timeout=600s
kubectl -n identity rollout status deployment/platform-idp
kubectl apply -f deploy/overlays/prod/tls.yaml.example   # after editing issuer
```

Or via Makefile: `make secrets-prod`, `make prod`.

---

## Backups

Not included in the base overlay. A `ScheduledBackup` with `method: barmanObjectStore` is rejected unless the Cluster has an object store or CNPG-I plugin `ObjectStore`.

See [Backups](backups.md).

---

## Related

- [Getting started → Production overlay](getting-started.md#production-overlay)
- [Runbook → Path C](runbook.md#path-c)
