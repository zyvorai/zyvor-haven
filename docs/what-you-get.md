# What you get

The moving parts of a Haven plane, how they fit together, and the design principles behind them.

[Back to the README](https://github.com/zyvorai/haven#readme) · [Documentation map](documentation-map.md)

---

## Components

- **`IdentityPlane`** — one CR for Postgres + Keycloak + certs + ingress (controller path in v1)
- **Compose today** — `deploy/overlays/{dev,prod}` are the exact manifests the controller will render
- **Command Deck** — live plane + Keycloak health in one glass
- **Realm Studio** — realms, users, clients, IdPs without living in the Keycloak admin UI
- **CLI** — `deploy`, `status`, `doctor`, `admin`, `backup`
- **Private-cloud defaults** — NetworkPolicies, TLS, metrics on in `production`

```text
  you ──► IdentityPlane CR ──► Haven controller (v1)
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
              CloudNativePG   Keycloak CR    Certs + Gateway
              (HA Postgres)   (official op)  (cert-manager)

  v0 compose path: deploy/overlays/{dev,prod}  (no controller required)
```

**Scope:** Haven deploys and operates Keycloak + PostgreSQL (CloudNativePG). It is **not** an AI agent or app-data tool — the Postgres cluster is Keycloak’s store, not your app OLTP. Pinned versions: [`versions.env`](https://github.com/zyvorai/haven/blob/main/versions.env).

### Design principles

1. **One object, two runtimes** — DB and Keycloak share a lifecycle; default `reclaimPolicy: Orphan`
2. **Operators stay official** — compose CloudNativePG and Keycloak Operator; no forks
3. **Secrets never leave the cluster** — operator bootstrap secret is source of truth in v0
4. **Git is optional** — console can write CRs; Flux/Argo can own the same CRs
5. **Private-cloud defaults** — NetworkPolicies, TLS, metrics on in `production`
6. **Identity is a platform service** — first realm can mint OIDC clients for Kubernetes API, Grafana, Argo CD, Zeus OS
