# What you get

The moving parts of a Haven plane, how they fit together, and the design principles behind them.

[Back to the README](https://github.com/zyvorai/haven#readme) · [Documentation map](documentation-map.md)

---

## Components

- **`haven-idp`**: Haven's own OIDC identity server (Go, PostgreSQL-backed, stateless replicas). Dev mode needs no database (`haven-idp dev`).
- **`IdentityPlane`**: one CR for Postgres + identity server + certs + ingress, reconciled by `haven-controller`
- **`OIDCClient`**: apps register themselves from a manifest or an Ingress annotation ([OIDCClient CRD](oidcclient-crd.md))
- **Kustomize overlays**: `deploy/overlays/{dev,prod}` render the same objects without a controller
- **Command Deck**: live plane and identity-server health in one glass
- **Realm Studio**: realms, users, clients and IdPs, with Guard in the loop
- **CLIs**: `haven` (login and tokens), `haven-audit` (CI posture checks), `haven-idp` (the server), and `./cli/haven` for plane operations (`deploy`, `status`, `doctor`, `admin`, `backup`)
- **Private-cloud defaults**: NetworkPolicies, Pod Security `restricted`, TLS, metrics on in `production`

```text
  you ──► IdentityPlane CR ──► haven-controller
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
              CloudNativePG     haven-idp      Certs + Ingress
              (HA Postgres)     (2+ replicas)  (cert-manager)

  no controller: deploy/overlays/{dev,prod} render the same objects
```

**Scope:** Haven deploys and operates its identity server and the PostgreSQL cluster behind it (CloudNativePG). It is **not** an AI agent or app-data tool: the Postgres cluster is the identity store, not your app OLTP. Pinned versions: [`versions.env`](https://github.com/zyvorai/haven/blob/main/versions.env).

### Design principles

1. **One object, two runtimes**: the database and the identity server share a lifecycle; default `reclaimPolicy: Orphan`
2. **Operators stay official**: compose CloudNativePG and cert-manager; no forks
3. **Secrets never leave the cluster**: generated once, never overwritten on later reconciles
4. **Git is optional**: the console can write CRs; Flux/Argo can own the same CRs
5. **Private-cloud defaults**: NetworkPolicies, TLS, metrics on in `production`
6. **Identity is a platform service**: the first realm can mint OIDC clients for the Kubernetes API, Grafana, Argo CD, Zeus OS
