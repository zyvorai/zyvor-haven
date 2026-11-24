# Controller RBAC required by haven-idp planes

Add to the controller ClusterRole (`charts/haven/templates/rbac.yaml` and
`deploy/k8s/controller/deployment.yaml`). Existing rules (identityplanes and
status/finalizers, namespaces get/patch, secrets, CNPG clusters/backups,
cert-manager certificates) stay as they are.

```yaml
# Deployments, owned and watched (Owns)
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Service, ServiceAccount, owned (Services are also watched)
- apiGroups: [""]
  resources: ["services", "serviceaccounts"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# PodDisruptionBudget (created for replicas > 1, deleted when it drops to 1)
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Pod waiting reasons (ImagePullBackOff, ...) for the IdentityProviderReady
# message. Read through the uncached API reader, so no pod informer is started.
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

Secrets: the controller now also does `get`, `create` and `patch` on Secrets
(`<plane>-idp`, `<plane>-idp-db`, `<plane>-db-app`). If the existing rule is
narrower than `get/list/watch/create/patch`, widen it; `update` and `delete`
are not needed. Secrets are read through the cached client, so `list` and
`watch` are required as before.

Also: `deployments` and `services` are watched, so `watch` is mandatory (not
only `get`).

OIDCClient controller (see `docs/oidcclient-crd.md`), in both the chart and
`deploy/k8s/controller/deployment.yaml`: `oidcclients`, `oidcclients/status` and
`oidcclients/finalizers` (get/list/watch/create/update/patch/delete), Secrets with
`update` as well (still no `delete`), and `events` create/patch for the recorder.
`internal/deploytest` asserts all of it.

Optional env on the controller Deployment: `HAVEN_IDP_IMAGE` (default
haven-idp image, e.g. `ghcr.io/zyvorai/haven-idp:<version>`); without it new
planes get `ghcr.io/zyvorai/haven-idp:latest` unless `spec.idp.image` or
`spec.idp.version` is set.

Ingress registration (see `docs/ingress-registration.md`): `networking.k8s.io` `ingresses`
get/list/watch and `ingresses/finalizers` update (blockOwnerDeletion on the generated
OIDCClient) in both the chart and `deploy/k8s/controller/deployment.yaml`; creating and
deleting `oidcclients` was already granted. The plain manifest deliberately grants no
write verbs on Ingresses.
