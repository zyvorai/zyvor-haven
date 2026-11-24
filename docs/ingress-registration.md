# Ingress registration: an annotated Ingress registers its app

Annotate an `Ingress` and the controller generates an [`OIDCClient`](oidcclient-crd.md)
for it. The OIDCClient controller then registers the client with the plane and writes
the Secret, exactly as for a hand-written OIDCClient.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop
  namespace: apps
  annotations:
    haven.dev/oidc-client: "true"
    haven.dev/oidc-plane: platform
    haven.dev/oidc-plane-namespace: identity      # default: the Ingress namespace
    haven.dev/oidc-redirect-paths: /auth/callback # default: /oauth2/callback
spec:
  rules:
    - host: shop.example.com
```

The plane must opt in (default is closed):

```bash
kubectl -n identity annotate identityplane platform \
  haven.zyvor.dev/allow-ingress-registration-from=apps   # comma list or "*"
```

This produces `OIDCClient apps/ing-shop` with `clientId: ing:apps/shop` and
`redirectUris: [https://shop.example.com/auth/callback]`, owned by the Ingress
(`controller: true`), so deleting the Ingress garbage-collects it and, through the
OIDCClient finalizer, the IdP client (`deletionPolicy: Delete`). The Secret is
`ing-shop-oidc` in the Ingress namespace.

## Annotations

| Annotation | Default | Meaning |
|---|---|---|
| `haven.dev/oidc-client` | off | Exactly `"true"` enables. Anything else is off. Removing or changing it deletes the generated OIDCClient. |
| `haven.dev/oidc-plane` | required | IdentityPlane name. |
| `haven.dev/oidc-plane-namespace` | Ingress namespace | A different namespace also needs the plane's existing `haven.zyvor.dev/allow-oidcclients-from` (enforced by the OIDCClient controller). |
| `haven.dev/oidc-realm` | plane's first realm | Realm. |
| `haven.dev/oidc-redirect-paths` | `/oauth2/callback` | Comma separated **paths**, at most 10. |
| `haven.dev/oidc-hosts` | all rule hosts | Subset of the Ingress rule hosts. |
| `haven.dev/oidc-public` | `false` | `true`: public client (PKCE, no secret; `webOrigins` set to the https origins). |
| `haven.dev/oidc-scopes` | none | Validated and recorded as `haven.dev/requested-scopes` on the OIDCClient. **Advisory only**: OIDCClient has no scope field and the IdP does not restrict scopes per client. |
| `haven.dev/oidc-insecure-http` | off | `"true"` allows `http`, only on a plane whose profile is `dev` (an unset profile counts as dev) and only for loopback hosts (`localhost`, `127.0.0.1`, `::1`). |

## Security properties

- **Hosts come from the Ingress rules only.** The hosts annotation can only narrow. Wildcard
  and empty rule hosts are never used; a host equal to the plane's own `hostname` or
  `consoleHostname` is refused.
- **Redirect URIs are derived, never free-form:** `scheme://host` + a validated path. A path
  must start with a single `/`, uses only `A-Za-z0-9/_.~:@!$&'()+,=;-`, so no `*`, `%`,
  `?`, `#`, backslash, whitespace, `//` or `.`/`..` segments. A full URL in the annotation is
  rejected. Every derived URI is also passed through the OIDCClient controller's own URI
  rules.
- **https only**, except dev-profile + loopback + explicit opt-in.
- **Plane opt-in:** without `haven.zyvor.dev/allow-ingress-registration-from` listing the
  Ingress namespace (or `*`) nothing is generated, even in the same namespace.
- **Never touches what it does not own.** The generated name is `ing-<ingress>`. If an
  OIDCClient with that name exists and is not controlled by this Ingress (matching UID), it is
  neither read as ours, updated nor deleted; a `IngressRegistrationConflict` event is emitted.
  Switching registration off deletes only an owned client. The IdP-side check (an IdP client
  with the same id that the OIDCClient did not create is not taken over) is the OIDCClient
  controller's; the generator also strips `haven.zyvor.dev/adopt-client` from what it owns.
- **Idempotent and drift-safe.** The whole spec of the generated OIDCClient is recomputed
  from the Ingress every time and overwritten if it differs (also on edits to the OIDCClient,
  which is watched); an unchanged Ingress causes no writes.
- **Fail closed, last known good.** Invalid annotations produce a Warning event on the
  Ingress and no change; an existing generated client keeps its previous spec (an invalid
  edit neither widens nor deletes it).
- Anyone who can create Ingresses in an opted-in namespace can register clients for hosts
  they route. Restrict who may create Ingresses (admission, host policies) accordingly.

## RBAC

Controller ClusterRole: `ingresses` get/list/watch and `ingresses/finalizers` update (needed
for the owner reference when `OwnerReferencesPermissionEnforcement` is on), `oidcclients`
create/update/delete (already granted). The plain manifest grants no write verbs on
Ingresses; a test pins this. The Helm chart already carried broader Ingress verbs for
exposing planes.

## Not yet

- Verified against the fake client only: not run on a real cluster or with a live
  controller-manager.
- Results are Events only; no status or condition is written to the Ingress (the OIDCClient
  carries Ready/Synced).
- Scopes are advisory. No Gateway API `HTTPRoute` support. No per-namespace host allow-list
  beyond the plane opt-in. A `localhost` http registration is the only non-https case.
- Plane lookup failures retry every 30 seconds; plane changes (for example becoming opt-in)
  are picked up by that retry, not by a watch.
