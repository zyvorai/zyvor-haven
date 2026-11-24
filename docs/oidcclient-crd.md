# OIDCClient: register an app from Kubernetes

An `OIDCClient` registers an OIDC client with a native [haven-idp](deploy-native.md)
plane and writes its credentials to a Secret next to your workload. Apps register
themselves from their own manifests; nobody clicks through the console.

```yaml
apiVersion: identity.haven.dev/v1alpha1
kind: OIDCClient
metadata: {name: shop-web, namespace: apps}
spec:
  planeRef: {name: platform, namespace: identity}
  redirectUris: [https://shop.example.com/auth/callback]
```

```bash
kubectl -n apps get oidc            # PLANE, REALM, CLIENTID, READY, SECRET
kubectl -n apps get secret shop-web-oidc -o jsonpath='{.data.issuer}' | base64 -d
```

!!! warning "Status of this feature"
    Implemented against the in-memory Admin API fake and one real `haven-idp dev`
    process (see [Testing](#testing)). It has **not** been run on a real cluster, and the
    CRD has not been applied to a real API server. Treat it as `v1alpha1`.

Samples: `config/samples/oidcclient.yaml` (public SPA, confidential web app, service
account). The CRD is `config/crd/haven.identity_identityplanes.yaml` (all three Haven CRDs
live in that one file; `make crds` applies it) and is copied byte for byte to
`charts/haven/crds/haven.identity_crds.yaml` for Helm. A test keeps the two identical.

!!! note "Replaces the old placeholder CRD"
    Earlier releases shipped a placeholder `OidcClient` CRD (`spec.planeRef` a string,
    `redirects`, `secretName`) that no controller read. It is replaced by this `OIDCClient`
    (same plural `oidcclients`, short name `oidc`). Re-apply the CRD and rewrite any
    leftover objects; nothing acted on the old ones.

## Spec

| Field | Default | Meaning |
|---|---|---|
| `planeRef.name` | required | The `IdentityPlane` hosting the client. Must use the native engine. |
| `planeRef.namespace` | the OIDCClient's namespace | Another namespace is honoured only if the plane allows yours, see [Cross-namespace](#cross-namespace-references). |
| `realm` | the plane's `spec.bootstrap.firstRealm` | Realm to create the client in. Immutable. |
| `clientId` | `metadata.name` | OIDC `client_id`. Immutable. `haven-admin` and `haven-console` are reserved. Pattern `^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`. |
| `displayName` | empty | Human name shown in the console. |
| `public` | `false` | Public client: no secret, PKCE always on. |
| `redirectUris` | none | Exact URLs. Required when the authorization code flow is on. At most 50. |
| `webOrigins` | none | CORS origins (scheme, host, port; no path). At most 50. |
| `pkce` | `true` | Require PKCE. S256 is the only method that exists. `false` is rejected for public clients. |
| `serviceAccount` | `false` | Enable the client credentials grant. |
| `flows.authorizationCode` | `true`, except `false` when `serviceAccount` is set and there are no `redirectUris` | Browser login. |
| `flows.clientCredentials` | follows `serviceAccount` | Same switch as `serviceAccount`; either one turns it on. |
| `backchannelLogoutUrl` | none | Sent to the IdP: the client is notified by OIDC Back-Channel Logout when a session it took part in ends ([sso-and-logout.md](sso-and-logout.md)). https, or http on loopback. Removing it clears it. |
| `secretRef.name` | `<metadata.name>-oidc` | Secret written for confidential clients. |
| `secretRef.keys.{clientId,clientSecret,issuer}` | `client-id`, `client-secret`, `issuer` | Key names inside the Secret. Must be distinct. |
| `deletionPolicy` | `Delete` | `Delete` removes the IdP client with the OIDCClient; `Retain` leaves it. |

At least one flow must be enabled. A public client cannot be a service account.

### Redirect URI and origin rules

Checked by the controller before anything reaches the IdP. These follow the
config-as-code validator (`internal/idp/configcode`, whose function is unexported, so the
rules are restated in `internal/controller/oidcclient_controller.go`):

- no `*` anywhere, so no wildcard hosts or paths;
- `https`, or `http` only for `localhost`, `127.0.0.1` and `::1`;
- never `javascript:`, `data:`, `vbscript:`, `file:` or `blob:`;
- no fragment, no `user:pass@`, at most 2048 characters.

This is stricter than the Admin API itself, which also accepts custom schemes
(`myapp://callback`). Native-app custom schemes are therefore rejected here, see
[Not yet](#limits-and-not-yet).

## Status

| Field | Meaning |
|---|---|
| `conditions[Ready]` | The client exists, matches the spec and (if confidential) its Secret is written. |
| `conditions[Synced]` | The last attempt to reach that state succeeded. Both carry the same reason. |
| `clientUuid` | The IdP's internal id for the client. |
| `issuer` | `https://<plane hostname>/realms/<realm>`, what apps put in their OIDC config. |
| `secretName` | The Secret holding the credentials; empty for public clients. |
| `lastSyncTime` | When the controller last changed something (IdP client, Secret). Idle reconciles do not move it. |
| `observedGeneration` | The spec generation the conditions describe. |
| `plane`, `realm`, `clientId` | What was actually created. Used to detect edits of immutable fields. |

Condition reasons: `Synced`, `InvalidSpec`, `PlaneNotFound`, `PlaneNotAllowed`,
`PlaneNotNative`, `PlaneNotReady`, `PlaneUnreachable`, `RealmNotFound`, `ClientExists`,
`SecretNotOwned`, `ImmutableFieldChanged`, `BackendError`, `Deleting`.

Retry behaviour: `InvalidSpec`, `PlaneNotAllowed`, `ImmutableFieldChanged` do not requeue
(only editing the object fixes them, and that triggers a reconcile), so a bad spec never
hot-loops. `PlaneNotFound`, `PlaneNotReady`, `PlaneUnreachable`, `RealmNotFound` retry every
20 to 30 seconds. `ClientExists`, `SecretNotOwned` and `PlaneNotNative` re-check every five
minutes. A healthy object is re-checked every five minutes for [drift](#drift).

## How it reconciles

1. Validate the spec. Invalid: condition `InvalidSpec`, nothing else happens.
2. Find the plane and check it is allowed, native and `IdentityProviderReady`.
3. Reach the Admin API as `haven-admin` of the plane's first realm, using the same
   credential as the console (Secret `<plane>-idp`, key `admin-client-secret`; URL
   `http://<plane>-idp.<ns>.svc:8081`). Only the Admin API (`idp.Provider`) is used.
4. Look the client up (by `status.clientUuid`, then by `clientId`). Create it if missing;
   otherwise compare the fields the controller manages and `PUT` only on a difference.
   A second reconcile with nothing changed performs no write to the IdP and none to
   Kubernetes (no status write either); this is tested.
5. For a confidential client, write the Secret (below).
6. Update status and conditions.

The controller manages: display name, enabled, public, redirect URIs, web origins,
authorization code flow, service account, and the PKCE attribute. Everything else on the
IdP client (description, other attributes) is left as it is.

## Secret handling

Only confidential clients (`public: false`, including service accounts) get a Secret. It
is created in the OIDCClient's namespace with these keys and an owner reference to the
OIDCClient, so deleting the OIDCClient garbage-collects it:

| Key (default name) | Value |
|---|---|
| `client-id` | the `clientId` |
| `client-secret` | the generated secret |
| `issuer` | the issuer URL |

The IdP stores only a hash and shows a generated secret once, at creation. The controller
therefore captures it from the create call (or calls the regenerate endpoint) and writes it
straight to the Secret. It is never read back from the IdP.

Rules:

- **Written once.** An existing Secret with a non-empty `client-secret` is left alone, so a
  secret you rotated by hand is never overwritten. (`client-id` and `issuer` are not secret
  and always follow the spec.) The controller cannot tell whether a hand-edited value still
  matches the IdP; that is yours to keep consistent.
- **Rotate on request.** Set the annotation `haven.zyvor.dev/rotate-secret` on the
  OIDCClient to any value you have not used before. The controller regenerates the secret
  in the IdP, writes it, and records the handled value on the Secret
  (`haven.zyvor.dev/rotate-handled`), so the same value never rotates twice. The old
  secret stops working immediately (the IdP has no overlap period).
  `kubectl annotate oidc shop-web haven.zyvor.dev/rotate-secret="$(date +%s)" --overwrite`
- **Missing Secret or key.** If the Secret was deleted, or its `client-secret` is empty or
  missing (also when you rename `secretRef.keys.clientSecret`), the secret is regenerated
  and written. Workloads must pick up the new value (restart, or a Secret reloader).
- **Not ours, not touched.** If a Secret with that name exists and is not owned by this
  OIDCClient the controller refuses (`SecretNotOwned`) and changes nothing.
- **Never in logs, status, events or errors.** Secret values appear only in the Secret.
  Backend error bodies are replaced by `identity backend returned <code>`. Tests capture
  the log and event streams through create, rotate, drift and delete and assert this.
- Changing `secretRef.name` writes a new Secret with a regenerated secret; the old Secret
  stays until the OIDCClient is deleted (the controller has no `delete` on Secrets).
- Switching a client to `public: true` leaves its old Secret in place (owned, so it goes
  with the OIDCClient). Switching to confidential creates one.

## Deletion policy

A finalizer (`identity.haven.dev/oidcclient`) is added on first reconcile.

- `Delete` (default): the IdP client is deleted by its UUID. "Not found" counts as done.
  If the plane is not ready the object waits (condition `Deleting`, retry every 20 s);
  set `deletionPolicy: Retain` to let it go without touching the IdP. If the plane no
  longer exists the finalizer is released, since the IdP is gone with it.
- `Retain`: the IdP client stays; the finalizer is removed.

Either way the Secret is garbage-collected by Kubernetes. If the controller was down while
the UUID was being recorded after a create (the UUID is stored in status immediately after
the create call), the client can be left behind; set `haven.zyvor.dev/adopt-client` to
reattach, then delete.

## Drift

The controller re-checks every five minutes, and immediately when the OIDCClient or its
Secret changes.

- Fields it manages are put back if edited in the console or Admin API.
- If the client was **deleted in the IdP** it is recreated, and because the IdP can only
  show a secret at creation, the client secret is **regenerated and the Secret is
  overwritten even if you had edited it** (the old value is dead anyway). A
  `DriftCorrected` event is recorded. Applications must reload the Secret.
- A client with the same `clientId` that this OIDCClient did not create is **not**
  taken over: `ClientExists`. This stops a tenant from rewriting someone else's client
  (or `haven-console`) by choosing its name. To adopt deliberately, annotate the OIDCClient
  `haven.zyvor.dev/adopt-client: "true"`; its redirect URIs and flags are then overwritten
  by your spec.
- `realm`, `clientId` and `planeRef` cannot change after creation (`ImmutableFieldChanged`);
  delete and recreate instead.

## Cross-namespace references

By default an OIDCClient may only reference a plane in its own namespace. Platform
operators allow other namespaces on the plane:

```bash
kubectl -n identity annotate identityplane platform \
  haven.zyvor.dev/allow-oidcclients-from="apps,team-a"      # or "*"
```

Without it the OIDCClient reports `PlaneNotAllowed` and nothing is written. Anyone who can
create OIDCClients in an allowed namespace can register clients in that plane, so treat
that RBAC like access to the realm.

## Examples

Public single-page app. No Secret; PKCE is on:

```yaml
apiVersion: identity.haven.dev/v1alpha1
kind: OIDCClient
metadata: {name: shop-spa, namespace: apps}
spec:
  planeRef: {name: platform, namespace: identity}
  public: true
  redirectUris: [https://shop.example.com/callback, "http://localhost:5173/callback"]
  webOrigins: [https://shop.example.com, "http://localhost:5173"]
```

Confidential web app. Secret `shop-web-oidc`, mount or `envFrom` it:

```yaml
apiVersion: identity.haven.dev/v1alpha1
kind: OIDCClient
metadata: {name: shop-web, namespace: apps}
spec:
  planeRef: {name: platform, namespace: identity}
  redirectUris: [https://shop.example.com/auth/callback]
  secretRef: {name: shop-web-oidc}
```

```yaml
# in the Deployment
env:
  - {name: OIDC_ISSUER, valueFrom: {secretKeyRef: {name: shop-web-oidc, key: issuer}}}
  - {name: OIDC_CLIENT_ID, valueFrom: {secretKeyRef: {name: shop-web-oidc, key: client-id}}}
  - {name: OIDC_CLIENT_SECRET, valueFrom: {secretKeyRef: {name: shop-web-oidc, key: client-secret}}}
```

Service account (client credentials only), kept in the IdP if the object is deleted:

```yaml
apiVersion: identity.haven.dev/v1alpha1
kind: OIDCClient
metadata: {name: nightly-export, namespace: apps}
spec:
  planeRef: {name: platform, namespace: identity}
  serviceAccount: true
  flows: {authorizationCode: false}
  deletionPolicy: Retain
```

## Permissions

The controller ClusterRole (chart `charts/haven/templates/rbac.yaml` and plain
`deploy/k8s/controller/deployment.yaml`, kept equal by `internal/deploytest`) grants:
`oidcclients` get/list/watch/create/update/patch/delete, `oidcclients/status` and
`oidcclients/finalizers`; `secrets` get/list/watch/create/update/patch (never delete);
`events` create/patch; plus the existing read access to `identityplanes`.
`oidcclients/finalizers` is what the owner reference on the Secret needs when the
`OwnerReferencesPermissionEnforcement` admission plugin is on. Secrets and the plane's
admin secret are read cluster-wide, as for the rest of the controller.

## Testing

- `internal/controller/oidcclient_controller_test.go`: fake Kubernetes client and fake
  `idp.Provider`. Covers public and confidential create, owner reference, idempotent
  reconcile, redirect updates, rotation, hand-rotated Secret, deletion with `Delete` and
  `Retain`, plane missing / not ready, invalid specs (a table of rejected redirect URIs
  and flags), drift recreation, adoption, foreign Secret, cross-namespace, and secret
  leakage into logs, events and status.
- `internal/controller/oidcclient_integration_test.go`: with `HAVEN_IDP_INTEGRATION=1` it
  builds `cmd/haven-idp`, starts `haven-idp dev` on a random loopback port with a throwaway
  HOME, reconciles against it through the native Admin API client, checks the clients exist,
  that the secret written to the (fake) Secret really obtains a `client_credentials` token,
  that drift and rotation kill the old secret, and that deleting the OIDCClient removes the
  client. It stops the server by the PID it started. Skipped otherwise.
- `internal/deploytest`: the CRD schema against the Go type (field by field), against every
  sample, chart CRD equals `config/crd`, and RBAC for every call the controller makes.
  None of this validates against a real API server.

## Limits and not yet

- **Ingress annotation:** see [ingress-registration.md](ingress-registration.md).
- The CRDs, samples and the manifests the controller renders were validated against a real k3s
  API server (server-side dry run, Pod Security `restricted`). The controller itself is exercised
  by unit tests and a test against the real `haven-idp`; see [deploy-native.md](deploy-native.md)
  for the in-cluster run. The CRD has no CEL immutability rules (the controller enforces
  immutability instead, reporting `ImmutableFieldChanged`).
- Native planes only. A plane on the Keycloak engine gets `PlaneNotNative`.
- Redirects: https or loopback http only. No custom-scheme (native app) redirects, no
  wildcards, by design.
- Flows: authorization code (+PKCE) and client credentials. The Admin API rejects the
  password grant and implicit flow, so they are not offered.
- A rotated secret has no overlap period; the IdP does not support one yet.
- The old Secret is not removed when `secretRef.name` changes.
- Drift is polled every five minutes; a plane becoming ready is noticed within 20 seconds
  but is not event-driven.
- Scopes, roles and audiences are not configurable from the CRD yet.
- The default Admin API connection assumes the in-cluster Service URL, so the controller
  must run in the cluster (or reach `<plane>-idp.<ns>.svc`).
