# Kubernetes login (kube-apiserver trusts haven-idp)

People sign in to a Kubernetes cluster with their haven-idp account, and
haven-idp groups decide what they may do. `kubectl` gets the token from
[`haven exec-credential`](haven-cli.md); the API server verifies it on its own,
with the issuer's public keys. Nothing is installed in the cluster.

`haven-idp kube-config generate` writes the settings, and
`haven-idp kube-config check` explains why a login does not work.

The command is part of `haven-idp`, the operator's tool: it produces
control-plane configuration and can use the Admin API with the admin secret.
The `haven` CLI stays what users run on their machines; it holds only their own
credentials.

## What you need

- haven-idp reachable over **https** (the API server refuses an `http` issuer),
  at a name every control-plane node resolves. `haven-idp dev` serves plain
  http, so it cannot be used as is.
- Kubernetes 1.30 or later for the AuthenticationConfiguration
  (`--authn-api-version v1beta1` up to 1.33; the default `v1` needs 1.34). The
  flags also work on older releases that support `ES256`.
- The `haven` CLI on each user's machine.

## Set up

### 1. Turn on the groups claim

haven-idp puts a `groups` claim into an ID token only when **both** are true:
the operator listed the client in `HAVEN_IDP_GROUPS_CLAIM_CLIENTS`, and the
login asked for the `groups` scope.

```sh
HAVEN_IDP_GROUPS_CLAIM_CLIENTS=platform/kubernetes      # realm/clientId, comma separated
```

Restart haven-idp after changing it. A malformed entry stops the server from
starting.

### 2. Generate, and create the client

```sh
export HAVEN_IDP_ADMIN_REALM=platform
export HAVEN_IDP_ADMIN_CLIENT_SECRET_FILE=/etc/haven/admin-secret

# --ca-file is only needed when the issuer's certificate is from a private CA
haven-idp kube-config generate \
  --issuer https://idp.example.com/realms/platform \
  --ca-file ca.pem \
  --bind developers=view@default \
  --bind developers=edit@team-a \
  --bind platform-ops=view \
  --cluster prod \
  --ensure-client \
  --out-dir ./kube-haven
```

`--out-dir` writes one file per item (mode 0600, never overwritten without
`--force`); without it everything is printed, and `--only flags|authn|kubeadm|k3s|kubeconfig|rbac`
prints one item, ready to pipe.

| File | What it is |
|---|---|
| `apiserver-flags.txt` | the `--oidc-*` flags (alternative A) |
| `authn.yaml` | the structured `AuthenticationConfiguration` (alternative B) |
| `kubeadm.yaml` | `ClusterConfiguration` (v1beta4, kubeadm 1.31+) for B, flags as comments |
| `k3s.yaml` | `config.yaml.d` drop-in for B, flags as comments |
| `kubeconfig-user.yaml` | a user entry running `haven exec-credential` (and a context with `--cluster`) |
| `rbac.yaml` | `RoleBinding` / `ClusterRoleBinding` objects for the `--bind` flags |
| `oidc-ca.pem` | the CA, when `--ca-file` is given |

### 3. Configure the API server

Use the flags **or** the AuthenticationConfiguration; the API server refuses to
start with both. The flags look like this:

```text
--oidc-issuer-url=https://idp.example.com/realms/platform
--oidc-client-id=kubernetes
--oidc-username-claim=preferred_username
--oidc-username-prefix=haven:
--oidc-groups-claim=groups
--oidc-groups-prefix=haven:
--oidc-signing-algs=ES256
--oidc-required-claim=typ=ID
--oidc-ca-file=/etc/kubernetes/haven/oidc-ca.pem
```

Two of them are easy to forget when writing this by hand:

- `--oidc-signing-algs=ES256`: haven-idp signs with ES256 and the flag's
  default accepts only RS256.
- `--oidc-required-claim=typ=ID`: without it the API server also accepts other
  tokens haven-idp signed for the same audience, such as the **access token** of
  the same login (or an agent token whose audience was set to the cluster's
  client id).

The AuthenticationConfiguration says the same, embeds the CA, and adds CEL
rules that reject any user or group name starting with `system:`.

With **kubeadm**, put `authn.yaml` in `/etc/kubernetes/haven/` on every
control-plane node and merge `kubeadm.yaml` into your `ClusterConfiguration`
(on a running cluster, then regenerate the API server static pod the usual
kubeadm way). With **k3s**, put `authn.yaml` in `/etc/rancher/k3s/haven/`, save
`k3s.yaml` as `/etc/rancher/k3s/config.yaml.d/haven.yaml` on every server and
restart k3s. In flags mode the CA file must exist at the path in the flag
(`--node-ca-path` changes it).

Managed control planes (EKS, GKE, AKS) have their own OIDC settings screens;
use the values above and check that the provider supports ES256 and required
claims.

### 4. Bind groups

```sh
kubectl apply -f kube-haven/rbac.yaml
```

`--bind` forms:

| Form | Result |
|---|---|
| `GROUP=ROLE` | `ClusterRoleBinding` to ClusterRole `ROLE` |
| `GROUP=ROLE@NS` | `RoleBinding` in `NS` to ClusterRole `ROLE` |
| `GROUP=role/NAME@NS` | `RoleBinding` in `NS` to the namespaced Role `NAME` |

`GROUP` is the haven-idp group path without the leading `/` (`developers`,
`eng/dev`), **without** the prefix. The subject becomes `haven:developers`.

Refused: any group in the `system:` namespace, any role starting with
`system:`, and `cluster-admin` unless `--allow-cluster-admin` is given. The
generator warns about `admin` or `edit` cluster wide and about write access in
`kube-system`, both of which can be escalated to cluster-admin.

### 5. Users sign in

Once per machine (the generator prints this line):

```sh
haven login --issuer https://idp.example.com/realms/platform \
  --client-id kubernetes --profile kubernetes \
  --scope "openid offline_access groups" --ca-file ca.pem
```

`--scope` matters: the default scope of `haven login` does not include
`groups`. Then merge the generated user entry with the cluster's kubeconfig:

```sh
KUBECONFIG=cluster.kubeconfig:kube-haven/kubeconfig-user.yaml \
  kubectl --context haven@prod auth whoami
```

`haven exec-credential` refreshes the ID token as needed and never prompts.

## Check

```sh
haven token --id-token --profile kubernetes |
  haven-idp kube-config check --issuer https://idp.example.com/realms/platform \
    --ca-file ca.pem --require-group developers --token-file -
```

`check` verifies, and explains how to fix: an https issuer; DNS, connection and
TLS (with `--ca-file`, only that CA is trusted, as in the API server); a
discovery document whose `issuer` matches exactly; the key set; that the realm
offers the `groups` scope; and for a sample token its signature, `iss`, `aud`,
`typ`, expiry, username claim, `groups` claim and any `--require-group`. It
prints the user and groups the API server would see. `--format json` is
available. Exit code 0 means no failure, 1 a failed check, 2 a usage error.

The token is read from a file or stdin only (also as the JSON printed by
`haven exec-credential`), is never sent anywhere and never printed.

`check` runs **where you run it**. The control-plane nodes need the same DNS,
route, proxy settings and trust; run it there when in doubt. It does not read
the API server's configuration.

## The groups claim

| Property | Behaviour |
|---|---|
| Where | the ID token only (not the access token, not userinfo) |
| When | client listed in `HAVEN_IDP_GROUPS_CLAIM_CLIENTS` **and** `groups` scope granted; otherwise absent |
| Value | sorted list of group paths without the leading `/`; `[]` when the user is in none |
| Filtered | anything starting with `system:` (any letter case), and names with control or invisible characters or surrounding spaces, are never emitted |
| Freshness | read again at every token issue, including refresh |
| Discovery | `groups` appears in `scopes_supported` / `claims_supported` of realms with a listed client |

A refresh cannot add the scope to a login that did not request it
(`invalid_scope`). Where the browser flow shows the
[consent screen](mcp-clients-and-consent.md#choosing-scopes) for this client,
the user can untick `groups`, and `preferred_username` is only in the token when
`profile` was requested and left ticked: with the default
`--username-claim preferred_username`, request `profile` too, or list the client
in the consent policy's `skipClients`.

## The client created by `--ensure-client`

A **public** client with the device authorization grant and nothing else. With
`--redirect URI` (https, or http on loopback) the authorization code flow with
PKCE S256 is enabled too, for tools such as kubelogin. The command is
idempotent:

- missing client: created;
- suitable client: unchanged;
- public client lacking something: reported, changed only with
  `--update-client` (additively);
- confidential, service-account or disabled client of that id: never touched.

It warns when the client has redirect URIs that are not on loopback: whoever
receives codes there can obtain tokens the cluster accepts. Use a client id
that no application uses.

It calls the Admin API with the same settings as `haven-idp plan`/`apply`
(`--url`, `--admin-realm`, `--admin-client-id`, `--env-file`,
`HAVEN_IDP_ADMIN_CLIENT_SECRET[_FILE]`); the URL defaults to the issuer's base
and must be https unless it is loopback. Routes used: `GET`, `POST` and `PUT`
on `/admin/v1/realms/{realm}/clients`; no new routes. Haven Guard applies to
these writes as to any other.

## Security properties

- Names from haven-idp are prefixed (`haven:`). An empty prefix, a prefix not
  ending in `:` and one starting with `system` are refused, so a haven-idp name
  cannot become `system:masters`. haven-idp also never emits `system:` groups,
  and the AuthenticationConfiguration rejects them again.
- Only ID tokens issued to the cluster's client id are accepted.
- Whoever can manage groups and membership in the realm (Admin API
  administrators, the SCIM token holder) controls cluster permissions of every
  bound group. Protect them like cluster administrators. A dedicated realm or
  Admin API discipline is worth considering.
- The default username claim, `preferred_username`, is readable but can be
  reused: an account that is renamed or deleted frees the name. Bind groups
  rather than users, or use `--username-claim sub` (stable, opaque).
- **Revocation is not immediate.** The API server does not ask haven-idp whether
  a session is still alive. After disabling a user, ending a session or removing
  a group, an ID token already issued keeps working until it expires (the
  realm's access token lifetime, 5 minutes by default); the next refresh is
  refused or carries the new groups. Keep that lifetime short.
- The device flow is exposed to device-code phishing: users must approve only
  logins they started themselves.
- The opt-in is by `realm/clientId`. A client deleted and created again under
  the same id inherits it.
- The generated files contain no secret. The CA file must contain only
  certificates; a file with a private key is refused.

## Verified

With a real `kube-apiserver` and `etcd` 1.34.1 (envtest binaries) on one
machine, haven-idp behind a TLS proxy with a private CA, and the real `haven`
and `kubectl`: the generated AuthenticationConfiguration (`v1` and `v1beta1`)
and the generated flags each authenticated users as `haven:alice` with groups
`haven:devs` (a haven group named `system:masters` was not emitted); a generated
`RoleBinding` granted exactly its permissions in its namespace and a user
without groups got none; the access token of the same login, a token with a bad
signature and an ID token of another client were rejected; with the groups
prefix edited to `system:` the CEL rule rejected the login.

## Not yet

- The `kubeadm` and `k3s` snippets were only parsed as YAML: neither tool was
  run. Nothing was run on a multi-node or managed cluster, or on a Kubernetes
  release other than 1.34.1.
- The test API server ran without a controller manager, so the built-in
  aggregated roles (`view`, `edit`, `admin`) had no rules there; permissions
  were proven with a plain ClusterRole.
- The browser (authorization code) flow with kubelogin was not run.
- The opt-in list is an environment variable: no Admin API or console setting,
  and a restart is needed to change it.
- All of a user's groups are sent; there is no per-client group filter.
- No logout or revocation signal to the API server, and no multi-issuer or
  multi-cluster generation in one run (run it once per issuer and client id).
