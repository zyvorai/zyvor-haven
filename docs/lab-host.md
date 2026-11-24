---
hero:
  eyebrow: LAB HOST
  title: Lab host
---

Notes for the shared lab machine used for Haven console development and OIDC integration testing.

> Run all deploy commands from the **Haven repo root**.

---

## Console

| Service | URL |
|---|---|
| **Haven console** | `http://<lab-host>:30742` (NodePort **30742**, namespace `haven-ui`) |
| **Console login** | `http://<lab-host>:30742/login` |

The host's address is not published here. The console Deployment and its manifests live in `deploy/k8s/ui/`.

!!! warning "Not yet moved to haven-idp"
    `scripts/deploy-remote.sh` and the manifests in `deploy/k8s/ui/` predate the `haven-idp` identity server. They configure the console through a separate admin-credentials secret rather than the `HAVEN_IDP_*` settings, and they have not been verified against a haven-idp plane. For a plane with the console, use the Helm path in [deploy-native.md](deploy-native.md#2-controller-and-console), which sets the console up against `haven-idp` by default.

The script copies the repo to the host, builds and loads the console image (unless `--quick`) and applies `deploy/k8s/ui/`:

```bash
./scripts/deploy-remote.sh <lab-host> <user>
./scripts/deploy-remote.sh <lab-host> <user> --quick       # skip image rebuild
./scripts/deploy-remote.sh <lab-host> <user> --uninstall
```

Sign-in modes (including the opt-in lab `demo` login enabled by `HAVEN_LAB_LOGIN`): [console.md → Authentication](console.md#authentication).

---

## Wire OIDC clients

Use the **issuer URL** of the realm, `https://<hostname>/realms/<realm>` (HTTP for `profile: dev`), not an admin console root. For a lab plane created from the dev sample that is:

```text
http://auth.127.0.0.1.nip.io/realms/platform
```

Register the client in Realm Studio, with an [`OIDCClient`](oidcclient-crd.md) manifest, or with the [add-an-app wizard](add-an-app.md). For a public PKCE client (no secret), register the exact redirect URI of the app.

Platform SSO catalog for private-cloud clients: [private-cloud.md](private-cloud.md).

---

## Health checks

On the host:

```bash
kubectl get svc -n haven-ui
kubectl -n identity get deploy,svc -l app.kubernetes.io/name=haven-idp
curl -s https://<hostname>/realms/platform/.well-known/openid-configuration | head
```

---

## Related docs

- [Getting started](getting-started.md)
- [Console](console.md): auth, env vars, local dev
- [Tutorials → Verify deploy](tutorials.md#verify-deploy)
- [CLI → Remote deploy](cli.md#remote-deploy-script)
