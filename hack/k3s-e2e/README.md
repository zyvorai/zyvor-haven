# k3s end-to-end deployment test

Scripts that deploy the whole native stack on a real Kubernetes cluster and check it:
CloudNativePG, our CRDs, the controller, an `IdentityPlane` with two `haven-idp` replicas and a
database, then login/SSO/logout, the `OIDCClient` controller, high availability, persistence and
log hygiene.

```bash
hack/k3s-e2e/run.sh user@host build     # build the images from the current commit (needs docker or sudo docker)
hack/k3s-e2e/run.sh user@host deploy    # CNPG + CRDs + controller + plane; waits for Ready
hack/k3s-e2e/run.sh user@host verify    # about 40 checks; includes a drift wait of up to 7 minutes
hack/k3s-e2e/run.sh user@host upgrade   # roll a new image over live data (migrations, token continuity)
hack/k3s-e2e/run.sh user@host cleanup   # removes exactly what deploy recorded, then ~/haven-deploy
```

It needs passwordless `sudo` for `k3s kubectl`, `docker` and `k3s ctr` on the host, and internet
access to ghcr.io, docker.io and raw.githubusercontent.com. Everything lives in the namespaces
`haven-e2e` and `haven-e2e-system`; `cleanup` also removes the CRDs, the CNPG operator and the
images it installed. `deploy` refuses to start if any of those already exist.

## What it has found (all fixed; each has a regression test in the repo)

* Controller and console pods that Kubernetes would not start (`runAsNonRoot` without a numeric
  user while the image `USER` was a name). An API-server dry run cannot see this; only a kubelet can.
* Deployed planes had no `HAVEN_IDP_SECRET_KEY`, so TOTP and federation were silently off.
* Two replicas starting together created two ACTIVE signing keys (a check-then-insert race).
* `expose.networkPolicy` was documented and defaulted but the controller never created a policy.

## Host caveats (these are properties of the machine, not of Haven)

1. **Image garbage collection.** A host whose disk is above the kubelet threshold (85% by default)
   deletes imported images that no pod uses yet. The scripts pin the images
   (`io.cri-containerd.pinned=pinned`). Without that, pods fail with `ErrImagePull`.
2. **AppArmor stacking blocks in-container signals.** On one test host (Ubuntu, kernel 7.0,
   containerd 2.3) every container's default AppArmor label was `cri-containerd.apparmor.d//&unconfined`,
   and *no process could signal another*, even as the same user with no restrictions. PostgreSQL then
   loops forever in recovery with `could not signal for checkpoint: Permission denied`.
   `probe-signals.sh` and `probe-apparmor.sh` reproduce and isolate it (`appArmorProfile: Unconfined`
   fixes it; `RuntimeDefault` does not). `apparmor-workaround.sh` applies that to ONLY the database
   pod through the CNPG `Cluster`, and relaxes the test namespace from Pod Security `restricted` to
   `privileged` (the baseline level forbids `Unconfined`). That is a test-only concession: the
   `haven-idp` and controller pods keep their full hardening, and `verify.sh` checks their live
   security context. Fix the host's AppArmor/containerd setup for anything beyond a test.

## What this does NOT prove

* The `NetworkPolicy` the controller now creates has unit tests and an RBAC check but has **not** been
  exercised under real policy enforcement on a cluster.
* The upgrade script (migration 0012 repairing a live duplicate-key database) was written but not run to
  completion: the shared test host became too loaded. The migration is tested against real PostgreSQL in
  `internal/idp/store/pgstore`.
* There is no ingress controller on the test cluster, so TLS and external reachability were not tested.
  The plane's certificate is issued by a self-signed cert-manager issuer.
* Flows are driven over `kubectl port-forward`; back-channel logout needs a reachable receiver and
  an https endpoint, so it was only covered by the local end-to-end run.
