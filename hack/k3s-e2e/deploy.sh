#!/bin/bash
# Stage B: install CNPG, our CRDs, the controller and a plane on the k3s cluster.
# Everything lives in haven-e2e / haven-e2e-system; state.env records what was created so cleanup is exact.
cd ~/haven-deploy || exit 1
K="sudo -n k3s kubectl"
NS=haven-e2e; SYS=haven-e2e-system
CNPG_VER=1.30.2; CNPG_MINOR=1.30
CRDS="identityplanes.identity.haven.dev oidcclients.identity.haven.dev"
: > state.env
say() { echo "[$(date -u +%T)] $*"; }
fail() { say "FAILED: $*"; diag; exit 1; }
diag() {
  echo "---- diagnostics"; $K get pods -A --no-headers 2>/dev/null | grep -E "haven-e2e|cnpg" | head -20
  $K -n $NS get events --sort-by=.lastTimestamp 2>/dev/null | tail -15
  $K -n $NS get identityplane platform -o jsonpath='{.status}' 2>/dev/null | head -c 1500; echo
}

say "== preflight: nothing of ours may exist yet"
for c in $CRDS clusters.postgresql.cnpg.io; do $K get crd $c >/dev/null 2>&1 && fail "CRD $c already exists (not mine)"; done
for n in $NS $SYS cnpg-system; do $K get ns $n >/dev/null 2>&1 && fail "namespace $n already exists (not mine)"; done
$K -n kube-system get pods --no-headers 2>/dev/null | head -0
say "preflight ok. load=$(cut -d' ' -f1 /proc/loadavg)"

say "== 0. images present and pinned in k3s containerd (kubelet GC removes unused ones on this host)"
for i in haven-idp haven-controller; do
  sudo -n k3s ctr -n k8s.io images ls -q | grep -q "docker.io/library/$i:e2e" || { sudo -n docker save $i:e2e | sudo -n k3s ctr -n k8s.io images import - >/dev/null 2>&1; }
  sudo -n k3s ctr -n k8s.io images label docker.io/library/$i:e2e io.cri-containerd.pinned=pinned >/dev/null 2>&1
  sudo -n k3s ctr -n k8s.io images ls | grep "docker.io/library/$i:e2e" | grep -q pinned && say "  $i:e2e present and pinned" || fail "image $i:e2e missing or not pinned"
done

say "== 1. CloudNativePG $CNPG_VER (cluster-wide operator in cnpg-system)"
URL="https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-$CNPG_MINOR/releases/cnpg-$CNPG_VER.yaml"
curl -fsSL -m 60 "$URL" -o cnpg.yaml || fail "cannot download $URL"
echo "CNPG_INSTALLED=1" >> state.env
$K apply --server-side --force-conflicts -f cnpg.yaml > cnpg-apply.log 2>&1 || { tail -5 cnpg-apply.log; fail "cnpg apply"; }
$K -n cnpg-system rollout status deployment/cnpg-controller-manager --timeout=300s || fail "cnpg operator not ready"

say "== 2. our CRDs"
echo "CRDS_INSTALLED=1" >> state.env
$K apply -f src/config/crd/haven.identity_identityplanes.yaml >/dev/null || fail "crd apply"
for c in $CRDS; do $K wait --for=condition=Established crd/$c --timeout=60s >/dev/null || fail "crd $c"; done

say "== 3. namespaces enforcing Pod Security 'restricted' (the strictest level)"
echo "NAMESPACES=1" >> state.env
for n in $SYS $NS; do
  $K create ns $n >/dev/null && $K label ns $n pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest haven.identity/e2e=true >/dev/null
done

say "== 4. controller (RBAC + Deployment from deploy/k8s/controller, image haven-controller:e2e)"
echo "CONTROLLER=1" >> state.env
sed -e "s/haven-system/$SYS/g" -e 's#haven-controller:dev#haven-controller:e2e#' src/deploy/k8s/controller/deployment.yaml > controller.yaml
$K apply -f controller.yaml > controller-apply.log 2>&1 || { cat controller-apply.log | head; fail "controller apply"; }
$K -n $SYS set env deployment/haven-controller HAVEN_IDP_IMAGE=haven-idp:e2e >/dev/null
$K -n $SYS rollout status deployment/haven-controller --timeout=180s || fail "controller not ready"

say "== 5. self-signed Issuer for the plane TLS certificate (cert-manager, namespaced)"
cat > issuer.yaml <<Y
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: {name: selfsigned, namespace: $NS}
spec: {selfSigned: {}}
Y
$K apply -f issuer.yaml >/dev/null || fail "issuer"

say "== 6. IdentityPlane (native engine, 2 IdP replicas, CNPG database)"
cat > plane.yaml <<Y
apiVersion: identity.haven.dev/v1alpha1
kind: IdentityPlane
metadata: {name: platform, namespace: $NS}
spec:
  engine: native
  profile: dev
  hostname: auth.e2e.haven.test
  database: {vendor: postgres, instances: 1, storage: 2Gi, storageClass: local-path}
  idp: {replicas: 2}
  expose:
    class: ingress
    tls: {issuerRef: {kind: Issuer, name: selfsigned}}
  bootstrap: {firstRealm: platform}
Y
$K apply -f plane.yaml || fail "plane apply"

say "== 7. waiting for the plane to become Ready (up to 12 min)"
last=""
for i in $(seq 1 72); do
  ph=$($K -n $NS get identityplane platform -o jsonpath='{.status.phase}' 2>/dev/null)
  [ "$ph" != "$last" ] && { say "phase: ${ph:-<none>}"; last="$ph"; }
  [ "$ph" = "Ready" ] && break
  [ "$ph" = "Degraded" ] && { sleep 10; ph2=$($K -n $NS get identityplane platform -o jsonpath='{.status.phase}'); [ "$ph2" = "Degraded" ] && fail "plane Degraded"; }
  sleep 10
done
[ "$ph" = "Ready" ] || fail "plane did not become Ready (last phase: ${ph:-none})"
say "== plane Ready"
$K -n $NS get pods,svc,pdb,networkpolicy,certificate,ingress 2>&1 | head -30
say "== deploy done"
