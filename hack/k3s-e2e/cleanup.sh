#!/bin/bash
# Removes exactly what remote_deploy.sh created (recorded in state.env). Safe to re-run.
cd ~/haven-deploy 2>/dev/null || { echo "~/haven-deploy not found: nothing to clean"; exit 0; }
K="sudo -n k3s kubectl"
NS=haven-e2e; SYS=haven-e2e-system
CRDS="identityplanes.identity.haven.dev realmbundles.identity.haven.dev oidcclients.identity.haven.dev"
say() { echo "[$(date -u +%T)] $*"; }
has() { grep -q "^$1=1" state.env 2>/dev/null; }

if has NAMESPACES || $K get ns $NS >/dev/null 2>&1; then
  say "deleting the plane first so its finalizers can remove the database and secrets"
  $K -n $NS delete identityplane platform --wait=true --timeout=180s 2>&1 | sed 's/^/  /'
  $K -n $NS delete oidcclient --all --wait=true --timeout=60s 2>&1 | sed 's/^/  /'
fi
if $K get ns $SYS >/dev/null 2>&1; then say "removing the controller"; $K delete -f controller.yaml --wait=true --timeout=120s 2>&1 | sed 's/^/  /' | tail -8; fi
for n in $NS $SYS; do $K get ns $n >/dev/null 2>&1 && { say "deleting namespace $n"; $K delete ns $n --wait=true --timeout=240s 2>&1 | sed 's/^/  /'; }; done
if has CRDS_INSTALLED; then say "deleting our CRDs"; for c in $CRDS; do $K delete crd $c --wait=true --timeout=90s 2>&1 | sed 's/^/  /'; done; fi
# local-path volumes released by the deleted claims
for pv in $($K get pv --no-headers 2>/dev/null | awk -v ns="$NS" '$6 ~ ns"/" {print $1}'); do say "deleting leftover volume $pv"; $K delete pv $pv --wait=false 2>&1 | sed 's/^/  /'; done
if has CNPG_INSTALLED; then say "removing the CloudNativePG operator we installed"; $K delete -f cnpg.yaml --wait=true --timeout=180s 2>&1 | tail -3 | sed 's/^/  /'; fi
say "removing images we built"
sudo -n k3s ctr -n k8s.io images rm docker.io/library/haven-idp:e2e docker.io/library/haven-controller:e2e 2>&1 | sed 's/^/  /'
sudo -n docker rmi haven-idp:e2e haven-controller:e2e 2>&1 | sed 's/^/  /'
echo "--- verify"
echo "haven CRDs left: $($K get crd --no-headers 2>/dev/null | grep -c 'identity.haven.dev')"
echo "cnpg CRDs left: $($K get crd --no-headers 2>/dev/null | grep -c 'cnpg.io')"
echo "namespaces: $($K get ns --no-headers 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
echo "haven clusterroles left: $($K get clusterrole,clusterrolebinding --no-headers 2>/dev/null | grep -c haven-controller)"
echo "pods outside kube-system still running: $($K get pods -A --no-headers 2>/dev/null | grep -vc kube-system)"
cd ~ && rm -rf ~/haven-deploy && echo "removed ~/haven-deploy"
