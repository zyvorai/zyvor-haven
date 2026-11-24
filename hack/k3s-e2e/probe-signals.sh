#!/bin/bash
K="sudo -n k3s kubectl"; NS=haven-e2e-probe
IMG=ghcr.io/cloudnative-pg/postgresql:16.15
$K get ns $NS >/dev/null 2>&1 && { echo "$NS exists: abort"; exit 1; }
$K create ns $NS >/dev/null
cmd='sleep 300 & p=$!; if kill -WINCH $p 2>/dev/null; then echo "RESULT=signal-allowed"; else echo "RESULT=signal-DENIED"; fi; echo "seccomp_filters=$(grep Seccomp_filters /proc/self/status | cut -f2) apparmor=$(cat /proc/self/attr/current 2>/dev/null | head -1)"; kill -9 $p 2>/dev/null; exit 0'
mk() { # name securityContext-yaml
cat <<Y | $K -n $NS apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: $1}
spec:
  restartPolicy: Never
  $2
  containers:
  - name: t
    image: $IMG
    imagePullPolicy: IfNotPresent
    command: ["sh","-c"]
    args: ['$cmd']
    $3
Y
}
mk a-default "" ""
mk b-cnpg-like 'securityContext: {runAsNonRoot: true, runAsUser: 26, runAsGroup: 26, seccompProfile: {type: RuntimeDefault}}' 'securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}'
mk c-unconfined-seccomp 'securityContext: {runAsNonRoot: true, runAsUser: 26, runAsGroup: 26, seccompProfile: {type: Unconfined}}' 'securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}'
mk d-root-default 'securityContext: {runAsUser: 0}' ""
for p in a-default b-cnpg-like c-unconfined-seccomp d-root-default; do
  for i in $(seq 1 40); do ph=$($K -n $NS get pod $p -o jsonpath='{.status.phase}' 2>/dev/null); [ "$ph" = "Succeeded" ] || [ "$ph" = "Failed" ] && break; sleep 2; done
  echo "== $p ($ph): $($K -n $NS logs $p 2>&1 | tr '\n' ' ' | cut -c1-200)"
done
$K delete ns $NS --wait=true --timeout=60s >/dev/null 2>&1; echo "probe namespace removed: $($K get ns $NS 2>&1 | grep -c NotFound)"
