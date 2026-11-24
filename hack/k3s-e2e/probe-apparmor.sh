#!/bin/bash
K="sudo -n k3s kubectl"; NS=haven-e2e-probe; IMG=ghcr.io/cloudnative-pg/postgresql:16.15
$K get ns $NS >/dev/null 2>&1 && { echo "$NS exists: abort"; exit 1; }
$K create ns $NS >/dev/null
cmd='sleep 300 & p=$!; if kill -WINCH $p 2>/dev/null; then echo "RESULT=signal-allowed"; else echo "RESULT=signal-DENIED"; fi; echo "apparmor=$(cat /proc/self/attr/current 2>/dev/null | head -1)"; kill -9 $p 2>/dev/null; exit 0'
cat <<Y | $K -n $NS apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: aa-unconfined}
spec:
  restartPolicy: Never
  containers:
  - name: t
    image: $IMG
    imagePullPolicy: IfNotPresent
    command: ["sh","-c"]
    args: ['$cmd']
    securityContext: {appArmorProfile: {type: Unconfined}, runAsUser: 26, runAsGroup: 26, runAsNonRoot: true, allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}
---
apiVersion: v1
kind: Pod
metadata: {name: aa-runtimedefault}
spec:
  restartPolicy: Never
  containers:
  - name: t
    image: $IMG
    imagePullPolicy: IfNotPresent
    command: ["sh","-c"]
    args: ['$cmd']
    securityContext: {appArmorProfile: {type: RuntimeDefault}, runAsUser: 26, runAsGroup: 26, runAsNonRoot: true, allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}
Y
for p in aa-unconfined aa-runtimedefault; do
  for i in $(seq 1 40); do ph=$($K -n $NS get pod $p -o jsonpath='{.status.phase}' 2>/dev/null); [ "$ph" = "Succeeded" ] || [ "$ph" = "Failed" ] && break; sleep 2; done
  echo "== $p ($ph): $($K -n $NS logs $p 2>&1 | tr '\n' ' ' | cut -c1-200)"
done
$K delete ns $NS --wait=true --timeout=60s >/dev/null 2>&1; echo "probe namespace removed: $($K get ns $NS 2>&1 | grep -c NotFound)"
echo "--- how can CNPG set security context? (fields on the Cluster spec)"
$K explain cluster.spec 2>/dev/null | grep -iE "^\s+(podSecurityContext|securityContext|seccompProfile|appArmor)" | head -6
$K explain cluster.spec.podSecurityContext 2>/dev/null | grep -iE "appArmor" | head -2
echo "--- host apparmor facts (read-only):"; sudo -n aa-status 2>/dev/null | head -4 || true; cat /sys/module/apparmor/parameters/enabled 2>/dev/null; ls /sys/kernel/security/apparmor/ 2>/dev/null | head -3
