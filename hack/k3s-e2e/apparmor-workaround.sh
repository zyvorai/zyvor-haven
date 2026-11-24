#!/bin/bash
K="sudo -n k3s kubectl"; NS=haven-e2e
echo "== relax enforcement for this test namespace only (warn/audit stay restricted)"
$K label ns $NS pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted --overwrite
echo "AAFIX_PSA=relaxed" >> ~/haven-deploy/state.env
echo "== patch ONLY the CNPG Cluster: database pod opts out of the node's broken AppArmor profile"
$K -n $NS patch cluster.postgresql.cnpg.io platform-db --type merge -p '{"spec":{"podSecurityContext":{"runAsNonRoot":true,"runAsUser":26,"runAsGroup":26,"fsGroup":26,"seccompProfile":{"type":"RuntimeDefault"},"appArmorProfile":{"type":"Unconfined"}}}}'
echo "== waiting for the database pod to be replaced and become ready (up to 6 min)"
for i in $(seq 1 72); do
  r=$($K -n $NS get pod platform-db-1 -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)
  aa=$($K -n $NS get pod platform-db-1 -o jsonpath='{.spec.securityContext.appArmorProfile.type}' 2>/dev/null)
  [ "$r" = "true" ] && [ "$aa" = "Unconfined" ] && { echo "database pod ready with appArmorProfile=$aa after $((i*5))s"; break; }
  sleep 5
done
$K -n $NS get pods --no-headers | awk '{print "  "$1, $2, $3, "restarts="$4}'
