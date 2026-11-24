#!/bin/bash
# Stage C: verify the deployed plane. Runs ON the dev host. Secrets are never printed.
cd ~/haven-deploy || exit 1
NS=haven-e2e
SK="sudo -n k3s kubectl -n $NS"
P=0; F=0
ok() { if [ "$2" = "1" ]; then P=$((P+1)); echo "PASS $1"; else F=$((F+1)); echo "FAIL $1  -> ${3:-}"; fi; }
b() { [ "$1" = "$2" ] && echo 1 || echo 0; }
PFPIDS=()
pf() { # target localport remoteport -> starts a port-forward owned by me; records pid
  k3s kubectl --kubeconfig ~/haven-deploy/kubeconfig -n $NS port-forward "$1" "$2:$3" > pf-$2.log 2>&1 &
  PFPIDS+=($!); for i in $(seq 1 40); do grep -q "Forwarding from" pf-$2.log 2>/dev/null && return 0; sleep 0.25; done; return 1; }
stop_pf() { for p in "${PFPIDS[@]}"; do if /bin/ps -p $p -o args= 2>/dev/null | grep -q "port-forward"; then kill $p 2>/dev/null; fi; done; PFPIDS=(); }
trap stop_pf EXIT
sudo -n cat /etc/rancher/k3s/k3s.yaml > kubeconfig && chmod 600 kubeconfig && echo "KUBECONFIG_COPIED=1" >> state.env

echo "=== A. what is running"
$SK get pods -o wide --no-headers | awk '{print "  "$1, $2, $3, "restarts="$4}'
NOTREADY=$($SK get pods --no-headers | awk '$3!="Running" && $3!="Completed"' | wc -l); ok "every pod in the namespace is Running" $(b $NOTREADY 0) "$NOTREADY not running"
AAT=$($SK get pod platform-db-1 -o jsonpath="{.spec.securityContext.appArmorProfile.type}")
echo "  NOTE: namespace PSA enforce=$(sudo -n k3s kubectl get ns $NS -o jsonpath="{.metadata.labels.pod-security\.kubernetes\.io/enforce}") (relaxed for this host); database pod appArmorProfile=${AAT:-default} (workaround for the host AppArmor signal bug)"
VIOL=$($SK get pods -l app.kubernetes.io/part-of=haven -o name 2>/dev/null | wc -l)
IDPPODS=$($SK get pods --no-headers | grep -c "platform-idp")
ok "two IdP replicas are up" $(b $IDPPODS 2) "$IDPPODS"
IMG=$($SK get deploy platform-idp -o jsonpath='{.spec.template.spec.containers[0].image}'); ok "IdP runs the image we built ($IMG)" $(b "$IMG" "haven-idp:e2e")
CTRL=$(sudo -n k3s kubectl -n haven-e2e-system get deploy haven-controller -o jsonpath='{.spec.template.spec.containers[0].image}'); ok "controller runs the image we built ($CTRL)" $(b "$CTRL" "haven-controller:e2e")
POD=$($SK get pods --no-headers | awk '/platform-idp/{print $1; exit}')
SC=$($SK get pod $POD -o jsonpath='{.spec.securityContext.runAsNonRoot}/{.spec.containers[0].securityContext.allowPrivilegeEscalation}/{.spec.containers[0].securityContext.readOnlyRootFilesystem}/{.spec.containers[0].securityContext.capabilities.drop}')
echo "  live IdP securityContext (runAsNonRoot/allowPrivEsc/readOnlyRootFS/drop): $SC"
ok "IdP pod: non-root, no privilege escalation, read-only root filesystem, capabilities dropped" $(echo "$SC" | grep -q '^true/false/true/\["ALL"\]$' && echo 1 || echo 0) "$SC"
KEYS=$($SK get secret platform-idp -o jsonpath='{.data}' | python3 -c "import sys,json; print(','.join(sorted(json.load(sys.stdin))))")
ok "plane Secret has csrf-key, secret-key, admin-password, admin-client-secret ($KEYS)" $(b "$KEYS" "admin-client-secret,admin-password,csrf-key,secret-key")
ENVREF=$($SK get deploy platform-idp -o jsonpath='{range .spec.template.spec.containers[0].env[?(@.name=="HAVEN_IDP_SECRET_KEY")]}{.valueFrom.secretKeyRef.name}/{.valueFrom.secretKeyRef.key}{end}')
ok "HAVEN_IDP_SECRET_KEY comes from the Secret (never inline)" $(b "$ENVREF" "platform-idp/secret-key") "$ENVREF"
# Profile-aware: dev leaves expose.networkPolicy off by default, staging/prod turn it on.
NPS=$($SK get networkpolicy --no-headers 2>/dev/null | wc -l)
if [ "$($SK get identityplane platform -o jsonpath='{.spec.expose.networkPolicy}')" = "true" ] || [ "$($SK get identityplane platform -o jsonpath='{.spec.profile}')" != "dev" ]; then
  ok "database NetworkPolicy present (expose.networkPolicy on)" $([ "$NPS" -ge 1 ] && echo 1 || echo 0)
else
  echo "  info: dev profile, expose.networkPolicy off by default: $NPS NetworkPolicy object(s)"
fi
ok "PodDisruptionBudget present (2 replicas)" $([ "$($SK get pdb --no-headers 2>/dev/null | wc -l)" -ge 1 ] && echo 1 || echo 0)
CERT=$($SK get certificate --no-headers 2>/dev/null | awk '{print $2}' | head -1); echo "  certificate Ready: ${CERT:-none}"
ok "cert-manager issued the plane TLS certificate (self-signed issuer)" $(b "$CERT" "True") "${CERT:-none}"
ING=$($SK get ingress --no-headers 2>/dev/null | wc -l); echo "  ingress objects: $ING (no ingress controller on this cluster, so not reachable from outside)"

echo "=== B. database (CloudNativePG)"
DBP=$($SK get pods --no-headers | awk '/platform-db-1/{print $1; exit}')
MIG=$($SK exec $DBP -c postgres -- psql -U postgres -d haven_idp -tAc "select string_agg(version::text, ',' order by version) from schema_migrations" 2>&1 | tr -d ' ')
echo "  migrations applied by haven-idp at start-up: $MIG"
ok "all 11 migrations applied in the real CNPG database" $(b "$MIG" "1,2,3,4,5,6,7,8,9,10,11") "$MIG"
NT=$($SK exec $DBP -c postgres -- psql -U postgres -d haven_idp -tAc "select count(*) from information_schema.tables where table_schema='public'" 2>&1 | tr -d ' ')
ok "database holds the 52 tables (51 haven-idp tables + the migration ledger)" $(b "$NT" 52) "$NT"

echo "=== C. interactive flows and features through the deployed service (PostgreSQL-backed)"
pf svc/platform-idp 18401 8081 && echo "  port-forward up" || ok "port-forward to svc/platform-idp" 0 "$(cat pf-18401.log)"
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18401/healthz > h.txt; ok "GET /healthz = 200" $(b "$(cat h.txt)" 200)
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18401/readyz > h.txt; ok "GET /readyz = 200 (database reachable)" $(b "$(cat h.txt)" 200)
python3 -I cluster_flow.py 18401 $NS > flow.out 2>&1; grep -E "^(PASS|FAIL|RESULT)" flow.out | sed 's/^/  /' | head -60
FP=$(grep -c "^PASS" flow.out); FF=$(grep -c "^FAIL" flow.out); P=$((P+FP)); F=$((F+FF))

echo "=== D. OIDCClient controller against the live plane (includes a drift resync wait of up to 7 minutes)"
python3 -I oidcclient_flow.py 18401 $NS > oc.out 2>&1; grep -E "^(PASS|FAIL|RESULT)" oc.out | sed 's/^/  /'
FP=$(grep -c "^PASS" oc.out); FF=$(grep -c "^FAIL" oc.out); P=$((P+FP)); F=$((F+FF))
[ "$FF" != "0" ] && { echo "  --- oidcclient output tail:"; tail -5 oc.out | sed 's/^/  /'; }

echo "=== E. high availability and persistence"
stop_pf
PODS=($($SK get pods --no-headers | awk '/platform-idp/{print $1}'))
pf pod/${PODS[0]} 18411 8081; pf pod/${PODS[1]} 18412 8081
kids() { curl -s "$1/realms/platform/protocol/openid-connect/certs" | python3 -c "import sys,json; print(','.join(sorted(k['kid'] for k in json.load(sys.stdin)['keys'])))"; }
K1=$(kids http://127.0.0.1:18411); K2=$(kids http://127.0.0.1:18412)
ok "both replicas publish the SAME signing keys (shared through the database)" $([ -n "$K1" ] && [ "$K1" = "$K2" ] && echo 1 || echo 0) "$K1 vs $K2"
ASEC=$($SK get secret platform-idp -o jsonpath='{.data.admin-client-secret}' | base64 -d)
TOK=$(curl -s -X POST http://127.0.0.1:18411/realms/platform/protocol/openid-connect/token --data @- <<<"grant_type=client_credentials&client_id=haven-admin&client_secret=$ASEC" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
S2=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOK" http://127.0.0.1:18412/admin/v1/realms)
ok "a token issued by replica 1 is accepted by replica 2 (stateless verification)" $(b "$S2" 200) "$S2"
unset TOK ASEC
stop_pf
$SK delete pod ${PODS[0]} --wait=false >/dev/null
MIN=9; for i in $(seq 1 45); do A=$($SK get deploy platform-idp -o jsonpath='{.status.availableReplicas}'); A=${A:-0}; [ "$A" -lt "$MIN" ] && MIN=$A; sleep 1; done
echo "  minimum available replicas while one pod was killed: $MIN"
ok "service stays available while a replica is killed (at least 1 replica available throughout)" $([ "$MIN" -ge 1 ] && echo 1 || echo 0) "min=$MIN"
$SK rollout status deploy/platform-idp --timeout=180s >/dev/null 2>&1; ok "deployment recovers to 2 ready replicas" $(b "$($SK get deploy platform-idp -o jsonpath='{.status.readyReplicas}')" 2)
pf svc/platform-idp 18401 8081
cat > persist.py <<'PY'
import base64,json,subprocess,sys,urllib.parse,urllib.request
NS=sys.argv[2]; B="http://127.0.0.1:"+sys.argv[1]; R=B+"/realms/platform"
sec=base64.b64decode(subprocess.run(["sudo","-n","k3s","kubectl","-n",NS,"get","secret","platform-idp","-o","jsonpath={.data.admin-client-secret}"],capture_output=True,text=True).stdout).decode()
def post(u,d): return json.loads(urllib.request.urlopen(urllib.request.Request(u,data=urllib.parse.urlencode(d).encode()),timeout=20).read())
tok=post(R+"/protocol/openid-connect/token",{"grant_type":"client_credentials","client_id":"haven-admin","client_secret":sec})["access_token"]
def api(m,p,body=None):
    r=urllib.request.Request(B+"/admin/v1"+p,data=json.dumps(body).encode() if body is not None else None,method=m,headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"})
    try: x=urllib.request.urlopen(r,timeout=20); return x.status,x.read().decode()
    except urllib.error.HTTPError as e: return e.code,e.read().decode()
if sys.argv[3]=="write":
    api("DELETE","/realms/platform/clients/persist-probe"); print(api("POST","/realms/platform/clients",{"clientId":"persist-probe","enabled":True,"publicClient":True})[0])
    print(api("POST","/realms/platform/users",{"username":"persist-user","enabled":True})[0])
else:
    ids=[c["clientId"] for c in json.loads(api("GET","/realms/platform/clients")[1])]; us=json.loads(api("GET","/realms/platform/users?username=persist-user")[1])
    print("client_present=%s user_present=%s"%("persist-probe" in ids,len(us)>0))
    api("DELETE","/realms/platform/clients/persist-probe")
    if us: api("DELETE","/realms/platform/users/"+us[0]["id"])
PY
python3 -I persist.py 18401 $NS write >/dev/null
KB=$(kids http://127.0.0.1:18401)
stop_pf
$SK rollout restart deploy/platform-idp >/dev/null; $SK rollout status deploy/platform-idp --timeout=240s >/dev/null 2>&1
pf svc/platform-idp 18401 8081
KA=$(kids http://127.0.0.1:18401)
ok "signing keys survive a full restart of every replica (stored in PostgreSQL)" $([ -n "$KB" ] && [ "$KB" = "$KA" ] && echo 1 || echo 0) "$KB vs $KA"
PR=$(python3 -I persist.py 18401 $NS read); ok "data written before the restart is still there ($PR)" $(b "$PR" "client_present=True user_present=True")
stop_pf

echo "=== F. secrets hygiene in live logs"
ASEC=$($SK get secret platform-idp -o jsonpath='{.data.admin-client-secret}' | base64 -d); CSRF=$($SK get secret platform-idp -o jsonpath='{.data.csrf-key}' | base64 -d)
SKEY=$($SK get secret platform-idp -o jsonpath='{.data.secret-key}' | base64 -d); APW=$($SK get secret platform-idp -o jsonpath='{.data.admin-password}' | base64 -d)
DBPW=$($SK get secret platform-idp-db -o jsonpath='{.data.password}' | base64 -d)
LEAK=0; for pod in $($SK get pods --no-headers | awk '/platform-idp/{print $1}') ; do
  L=$($SK logs $pod 2>/dev/null); for v in "$ASEC" "$CSRF" "$SKEY" "$APW" "$DBPW"; do [ -n "$v" ] && echo "$L" | grep -qF -- "$v" && LEAK=$((LEAK+1)); done
  echo "$L" | grep -qiE "token=|logout_token=|id_token=" && LEAK=$((LEAK+1))
done
CL=$(sudo -n k3s kubectl -n haven-e2e-system logs deploy/haven-controller 2>/dev/null); for v in "$ASEC" "$CSRF" "$SKEY" "$APW" "$DBPW"; do [ -n "$v" ] && echo "$CL" | grep -qF -- "$v" && LEAK=$((LEAK+1)); done
ok "no secret or token value appears in any IdP or controller log" $(b $LEAK 0) "$LEAK leak(s)"
unset ASEC CSRF SKEY APW DBPW
echo "  IdP log sample (last lines):"; $SK logs $($SK get pods --no-headers | awk '/platform-idp/{print $1; exit}') 2>/dev/null | tail -4 | cut -c1-150 | sed 's/^/    /'

rm -f kubeconfig
echo; echo "SUMMARY pass=$P fail=$F"
