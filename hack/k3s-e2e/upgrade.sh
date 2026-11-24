#!/bin/bash
# Upgrade the running plane to a new haven-idp image and prove the data migration + token continuity.
cd ~/haven-deploy || exit 1
K="sudo -n k3s kubectl -n haven-e2e"
say() { echo "[$(date -u +%T)] $*"; }
say "== before: signing keys in the live database"
$K exec platform-db-1 -c postgres -- psql -U postgres -d haven_idp -tAc "select kid, active from signing_keys order by created_at" 2>&1 | sed 's/^/  /'
say "   migrations: $($K exec platform-db-1 -c postgres -- psql -U postgres -d haven_idp -tAc "select max(version) from schema_migrations" 2>&1 | tr -d ' ')"
say "== capture a token signed BEFORE the upgrade (kept only in this process memory/file mode 600)"
sudo -n cat /etc/rancher/k3s/k3s.yaml > kubeconfig; chmod 600 kubeconfig
k3s kubectl --kubeconfig kubeconfig -n haven-e2e port-forward svc/platform-idp 18403:8081 > pf3.log 2>&1 & PF=$!
for i in $(seq 1 40); do grep -q Forwarding pf3.log 2>/dev/null && break; sleep 0.25; done
ASEC=$($K get secret platform-idp -o jsonpath='{.data.admin-client-secret}' | base64 -d)
( umask 077; curl -s -X POST http://127.0.0.1:18403/realms/platform/protocol/openid-connect/token --data @- <<<"grant_type=client_credentials&client_id=haven-admin&client_secret=$ASEC" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" > oldtoken.txt )
unset ASEC
say "   old token captured: $(wc -c < oldtoken.txt) bytes; works now: $(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(cat oldtoken.txt)" http://127.0.0.1:18403/admin/v1/realms)"
kill $PF 2>/dev/null

say "== build the new image from the fixed source"
rm -rf src && mkdir src && tar xzf src2.tgz -C src 2>/dev/null
( cd src && sudo -n docker build -q -f Dockerfile.idp -t haven-idp:e2e . ) 2>&1 | grep -v "DEPRECATED\|buildx\|docs.docker" | tail -1
sudo -n docker save haven-idp:e2e | sudo -n k3s ctr -n k8s.io images import - 2>&1 | tail -1
sudo -n k3s ctr -n k8s.io images label docker.io/library/haven-idp:e2e io.cri-containerd.pinned=pinned >/dev/null 2>&1
say "== roll out (both replicas restart together, exactly the situation that caused the race)"
$K rollout restart deploy/platform-idp >/dev/null
$K rollout status deploy/platform-idp --timeout=240s 2>&1 | tail -1
say "== after"
$K exec platform-db-1 -c postgres -- psql -U postgres -d haven_idp -tAc "select kid, active from signing_keys order by created_at" 2>&1 | sed 's/^/  /'
say "   migrations: $($K exec platform-db-1 -c postgres -- psql -U postgres -d haven_idp -tAc "select string_agg(version::text, ',' order by version) from schema_migrations" 2>&1 | tr -d ' ')"
say "   active keys: $($K exec platform-db-1 -c postgres -- psql -U postgres -d haven_idp -tAc "select count(*) from signing_keys where realm='platform' and active" 2>&1 | tr -d ' ')   unique index present: $($K exec platform-db-1 -c postgres -- psql -U postgres -d haven_idp -tAc "select count(*) from pg_indexes where indexname='signing_keys_one_active'" 2>&1 | tr -d ' ')"
k3s kubectl --kubeconfig kubeconfig -n haven-e2e port-forward svc/platform-idp 18403:8081 > pf3.log 2>&1 & PF=$!
for i in $(seq 1 40); do grep -q Forwarding pf3.log 2>/dev/null && break; sleep 0.25; done
say "   JWKS still publishes: $(curl -s http://127.0.0.1:18403/realms/platform/protocol/openid-connect/certs | python3 -c "import sys,json; print(len(json.load(sys.stdin)['keys']))") key(s)"
say "   token signed BEFORE the upgrade still accepted: HTTP $(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(cat oldtoken.txt)" http://127.0.0.1:18403/admin/v1/realms)"
kill $PF 2>/dev/null; rm -f oldtoken.txt kubeconfig
say "== upgrade done"
