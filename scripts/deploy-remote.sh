#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
# Deploy Haven console (Go API + React UI) to a remote k3s host via NodePort.
#
# Usage (from repo root):
#   ./scripts/deploy-remote.sh <host> [user]
#   ./scripts/deploy-remote.sh <ephemeral-ip> operator
#   ./scripts/deploy-remote.sh <ephemeral-ip> operator --quick
#   ./scripts/deploy-remote.sh <ephemeral-ip> operator --uninstall
#
# Docs: docs/lab-host.md · docs/cli.md
#
# Environment:
#   HAVEN_NODE_PORT       default 30742
#   HAVEN_IMAGE_TAG       default dev
#   KEYCLOAK_NODE_PORT    default 30180 (existing Keycloak on host)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/deploy-remote-ui.sh
source "${SCRIPT_DIR}/lib/deploy-remote-ui.sh"

QUICK_MODE=false
UNINSTALL_MODE=false
SKIP_SYNC=false
POSITIONAL=()
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK_MODE=true ;;
    --skip-sync) SKIP_SYNC=true ;;
    --uninstall) UNINSTALL_MODE=true ;;
    --help|-h)
      sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done

HOST="${POSITIONAL[0]:-${DEPLOY_HOST:-}}"
USER="${POSITIONAL[1]:-${DEPLOY_USER:-sus}}"

[ -n "$HOST" ] || error "Usage: $0 <host> [user] [--quick|--uninstall]"

DEPLOYMENTS_SUBDIR="${DEPLOYMENTS_SUBDIR:-.deployment}"
HAVEN_CHECKOUT="${HAVEN_CHECKOUT:-haven}"
HAVEN_IMAGE_TAG="${HAVEN_IMAGE_TAG:-dev}"
NODE_PORT="${HAVEN_NODE_PORT:-30742}"
KEYCLOAK_PORT="${KEYCLOAK_NODE_PORT:-30180}"

REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REMOTE_DIR="\$HOME/${DEPLOYMENTS_SUBDIR}/${HAVEN_CHECKOUT}"
RSYNC_DEST="${USER}@${HOST}:${DEPLOYMENTS_SUBDIR}/${HAVEN_CHECKOUT}/"
REMOTE_SH_PREFIX="cd \"${REMOTE_DIR}\""

_SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ServerAliveCountMax=6"
_KUBECONFIG_PREFIX='if [ -r "$HOME/.kube/config" ]; then export KUBECONFIG="$HOME/.kube/config"; fi;'

_ssh() {
  ssh ${_SSH_OPTS} "${USER}@${HOST}" "$_KUBECONFIG_PREFIX" "$@"
}

_rsync() {
  rsync -az --delete \
    -e "ssh ${_SSH_OPTS}" \
    --exclude '.git/' \
    --exclude 'ui/web/node_modules/' \
    --exclude 'ui/web/dist/' \
    --exclude 'cmd/haven-console/dist/' \
    --exclude 'bin/' \
    "$@"
}

axiom_ui_set_total 7
axiom_ui_banner "Haven Console Remote Deploy" "${USER}@${HOST}"
axiom_ui_kv "Checkout" "${DEPLOYMENTS_SUBDIR}/${HAVEN_CHECKOUT}"
axiom_ui_kv "UI" "http://${HOST}:${NODE_PORT}"
axiom_ui_kv "Keycloak" "http://${HOST}:${KEYCLOAK_PORT}"
axiom_ui_kv "NodePort" "${NODE_PORT}"

if $UNINSTALL_MODE; then
  step 1 2 "Remove Haven console"
  _ssh "${REMOTE_SH_PREFIX}; kubectl delete -f deploy/k8s/ui/deployment.yaml --ignore-not-found; podman rm -f haven-console 2>/dev/null || true" || true
  info "Haven console removed"
  axiom_ui_success "$HOST" "$USER"
  exit 0
fi

step 1 7 "SSH preflight"
_ssh 'command -v kubectl >/dev/null' || error "kubectl not found on ${HOST}"
info "kubectl OK"

step 2 7 "Rsync source → remote"
if $SKIP_SYNC; then
  warn "Skipping rsync"
else
  _ssh "mkdir -p \"\$HOME/${DEPLOYMENTS_SUBDIR}/${HAVEN_CHECKOUT}\""
  _rsync "${REPO_DIR}/" "${RSYNC_DEST}"
  info "Synced"
fi

step 3 7 "Sync Keycloak admin credentials"
_ssh 'kubectl create namespace haven-ui --dry-run=client -o yaml | kubectl apply -f -' >/dev/null
KC_PASS=$(_ssh 'export KUBECONFIG=$HOME/.kube/config; \
  pw=$(kubectl get deploy keycloak -n argus-enterprise -o jsonpath="{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{\"\\n\"}{end}" 2>/dev/null | sed -n "s/^KEYCLOAK_ADMIN_PASSWORD=//p" | head -1); \
  if [ -n "$pw" ]; then echo "$pw"; exit 0; fi; \
  kubectl get secret argus-keycloak-admin -n argus-enterprise -o jsonpath="{.data.password}" 2>/dev/null | base64 -d' || true)
if [ -n "$KC_PASS" ]; then
  _ssh "kubectl -n haven-ui create secret generic haven-keycloak-admin \\
  --from-literal=KEYCLOAK_URL=http://${HOST}:${KEYCLOAK_PORT} \\
  --from-literal=KEYCLOAK_ADMIN_USER=admin \\
  --from-literal=KEYCLOAK_ADMIN_PASSWORD='${KC_PASS}' \\
  --dry-run=client -o yaml | kubectl apply -f -"
  info "Keycloak credentials synced to haven-keycloak-admin"
else
  warn "No Argus Keycloak secret — using lab defaults (admin/changeme on :${KEYCLOAK_PORT})"
  _ssh "kubectl -n haven-ui create secret generic haven-keycloak-admin \\
  --from-literal=KEYCLOAK_URL=http://${HOST}:${KEYCLOAK_PORT} \\
  --from-literal=KEYCLOAK_ADMIN_USER=admin \\
  --from-literal=KEYCLOAK_ADMIN_PASSWORD='changeme' \\
  --dry-run=client -o yaml | kubectl apply -f -"
fi

step 4 7 "Build + import haven-console image"
if $QUICK_MODE; then
  warn "Skipping image build (--quick)"
else
  _ssh "export HAVEN_IMAGE_TAG='${HAVEN_IMAGE_TAG}'; ${REMOTE_SH_PREFIX}; . scripts/lib/deploy-remote-images.sh; haven_build_console_image; haven_build_controller_image"
  info "Image built"
fi

step 5 7 "Apply Kubernetes manifests (NodePort ${NODE_PORT})"
K8S_RESULT=$(_ssh "export HAVEN_HOST='${HOST}'; export HAVEN_NODE_PORT='${NODE_PORT}'; export KEYCLOAK_PORT='${KEYCLOAK_PORT}'; ${REMOTE_SH_PREFIX}; \
python3 - <<'PY'
from pathlib import Path
import os, re

host = os.environ['HAVEN_HOST']
node_port = os.environ['HAVEN_NODE_PORT']
kc_port = os.environ['KEYCLOAK_PORT']

p = Path('deploy/k8s/ui/deployment.yaml')
text = p.read_text()
text = re.sub(r'nodePort: [0-9]+', f'nodePort: {node_port}', text)
text = text.replace('KEYCLOAK_HOST', host)
p.write_text(text)
print(f'nodePort -> {node_port}')
print(f'keycloak -> http://{host}:{kc_port}')
PY
kubectl create namespace haven-ui --dry-run=client -o yaml | kubectl apply -f -
kubectl -n haven-ui delete deploy/haven-web svc/haven-web-nodeport --ignore-not-found 2>/dev/null || true
kubectl apply -f deploy/k8s/ui/rbac.yaml
kubectl apply -f deploy/k8s/ui/deployment.yaml
kubectl apply -f config/crd/haven.identity_identityplanes.yaml 2>/dev/null || true
kubectl apply -f deploy/k8s/controller/deployment.yaml 2>/dev/null || true
kubectl apply -f config/samples/identityplane-dev.yaml 2>/dev/null || true
if [ -n '${KC_PASS}' ]; then
  kubectl -n haven-ui create secret generic haven-keycloak-admin \\
    --from-literal=KEYCLOAK_URL=http://${HOST}:${KEYCLOAK_PORT} \\
    --from-literal=KEYCLOAK_ADMIN_USER=admin \\
    --from-literal=KEYCLOAK_ADMIN_PASSWORD='${KC_PASS}' \\
    --dry-run=client -o yaml | kubectl apply -f -
else
  kubectl -n haven-ui create secret generic haven-keycloak-admin \\
    --from-literal=KEYCLOAK_URL=http://${HOST}:${KEYCLOAK_PORT} \\
    --from-literal=KEYCLOAK_ADMIN_USER=admin \\
    --from-literal=KEYCLOAK_ADMIN_PASSWORD='changeme' \\
    --dry-run=client -o yaml | kubectl apply -f -
fi
if kubectl -n haven-ui rollout status deploy/haven-console --timeout=180s 2>/dev/null; then
  kubectl -n haven-ui rollout restart deploy/haven-console >/dev/null 2>&1 || true
  kubectl -n haven-ui rollout status deploy/haven-console --timeout=180s 2>/dev/null || true
  echo K8S_OK
else
  echo K8S_ROLLOUT_FAILED
fi" | tail -1)
info "Manifests applied (${K8S_RESULT})"

step 6 7 "Verify HTTP (+ podman fallback if CNI broken)"

_ssh "sudo ufw allow ${NODE_PORT}/tcp comment haven-console 2>/dev/null || true" || true

if [ "$K8S_RESULT" = "K8S_ROLLOUT_FAILED" ]; then
  warn "K8s rollout failed (CNI?) — starting podman host container on :${NODE_PORT}"
  _ssh "mkdir -p \"\$HOME/${DEPLOYMENTS_SUBDIR}/${HAVEN_CHECKOUT}/.run\"
podman rm -f haven-console 2>/dev/null || true
podman run -d --name haven-console -p ${NODE_PORT}:8080 \\
  -e KEYCLOAK_URL=http://${HOST}:${KEYCLOAK_PORT} \\
  -e KEYCLOAK_ADMIN_USER=admin \\
  -e KEYCLOAK_ADMIN_PASSWORD='${KC_PASS:-changeme}' \\
  -e HAVEN_BOOTSTRAP_REALM=platform \\
  -e HAVEN_LAB_LOGIN=1 \\
  localhost/haven-console:${HAVEN_IMAGE_TAG}"
  info "Podman fallback running"
fi

sleep 3
UI_URL="http://${HOST}:${NODE_PORT}"
if curl -fsS --connect-timeout 10 "${UI_URL}/api/v1/health" >/dev/null; then
  info "API OK: ${UI_URL}/api/v1/health"
elif curl -fsS --connect-timeout 10 "${UI_URL}/" >/dev/null; then
  info "UI OK: ${UI_URL}"
else
  warn "Health check failed"
  _ssh 'kubectl -n haven-ui get pods,svc -o wide 2>/dev/null; podman ps -a | grep haven' || true
fi

step 7 7 "Done" "$HOST" "$USER"
axiom_ui_panel "Access" \
  "Landing:       ${UI_URL}/" \
  "Command Deck:  ${UI_URL}/deck" \
  "Realm Studio:  ${UI_URL}/realms" \
  "Clients:       ${UI_URL}/clients" \
  "API health:    ${UI_URL}/api/v1/health" \
  "" \
  "Redeploy:      ./scripts/deploy-remote.sh ${HOST} ${USER} --quick"
info "Identity ops run through Haven — Keycloak admin is Settings → Advanced only"
