#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
# Block until CNPG is ready, then until the identity server (haven-idp, or deprecated Keycloak) is ready.
set -euo pipefail
NS="${NS:-identity}"
NAME="${NAME:-platform}"
TIMEOUT="${TIMEOUT:-600s}"

echo "waiting for Cluster ${NAME}-db"
kubectl -n "$NS" wait cluster.postgresql.cnpg.io/"${NAME}-db" \
  --for=condition=Ready --timeout="$TIMEOUT"

if kubectl -n "$NS" get deployment "${NAME}-idp" >/dev/null 2>&1 \
  || kubectl -n "$NS" get identityplane "$NAME" -o jsonpath='{.status.conditions[*].type}' 2>/dev/null | grep -q IdentityProviderReady; then
  echo "waiting for haven-idp (condition IdentityProviderReady, Deployment ${NAME}-idp)"
  if kubectl -n "$NS" get identityplane "$NAME" >/dev/null 2>&1; then
    kubectl -n "$NS" wait identityplane/"$NAME" --for=condition=IdentityProviderReady --timeout="$TIMEOUT"
  fi
  kubectl -n "$NS" rollout status deployment/"${NAME}-idp" --timeout="$TIMEOUT"
  issuer="$(kubectl -n "$NS" get identityplane "$NAME" -o jsonpath='{.status.endpoints.issuer}' 2>/dev/null || true)"
  [[ -z "$issuer" ]] || echo "issuer: $issuer"
  echo "plane workloads ready in $NS"
  kubectl -n "$NS" get cluster.postgresql.cnpg.io,deployment,pods -l 'app.kubernetes.io/part-of=haven' 2>/dev/null || true
else
  # DEPRECATED Keycloak engine. Operator-created pods are labeled app=keycloak.
  echo "waiting for Keycloak pods (deprecated engine)"
  kubectl -n "$NS" wait pod -l app=keycloak --for=condition=Ready --timeout="$TIMEOUT"
  echo "plane workloads ready in $NS"
  kubectl -n "$NS" get cluster.postgresql.cnpg.io,keycloak,pods
fi
