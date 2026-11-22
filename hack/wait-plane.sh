#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
# Block until CNPG is ready, then until Keycloak reports ready instances.
set -euo pipefail
NS="${NS:-identity}"
NAME="${NAME:-platform}"
TIMEOUT="${TIMEOUT:-600s}"

echo "waiting for Cluster ${NAME}-db"
kubectl -n "$NS" wait cluster.postgresql.cnpg.io/"${NAME}-db" \
  --for=condition=Ready --timeout="$TIMEOUT"

echo "waiting for Keycloak pods"
# Operator-created pods are labeled app=keycloak
kubectl -n "$NS" wait pod -l app=keycloak --for=condition=Ready --timeout="$TIMEOUT"

echo "plane workloads ready in $NS"
kubectl -n "$NS" get cluster.postgresql.cnpg.io,keycloak,pods
