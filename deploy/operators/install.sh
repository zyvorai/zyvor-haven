#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
# Install cluster operators Haven composes. Idempotent. Requires cluster-admin.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
if [[ -f "${ROOT}/versions.env" ]]; then
  # shellcheck source=/dev/null
  source "${ROOT}/versions.env"
fi

CNPG_VERSION="${CNPG_VERSION:-1.30.2}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.21.3}"

cnpg_minor="${CNPG_VERSION%.*}"

echo "==> CloudNativePG ${CNPG_VERSION}"
kubectl apply --server-side --force-conflicts -f \
  "https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-${cnpg_minor}/releases/cnpg-${CNPG_VERSION}.yaml"

echo "==> cert-manager ${CERT_MANAGER_VERSION}"
kubectl apply -f \
  "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"

echo "==> Wait for operators"
kubectl -n cnpg-system rollout status deployment/cnpg-controller-manager --timeout=180s
kubectl -n cert-manager rollout status deployment/cert-manager --timeout=180s
kubectl -n cert-manager rollout status deployment/cert-manager-webhook --timeout=180s

echo
echo "Operators ready."
echo "  make crds"
echo "  make dev          # compose path: Postgres + haven-idp"
echo "  make samples-dev  # intent-only IdentityPlane CR (needs controller)"
