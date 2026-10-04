#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Install cluster operators Haven composes. Idempotent. Requires cluster-admin.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
if [[ -f "${ROOT}/versions.env" ]]; then
  # shellcheck source=/dev/null
  source "${ROOT}/versions.env"
fi

CNPG_VERSION="${CNPG_VERSION:-1.30.1}"
KEYCLOAK_OPERATOR_REF="${KEYCLOAK_OPERATOR_REF:-26.8.0}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.21.2}"
KEYCLOAK_OPERATOR_NS="${KEYCLOAK_OPERATOR_NS:-keycloak}"

cnpg_minor="${CNPG_VERSION%.*}"

echo "==> CloudNativePG ${CNPG_VERSION}"
kubectl apply --server-side --force-conflicts -f \
  "https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-${cnpg_minor}/releases/cnpg-${CNPG_VERSION}.yaml"

echo "==> Keycloak Operator ${KEYCLOAK_OPERATOR_REF} (namespace ${KEYCLOAK_OPERATOR_NS})"
kubectl create namespace "${KEYCLOAK_OPERATOR_NS}" --dry-run=client -o yaml | kubectl apply -f -
# Upstream kustomization targets namespace "keycloak". Overlay if redirected.
kubectl apply -k "github.com/keycloak/keycloak-k8s-resources/kubernetes?ref=${KEYCLOAK_OPERATOR_REF}"

echo "==> cert-manager ${CERT_MANAGER_VERSION}"
kubectl apply -f \
  "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"

echo "==> Wait for operators"
kubectl -n cnpg-system rollout status deployment/cnpg-controller-manager --timeout=180s
kubectl -n cert-manager rollout status deployment/cert-manager --timeout=180s
kubectl -n cert-manager rollout status deployment/cert-manager-webhook --timeout=180s

# Deployment name is keycloak-operator in current upstream manifests.
if kubectl -n "${KEYCLOAK_OPERATOR_NS}" get deploy keycloak-operator >/dev/null 2>&1; then
  kubectl -n "${KEYCLOAK_OPERATOR_NS}" rollout status deployment/keycloak-operator --timeout=180s
else
  echo "warn: keycloak-operator Deployment not named as expected; listing:"
  kubectl -n "${KEYCLOAK_OPERATOR_NS}" get deploy,pods
fi

echo
echo "Operators ready."
echo "  make crds"
echo "  make dev          # compose path — actually runs Postgres + Keycloak"
echo "  make samples-dev  # intent-only IdentityPlane CR (needs controller)"
