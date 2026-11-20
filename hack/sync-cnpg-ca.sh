#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
# Copy the CloudNativePG cluster CA into a ConfigMap Keycloak can trust.
# Mirrors https://www.keycloak.org/high-availability/single-cluster/deploy-keycloak
set -euo pipefail
NS="${NS:-identity}"
CLUSTER="${CLUSTER:-platform-db}"
CM="${CM:-platform-db-ca}"

# CNPG names the CA secret <cluster>-ca
CA_B64="$(kubectl -n "$NS" get secret "${CLUSTER}-ca" -o jsonpath='{.data.ca\.crt}' 2>/dev/null || true)"
if [[ -z "$CA_B64" ]]; then
  echo "secret ${CLUSTER}-ca not found in $NS — is the Cluster ready?" >&2
  exit 1
fi

CA_PEM="$(printf '%s' "$CA_B64" | base64 -d)"
kubectl -n "$NS" create configmap "$CM" \
  --from-literal=ca.crt="$CA_PEM" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Updated ConfigMap $NS/$CM from secret ${CLUSTER}-ca"
