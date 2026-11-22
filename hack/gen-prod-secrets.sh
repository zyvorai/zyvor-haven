#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
# Generate matching CNPG + Keycloak DB secrets. Does not print the password.
set -euo pipefail
NS="${NS:-identity}"
PASS="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NS" create secret generic platform-db-app \
  --type=kubernetes.io/basic-auth \
  --from-literal=username=keycloak \
  --from-literal=password="$PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NS" create secret generic platform-keycloak-db \
  --from-literal=username=keycloak \
  --from-literal=password="$PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NS" label secret platform-db-app platform-keycloak-db \
  cnpg.io/reload=true haven.identity/plane=platform --overwrite

echo "Wrote platform-db-app and platform-keycloak-db in $NS (password not echoed)."
