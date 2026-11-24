#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
# Generate the secrets the prod overlay expects for the native haven-idp engine:
#   platform-db-app   basic-auth haven_idp + password        (CNPG bootstrap, name unchanged)
#   platform-idp-db   username, password, dsn                (read by haven-idp)
#   platform-idp      csrf-key, secret-key, admin-password, admin-client-secret
# Contract: internal/render/IDP_CONTRACT.md.
#
# Safety: never prints a secret value, never overwrites (exits if any target exists),
# keeps values in 0600 files inside a 0700 temp dir (never in argv), removes them on exit.
# Set KEEP_DIR=/path to keep the 0600 files for your secret manager (the dir must not exist).
set -euo pipefail
umask 077

NS="${NS:-identity}"
PLANE="${PLANE:-platform}"
DB_HOST="${DB_HOST:-${PLANE}-db-rw.${NS}.svc}"
DB_NAME="haven_idp"

names=("${PLANE}-db-app" "${PLANE}-idp-db" "${PLANE}-idp")

kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null

for n in "${names[@]}"; do
  if kubectl -n "$NS" get secret "$n" >/dev/null 2>&1; then
    echo "refusing to overwrite: secret $n already exists in $NS (delete it deliberately to rotate)" >&2
    exit 1
  fi
done

if [[ -n "${KEEP_DIR:-}" ]]; then
  mkdir -m 0700 "$KEEP_DIR"   # fails if it exists: no overwrite
  WORK="$KEEP_DIR"
else
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
fi

rand() {
  python3 -c 'import secrets,sys; sys.stdout.write(secrets.token_urlsafe(32))'
}

# Write VALUE (no trailing newline) to $WORK/NAME with mode 0600.
put() { printf '%s' "$2" >"$WORK/$1"; chmod 0600 "$WORK/$1"; }

DBPASS="$(rand)"
put db-username "$DB_NAME"
put db-password "$DBPASS"
put db-dsn "postgres://${DB_NAME}:${DBPASS}@${DB_HOST}:5432/${DB_NAME}?sslmode=require"
put csrf-key "$(rand)"
put secret-key "$(rand)"   # HAVEN_IDP_SECRET_KEY: encrypts TOTP seeds and upstream IdP secrets; back it up, losing it loses those
put admin-password "$(rand)"
put admin-client-secret "$(rand)"
unset DBPASS

kubectl -n "$NS" create secret generic "${PLANE}-db-app" \
  --type=kubernetes.io/basic-auth \
  --from-file=username="$WORK/db-username" \
  --from-file=password="$WORK/db-password"

kubectl -n "$NS" create secret generic "${PLANE}-idp-db" \
  --from-file=username="$WORK/db-username" \
  --from-file=password="$WORK/db-password" \
  --from-file=dsn="$WORK/db-dsn"

kubectl -n "$NS" create secret generic "${PLANE}-idp" \
  --from-file=csrf-key="$WORK/csrf-key" \
  --from-file=secret-key="$WORK/secret-key" \
  --from-file=admin-password="$WORK/admin-password" \
  --from-file=admin-client-secret="$WORK/admin-client-secret"

kubectl -n "$NS" label secret "${PLANE}-db-app" cnpg.io/reload=true --overwrite >/dev/null
kubectl -n "$NS" label secret "${names[@]}" \
  haven.identity/plane="$PLANE" app.kubernetes.io/part-of=haven --overwrite >/dev/null

echo "Created ${names[*]} in $NS (values not echoed)."
if [[ -n "${KEEP_DIR:-}" ]]; then
  echo "Kept 0600 files in $KEEP_DIR; store them in your secret manager, then delete the directory."
fi
echo "Read the admin password: haven admin ${PLANE} -n ${NS}"
