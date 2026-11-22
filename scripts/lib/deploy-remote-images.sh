#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
# shellcheck shell=bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

HAVEN_IMAGE_TAG="${HAVEN_IMAGE_TAG:-dev}"

haven_k3s_ctr() {
  if [ -n "${HAVEN_K3S_CTR_CMD:-}" ]; then
    "${HAVEN_K3S_CTR_CMD[@]}" "$@"
    return
  fi
  if [ -x /usr/local/bin/k3s ]; then
    sudo /usr/local/bin/k3s ctr "$@"
  else
    sudo k3s ctr "$@"
  fi
}

haven_detect_k3s_ctr() {
  if [ -x /usr/local/bin/k3s ] && sudo /usr/local/bin/k3s ctr images ls &>/dev/null; then
    HAVEN_K3S_CTR_CMD=(sudo /usr/local/bin/k3s ctr)
  elif command -v k3s &>/dev/null && sudo k3s ctr images ls &>/dev/null; then
    HAVEN_K3S_CTR_CMD=(sudo k3s ctr)
  elif command -v k3s &>/dev/null && k3s ctr images ls &>/dev/null; then
    HAVEN_K3S_CTR_CMD=(k3s ctr)
  else
    return 1
  fi
}

haven_container_cmd() {
  if command -v podman &>/dev/null; then
    echo podman
  elif command -v docker &>/dev/null; then
    echo docker
  else
    return 1
  fi
}

haven_import_image() {
  local tag="$1"
  local ctr="$2"
  local tmp
  echo "  Importing ${tag} into k3s..."
  for ref in "docker.io/library/${tag}" "docker.io/${tag}" "${tag}" "localhost/${tag}"; do
    haven_k3s_ctr images rm "${ref}" 2>/dev/null || true
  done
  tmp=$(mktemp /tmp/haven-img-XXXXXX.tar)
  "$ctr" save -o "$tmp" "$tag"
  haven_k3s_ctr images import "$tmp"
  rm -f "$tmp"
  haven_k3s_ctr images tag "localhost/${tag}" "docker.io/library/${tag}" 2>/dev/null || true
  haven_k3s_ctr images tag "localhost/${tag}" "${tag}" 2>/dev/null || true
}

haven_build_console_image() {
  local ctr
  ctr="$(haven_container_cmd)" || {
    echo "MISSING: podman or docker required"
    return 1
  }
  haven_detect_k3s_ctr || {
    echo "MISSING: k3s ctr required"
    return 1
  }
  local tag="haven-console:${HAVEN_IMAGE_TAG}"
  echo "  Building ${tag} (React + Go)..."
  "$ctr" build -t "$tag" -f Dockerfile.console .
  haven_import_image "$tag" "$ctr"
  echo "  Image ready: ${tag}"
}

haven_build_controller_image() {
  local ctr
  ctr="$(haven_container_cmd)" || {
    echo "MISSING: podman or docker required"
    return 1
  }
  haven_detect_k3s_ctr || {
    echo "MISSING: k3s ctr required"
    return 1
  }
  local tag="haven-controller:${HAVEN_IMAGE_TAG}"
  echo "  Building ${tag}..."
  "$ctr" build -t "$tag" -f Dockerfile.controller .
  haven_import_image "$tag" "$ctr"
  echo "  Image ready: ${tag}"
}

haven_build_web_image() {
  local ctr
  ctr="$(haven_container_cmd)" || {
    echo "MISSING: podman or docker required"
    return 1
  }
  haven_detect_k3s_ctr || {
    echo "MISSING: k3s ctr required"
    return 1
  }
  local tag="haven-web:${HAVEN_IMAGE_TAG}"
  echo "  Building ${tag} from ui/web..."
  "$ctr" build -t "$tag" -f ui/web/Dockerfile ui/web
  haven_import_image "$tag" "$ctr"
  echo "  Image ready: ${tag}"
}
