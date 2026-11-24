#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
#
# Build an UNSIGNED, UNNOTARIZED macOS installer package that installs the
# universal (arm64 + x86_64) `haven-idp` and `haven` binaries into /usr/local/bin.
#
#   packaging/macos/build-pkg.sh --version 0.1.0 [--out dist/macos] [--prebuilt DIR]
#
# --prebuilt DIR  use DIR/haven-idp and DIR/haven (already universal, and already
#                 code-signed if you want a notarizable package) instead of
#                 building from source.
#
# This script never signs, notarizes or reads any credential. Signing and
# notarization are separate, deliberate steps: see packaging/macos/README.md.
set -euo pipefail

VERSION=""
OUT="dist/macos"
PREBUILT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version)  VERSION="${2:-}"; shift 2 ;;
    --out)      OUT="${2:-}"; shift 2 ;;
    --prebuilt) PREBUILT="${2:-}"; shift 2 ;;
    -h|--help)  sed -n '4,15p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$VERSION" ] || { echo "--version is required (e.g. 0.1.0)" >&2; exit 2; }
case "$VERSION" in
  *[!0-9A-Za-z.+-]*|"") echo "invalid --version: $VERSION" >&2; exit 2 ;;
esac
[ "$(uname -s)" = "Darwin" ] || { echo "pkgbuild, productbuild and lipo exist only on macOS" >&2; exit 1; }
for tool in pkgbuild productbuild lipo shasum; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/haven-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

STAGE="$WORK/root/usr/local/bin"
mkdir -p "$STAGE"

if [ -n "$PREBUILT" ]; then
  for c in haven-idp haven; do
    [ -x "$PREBUILT/$c" ] || { echo "$PREBUILT/$c is missing or not executable" >&2; exit 1; }
    cp "$PREBUILT/$c" "$STAGE/$c"
  done
else
  cd "$ROOT"
  for c in haven-idp haven; do
    for arch in arm64 amd64; do
      GOOS=darwin GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=$VERSION" -o "$WORK/$c-$arch" "./cmd/$c"
    done
    lipo -create -output "$STAGE/$c" "$WORK/$c-arm64" "$WORK/$c-amd64"
  done
fi
chmod 0755 "$STAGE/haven-idp" "$STAGE/haven"
for c in haven-idp haven; do
  echo "$c: $(lipo -archs "$STAGE/$c")"
done

# Drop extended attributes so the payload carries no AppleDouble (._*) entries.
# (The kernel-managed com.apple.provenance attribute cannot be removed; where
# it is present pkgbuild still records it as a ._ entry, which the installer
# applies as an attribute, not as a file.)
xattr -cr "$WORK/root" 2>/dev/null || true
export COPYFILE_DISABLE=1
COMPONENT="$WORK/haven-component.pkg"
pkgbuild --root "$WORK/root" --identifier dev.zyvor.haven --version "$VERSION" \
  --install-location / --ownership recommended --filter '/\.DS_Store$' "$COMPONENT"

PKG="$OUT/haven-$VERSION-unsigned.pkg"
productbuild --package "$COMPONENT" --identifier dev.zyvor.haven.product --version "$VERSION" "$PKG"

echo
echo "Built (UNSIGNED, not notarized): $PKG"
shasum -a 256 "$PKG"
echo "Next: sign and notarize on the Mac mini, see packaging/macos/README.md"
