#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
#
# Render the Homebrew formula for a release.
#
#   packaging/homebrew/render-formula.sh VERSION TARBALL > Formula/haven.rb
#
# TARBALL is the GitHub source archive of tag vVERSION that you downloaded
# (https://github.com/zyvorai/haven/archive/refs/tags/vVERSION.tar.gz); its
# SHA-256 is computed here, locally. Nothing is downloaded or published.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 VERSION TARBALL" >&2; exit 2; }
VERSION="$1"
TARBALL="$2"
case "$VERSION" in
  *[!0-9A-Za-z.+-]*|"") echo "invalid VERSION: $VERSION" >&2; exit 2 ;;
esac
[ -f "$TARBALL" ] || { echo "no such file: $TARBALL" >&2; exit 1; }

if command -v shasum >/dev/null; then
  SUM="$(shasum -a 256 "$TARBALL" | cut -d' ' -f1)"
else
  SUM="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
fi

TMPL="$(cd "$(dirname "$0")" && pwd)/haven.rb.tmpl"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@SHA256@/$SUM/g" "$TMPL"
