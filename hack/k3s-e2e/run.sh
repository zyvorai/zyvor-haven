#!/bin/bash
# Ship the current commit to a k3s host over SSH and run a stage there.
#   hack/k3s-e2e/run.sh user@host build|deploy|verify|upgrade|cleanup
# Everything lands in ~/haven-deploy on the host and in the namespaces haven-e2e and
# haven-e2e-system; cleanup removes exactly what deploy recorded. See README.md first.
set -euo pipefail
HOST="${1:?usage: run.sh user@host build|deploy|verify|upgrade|cleanup}"; STAGE="${2:?stage}"
ROOT="$(git rev-parse --show-toplevel)"; HERE="$ROOT/hack/k3s-e2e"
O=(-o BatchMode=yes -o ConnectTimeout=15 -o ControlPath=none)
case "$STAGE" in
  build|deploy|upgrade)
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    git -C "$ROOT" archive --format=tar.gz -o "$TMP/src.tgz" HEAD
    ssh "${O[@]}" "$HOST" 'mkdir -p -m 700 ~/haven-deploy'
    scp "${O[@]}" -q "$TMP/src.tgz" "$HERE"/*.sh "$HERE"/*.py "$HOST:haven-deploy/"
    ssh "${O[@]}" "$HOST" 'cd ~/haven-deploy && rm -rf src && mkdir src && tar xzf src.tgz -C src' ;;
  verify|cleanup) scp "${O[@]}" -q "$HERE"/*.sh "$HERE"/*.py "$HOST:haven-deploy/" ;;
  *) echo "unknown stage $STAGE" >&2; exit 2 ;;
esac
ssh "${O[@]}" "$HOST" "cd ~/haven-deploy && bash $STAGE.sh"
