#!/usr/bin/env bash
# Build all sandbox runtime profile images.
#
# Each profile Dockerfile lives in its own directory and depends on the shared
# common.sh that sits alongside this script. We copy common.sh into each build
# context on the fly so Docker's COPY only sees the files it needs.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
profiles=(node20 node22 python311 python312 polyglot)

for p in "${profiles[@]}"; do
    ctx="$here/$p"
    cp "$here/common.sh" "$ctx/common.sh"
    echo ">> building mcp-sandbox-$p"
    docker build -t "mcp-sandbox-$p" "$ctx"
    rm "$ctx/common.sh"
done

echo "done. images:"
docker images --filter reference='mcp-sandbox-*'
