#!/bin/sh
# Shared apt install step for all profile images. Sourced into each Dockerfile
# via `COPY common.sh` + `RUN sh /common.sh`. Kept tiny so every profile stays
# close to the upstream runtime image.
set -eu

apt-get update
apt-get install -y --no-install-recommends \
    strace \
    inotify-tools \
    curl \
    ca-certificates \
    procps \
    iproute2
rm -rf /var/lib/apt/lists/*

# Non-root analysis user. UID/GID 1000 matches typical host user on Linux; on
# macOS/Windows Docker Desktop handles the mapping transparently.
id -u user >/dev/null 2>&1 || useradd -m -s /bin/bash -u 1000 user
