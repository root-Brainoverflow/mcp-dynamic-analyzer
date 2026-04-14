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

# Non-root analysis user named 'user'. Official node/python base images
# already ship a user at UID 1000 ('node', 'python', …); we rename that
# one instead of creating a duplicate UID.
if ! id -u user >/dev/null 2>&1; then
    if id -u 1000 >/dev/null 2>&1; then
        existing=$(id -nu 1000)
        usermod -l user "$existing"
        groupmod -n user "$existing" 2>/dev/null || true
        usermod -d /home/user -m user 2>/dev/null || true
    else
        useradd -m -s /bin/bash -u 1000 user
    fi
fi
