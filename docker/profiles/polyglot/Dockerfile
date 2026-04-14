# Fallback image for servers whose runtime we cannot narrow down to one of the
# dedicated profiles (e.g. shell scripts that shell out to both node and python,
# or unknown bare binaries). Mirrors the legacy docker/Dockerfile.sandbox.
FROM node:22-bookworm-slim

COPY common.sh /common.sh
RUN sh /common.sh && rm /common.sh

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages \
        uv mcp fastmcp python-dotenv httpx aiofiles pydantic

WORKDIR /workspace
USER user
CMD ["sleep", "infinity"]
