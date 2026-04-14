FROM python:3.12-bookworm

COPY common.sh /common.sh
RUN sh /common.sh && rm /common.sh

RUN pip install --no-cache-dir uv \
    && pip install --no-cache-dir mcp fastmcp python-dotenv httpx aiofiles pydantic

WORKDIR /workspace
USER user
CMD ["sleep", "infinity"]
