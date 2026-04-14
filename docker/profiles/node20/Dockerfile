FROM node:20-bookworm-slim

COPY common.sh /common.sh
RUN sh /common.sh && rm /common.sh

WORKDIR /workspace
USER user
CMD ["sleep", "infinity"]
