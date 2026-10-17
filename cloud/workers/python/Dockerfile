# Worker sandbox image. Build context MUST be the repository root (see compose.yaml).
FROM node:22-bookworm-slim AS js-deps
WORKDIR /opt/spdecode
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends php-cli \
    && rm -rf /var/lib/apt/lists/*
COPY --from=js-deps /usr/local/bin/node /usr/local/bin/node
WORKDIR /opt/spdecode
COPY requirements.txt package.json package-lock.json ./
RUN pip install --no-cache-dir -r requirements.txt
# The root npm dependencies are used by a small number of legacy JS engines.
COPY --from=js-deps /opt/spdecode/node_modules ./node_modules
COPY decoders/ ./decoders/
COPY spdecode/ ./spdecode/
COPY decoders.json ./decoders.json
COPY docs/cloud/C0_FORMAT_MATRIX.csv ./docs/cloud/C0_FORMAT_MATRIX.csv
COPY cloud/workers/python/engine.py cloud/workers/python/server.py cloud/workers/python/text_bridge.py cloud/workers/python/hc_bridge.py ./cloud/workers/python/
# Package and local import work from the original repository tree.
USER 65532:65532
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 WORKER_BIND_HOST=0.0.0.0 WORKER_PORT=8787
EXPOSE 8787
CMD ["python", "-B", "cloud/workers/python/server.py"]
