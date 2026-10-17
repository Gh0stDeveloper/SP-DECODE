# SP-DECODE Cloud — C1 development infrastructure

This directory is an **isolated prototype**, not an operational decoder service. Android and Telegram bot sources are untouched. No existing customer configuration should be submitted to it.

## Topology

- `web/`: Next.js 16 App Router + Node.js 22, HTTP API v1, placeholder home page (official website design arrives in C6).
- `contracts/v1/openapi.json`: versioned contract; all decode/session/job POST operations explicitly return `503 CLOUD_NOT_READY`.
- `workers/python/`: standard-library HTTP control-plane stub for future isolated Python/Node/PHP decoders. **No decoder is imported or executed in C1**.
- `compose.yaml`: two services; the API is published to **localhost only** on port 3000, and the worker can only be reached over an internal Docker network. Worker has no outbound network access; read-only filesystem, non-root, dropped capabilities and resource limits.
- `docs/cloud/C1_IMPLEMENTATION.md`: roadmap, threat model and validation gates.

## Local tests

From the repository root:

```bash
cd cloud/web
npm install
npm test
npm run build
cd ../..
PYTHONPATH=cloud/workers/python python -m unittest discover -s cloud/workers/python -p 'test_*.py' -v
docker compose -f cloud/compose.yaml config --quiet
```

## Optional local stack

```bash
docker compose -f cloud/compose.yaml up --build -d
curl -i http://127.0.0.1:3000/api/v1/health
curl -i http://127.0.0.1:3000/api/v1/ready
curl -i http://127.0.0.1:3000/api/v1/capabilities
docker compose -f cloud/compose.yaml down
```

Expected: health 200; readiness 503; capabilities 200 with `decodingEnabled=false` and empty `enabledFormats`; any decode call 503.

**Security:** localhost binding is intentional, not a production access control. Do not expose port 3000 or publish containers without HTTPS termination, real auth, quota limits and audit findings in C3. C1 deliberately has no sessions, uploads, database, real jobs, decoders, NUR fetcher, third-party Cloud importer, dashboard, or C++ native library. The agreed later Android native library name is **`libspdecode.so`**.

**Secrets:** `web/.env.example` is illustrative; no live tokens or master keys belong in Android, Git history or a distributed native binary. `WORKER_INTERNAL_URL` remains server-private.

**Dependency strategy:** Next.js and React use compatible major-version semver ranges in `web/package.json`; package installation during C1 CI is restricted to this directory and does not modify the bot's root `package.json`. Production should add and vet a pinned lockfile and image digests before deployment.
