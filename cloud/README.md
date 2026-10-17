# SP-DECODE Cloud — Android online backend (C1 → C2)

**C2 status:** private reference worker implemented. The Android UI and bot have not been changed. **No public decoding is enabled**: Next.js still returns `503 CLOUD_NOT_READY` on file/text/import/job/session routes until C3 security is completed.

## Architecture

- `web/`: Next.js 16, Node.js 22 App Router; versioned public HTTP contract. Health, readiness, config and capabilities only.
- `contracts/v1/openapi.json`: frozen **public** C1 routes (decoder requests still disabled).
- `workers/python/server.py`: internal token-gated HTTP worker with file, text and encrypted NUR-catalog entrypoints.
- `workers/python/engine.py`: isolated and bounded subprocess dispatcher for 239 Android file routes plus `.solid`, using the exact C0 map.
- `workers/python/text_bridge.py`: direct import of source protocol modules without Telegram bot handlers.
- `workers/python/hc_bridge.py`: HTTP Custom HCCFG password/HWID via stdin to original source.
- `workers/python/catalog_bridge.py`: authenticated NUR server catalog processing; it **never fetches a URL**.
- `compose.yaml`: development topology. API bound to localhost; worker is on Docker's internal network with non-root, no outbound Internet, read-only filesystem and resource limits.

## Local verification

From the repo root (Python requirements, Node and PHP are required):

```bash
python -m pip install -r requirements.txt
npm ci
PYTHONPATH=. python scripts/cloud_c0_inventory.py --check
PYTHONPATH=cloud/workers/python:. python -m unittest discover -s cloud/workers/python -p 'test_*.py' -v
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_cloud_c2_golden tests.test_cloud_c2_text tests.test_cloud_c2_hc tests.test_cloud_c2_nur_catalog -v
docker compose -f cloud/compose.yaml config --quiet
docker compose -f cloud/compose.yaml build decoder-worker
```

The full results appear in `.github/workflows/cloud-c2.yml`. The original scripts and existing tests are not rewritten.

## Internal worker authorization

To enable internal development calls, generate and provision a random, server-only `CLOUD_WORKER_TOKEN` of at least 32 characters at runtime (not in git, Android or `libspdecode.so`). Pass it in the `X-SP-Worker-Token` header over the private Docker network. Without it all decode attempts are denied; public API is **still disabled** with or without this token.

Internal endpoints:

- `GET /internal/v1/capabilities`
- `POST /internal/v1/decode/file`: `{"format":"tls","dataBase64":"..."}` (only for synthetic/authorized samples); `{"credentials":{"password":"...","hwid":"..."}}` is allowed exclusively for `.hc`.
- `POST /internal/v1/decode/text`: `{"text":"scheme://..."}`
- `POST /internal/v1/decode/import/catalog`: `{"dataBase64":"..."}` for **already downloaded** encrypted NUR catalog bytes.

**Never expose the worker port or use the internal token as a customer credential.** C3 must provide public authorization, upload limits, Play Integrity verification, rate limiting, SSRF-safe provider fetching, audit and non-retention policies before the Android app can be connected.

The **official promotional website** is C6, and the native Android transport will be named **`libspdecode.so`** in C4. Permanent decoder keys and backend secrets belong on the server, not in compiled C++.

Detailed docs: [C0 baseline](../docs/cloud/C0_BASELINE.md), [C1](../docs/cloud/C1_IMPLEMENTATION.md), [C2](../docs/cloud/C2_IMPLEMENTATION.md).

**Current limitations:** no public auth/upload/decode, no HTTP Injector Cloud remote import, and no claim that a cataloged file route proves all vendor/exporter versions. Preserve the Android UI/UX and all result fields during C3–C4.
