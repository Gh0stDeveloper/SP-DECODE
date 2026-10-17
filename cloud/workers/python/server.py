#!/usr/bin/env python3
"""C1 isolated worker control-plane stub. No decoder imports, no file processing."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class WorkerHandler(BaseHTTPRequestHandler):
    server_version = "SPDecodeWorker/0.1"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        # Do not log URLs, payloads, user credentials or request headers.
        return

    def _json(self, status: int, body: dict) -> None:
        response = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self) -> None:
        if self.path == "/health":
            return self._json(200, {"service": "spdecode-worker", "status": "alive", "phase": "C1"})
        if self.path == "/ready":
            return self._json(503, {"service": "spdecode-worker", "status": "not_ready", "reason": "DECODERS_DISABLED"})
        return self._json(404, {"error": {"code": "NOT_FOUND"}})

    def do_POST(self) -> None:
        # Intentionally do not read or persist the request body.
        self._json(503, {"error": {"code": "DECODERS_DISABLED"}})

    def do_PUT(self) -> None:
        self._json(503, {"error": {"code": "DECODERS_DISABLED"}})


def main() -> None:
    host = os.environ.get("WORKER_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("WORKER_PORT", "8787"))
    ThreadingHTTPServer((host, port), WorkerHandler).serve_forever()


if __name__ == "__main__":
    main()
