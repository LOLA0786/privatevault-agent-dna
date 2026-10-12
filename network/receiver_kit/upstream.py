"""Dummy payment upstream for the demo. Not a real system of record.

It accepts any POST, records what it received (method, path, body digest and
length, header names), and answers 200. ``GET /_seen`` returns the records so
``send_test.py`` can prove which requests never arrived. ``GET /_health``
answers ok.

DEMO ONLY. A real partner never exposes the upstream; the gate is the only
network path to it. ``/_seen`` exists so the quickstart can show the gate
working, nothing more.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class _Handler(BaseHTTPRequestHandler):
    server: UpstreamServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib name
        sys.stderr.write("upstream: " + (format % args) + "\n")

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        if self.path == "/_health":
            self._json(200, {"ok": True})
        elif self.path == "/_seen":
            self._json(200, self.server.seen())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        try:
            body_json: Any = json.loads(body.decode("utf-8")) if body else None
        except (ValueError, UnicodeDecodeError):
            body_json = None
        record = {
            "method": "POST",
            "path": self.path,
            "body_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
            "body_length": len(body),
            # Demo only: what the stub would have acted on, so the proof can
            # print the amount and payee that actually arrived.
            "body_json": body_json,
            "header_names": sorted({k.lower() for k in self.headers.keys()}),
        }
        number = self.server.record(record)
        self._json(200, {"transferId": number, "status": "accepted"})

    do_PUT = do_POST  # noqa: N815 - stdlib handler name
    do_PATCH = do_POST  # noqa: N815 - stdlib handler name
    do_DELETE = do_POST  # noqa: N815 - stdlib handler name


class UpstreamServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, _Handler)
        self._lock = threading.Lock()
        self._seen: list[dict[str, Any]] = []

    def record(self, item: dict[str, Any]) -> int:
        with self._lock:
            self._seen.append(item)
            return len(self._seen)

    def seen(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._seen)

    @property
    def port(self) -> int:
        return int(self.server_address[1])


def start(host: str = "127.0.0.1", port: int = 0) -> UpstreamServer:
    """Start in a daemon thread; ``port=0`` picks a free port."""
    server = UpstreamServer((host, port))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dummy payment upstream (demo only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9001)
    args = parser.parse_args(argv)
    server = UpstreamServer((args.host, args.port))
    print(
        f"upstream listening on {args.host}:{server.port} (demo only)", file=sys.stderr
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
