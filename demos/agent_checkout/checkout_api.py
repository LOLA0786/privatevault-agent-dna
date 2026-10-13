"""Mock checkout API, shaped like a payment gateway's order-create endpoint.

    POST /v1/orders
    {"order_id": "ORD-...", "amount": 18500, "currency": "INR",
     "merchant_id": "M-1021", "callback_url": "https://.../callback"}
    -> 201 {"order_id": ..., "status": "created", "gateway_ref": "ord_..."}

It validates the request shape (every field present, amount a positive
whole number, currency three letters, merchant id ``M-<digits>``, callback
over https), creates an order record for every well-formed request it
receives, and answers 201. It does not dedupe on ``order_id``: it stands in
for an upstream that trusts whatever its caller is authorised to send,
which is exactly the position the receiver gate protects.

DEMO ONLY. ``GET /_orders`` exposes what was created so the demo can prove
which requests never arrived. A real gateway never exposes that, and never
exposes the order API except through the gate.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ORDERS_PATH = "/v1/orders"
FIELDS = ("order_id", "amount", "currency", "merchant_id", "callback_url")
MERCHANT_ID = re.compile(r"^M-\d{3,8}$")
CURRENCY = re.compile(r"^[A-Z]{3}$")


def validate_order(body: Any) -> list[str]:
    """Return the shape problems with an order request; empty means valid."""
    if not isinstance(body, dict):
        return ["body must be a JSON object"]
    problems = [f"missing {f}" for f in FIELDS if f not in body]
    problems += [f"unexpected {k}" for k in sorted(set(body) - set(FIELDS))]
    if problems:
        return problems
    if not isinstance(body["order_id"], str) or not body["order_id"].strip():
        problems.append("order_id must be a non-empty string")
    amount = body["amount"]
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        problems.append("amount must be a positive whole number of minor units")
    if not isinstance(body["currency"], str) or not CURRENCY.match(body["currency"]):
        problems.append("currency must be a three-letter ISO code")
    if not isinstance(body["merchant_id"], str) or not MERCHANT_ID.match(
        body["merchant_id"]
    ):
        problems.append("merchant_id must look like M-1234")
    url = body["callback_url"]
    if not isinstance(url, str) or not url.startswith("https://"):
        problems.append("callback_url must be an https URL")
    return problems


class _Handler(BaseHTTPRequestHandler):
    server: CheckoutServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib name
        if self.server.verbose:
            sys.stderr.write("checkout-api: " + (format % args) + "\n")

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
        elif self.path == "/_orders":
            self._json(200, self.server.seen())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
        if self.path != ORDERS_PATH:
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            body: Any = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            body = None
        problems = validate_order(body)
        if problems:
            self._json(400, {"error": "invalid_request", "problems": problems})
            return
        record = {
            "method": "POST",
            "path": self.path,
            "body_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "body_length": len(raw),
            "body_json": body,
            "header_names": sorted({k.lower() for k in self.headers.keys()}),
        }
        number = self.server.record(record)
        gateway_ref = (
            "ord_" + hashlib.sha256(raw + str(number).encode()).hexdigest()[:12]
        )
        record["gateway_ref"] = gateway_ref
        self._json(
            201,
            {
                "order_id": body["order_id"],
                "status": "created",
                "gateway_ref": gateway_ref,
                "amount": body["amount"],
                "currency": body["currency"],
                "merchant_id": body["merchant_id"],
            },
        )


class CheckoutServer(ThreadingHTTPServer):
    """Satisfies ``agents.core.harness.Upstream``."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], *, verbose: bool = False) -> None:
        super().__init__(address, _Handler)
        self.verbose = verbose
        self._lock = threading.Lock()
        self._orders: list[dict[str, Any]] = []

    def record(self, item: dict[str, Any]) -> int:
        with self._lock:
            self._orders.append(item)
            return len(self._orders)

    def seen(self) -> list[dict[str, Any]]:
        """Every order the API created, in order. Same shape as the stub."""
        with self._lock:
            return [dict(o) for o in self._orders]

    def orders(self) -> list[dict[str, Any]]:
        """Just the order bodies, with the gateway reference."""
        return [
            {**o["body_json"], "gateway_ref": o.get("gateway_ref")} for o in self.seen()
        ]

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def start(host: str = "127.0.0.1", port: int = 0) -> CheckoutServer:
    """Start in a daemon thread; ``port=0`` picks a free port."""
    server = CheckoutServer((host, port))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
