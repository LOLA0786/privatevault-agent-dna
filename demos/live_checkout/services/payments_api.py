"""Mock payments API behind the gate: refunds to a payment instrument.

    python -m demos.live_checkout.services.payments_api --port 8704

    POST /v1/refunds
    {"refund_id": "RF-...", "order_id": "ORD-...", "customer_id": "C-...",
     "amount": 1200, "currency": "INR", "payee": "ananya.s@okaxis", ...facts}
    -> 201 {"refund_id": ..., "status": "paid", "payout_ref": "pay_..."}

    GET /refunds   every refund paid so far (the order-history tool reads it)

It validates the shape, pays every well-formed request it receives, and
answers 201. The decided facts PrivateVault read (``original_amount``,
``payee_matches_original`` and so on) travel in the same bytes the permit
is bound to; the API stores and ignores them. It does not dedupe and does
not authenticate: it stands in for an upstream that trusts whatever its
caller is authorised to send. DEMO ONLY; the gate is its only intended
network path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # run as a script

from demos.live_checkout import config as cfg  # noqa: E402
from demos.live_checkout.events import log  # noqa: E402

REQUIRED = ("refund_id", "order_id", "customer_id", "amount", "currency", "payee")
FACTS = (
    "original_amount",
    "original_payee",
    "amount_exceeds_original",
    "payee_matches_original",
    "prior_refunds_for_order",
    "customer_refunds_today",
)
CURRENCY = re.compile(r"^[A-Z]{3}$")
PAYEE = re.compile(r"^([a-z0-9._-]+@[a-z0-9]+|card:[a-z]+-\d{4}|nb:[a-z]+-\d{4})$")


def validate_refund(body: Any) -> list[str]:
    if not isinstance(body, dict):
        return ["body must be a JSON object"]
    problems = [f"missing {f}" for f in REQUIRED if f not in body]
    problems += [
        f"unexpected {k}" for k in sorted(set(body) - set(REQUIRED) - set(FACTS))
    ]
    if problems:
        return problems
    for field in ("refund_id", "order_id", "customer_id"):
        if not isinstance(body[field], str) or not body[field].strip():
            problems.append(f"{field} must be a non-empty string")
    amount = body["amount"]
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        problems.append("amount must be a positive whole number")
    if not isinstance(body["currency"], str) or not CURRENCY.match(body["currency"]):
        problems.append("currency must be a three-letter ISO code")
    if not isinstance(body["payee"], str) or not PAYEE.match(body["payee"]):
        problems.append("payee must be a UPI id, card:brand-last4 or nb:bank-last4")
    return problems


class _Handler(BaseHTTPRequestHandler):
    server: PaymentsServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib name
        return

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        path = self.path.split("?", 1)[0]
        if path == "/_health":
            self._json(200, {"ok": True})
        elif path == "/refunds":
            self._json(200, self.server.refunds())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
        if self.path != cfg.REFUNDS_PATH:
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            body: Any = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            body = None
        problems = validate_refund(body)
        if problems:
            log(
                "payments-api",
                "REFUND",
                "REJECTED",
                http=400,
                problems=";".join(problems),
            )
            self._json(400, {"error": "invalid_request", "problems": problems})
            return
        number = self.server.record(body, raw)
        payout_ref = (
            "pay_" + hashlib.sha256(raw + str(number).encode()).hexdigest()[:12]
        )
        self.server.set_ref(number, payout_ref)
        log(
            "payments-api",
            "REFUND",
            "PAID",
            refund_id=body["refund_id"],
            order_id=body["order_id"],
            customer=body["customer_id"],
            amount=body["amount"],
            payee=body["payee"],
            ref=payout_ref,
        )
        self._json(
            201,
            {
                "refund_id": body["refund_id"],
                "status": "paid",
                "payout_ref": payout_ref,
                "amount": body["amount"],
                "currency": body["currency"],
                "payee": body["payee"],
            },
        )


class PaymentsServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, _Handler)
        self._lock = threading.Lock()
        self._refunds: list[dict[str, Any]] = []

    def record(self, body: dict[str, Any], raw: bytes) -> int:
        with self._lock:
            self._refunds.append(
                {
                    **{k: body[k] for k in REQUIRED},
                    "body_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "payout_ref": None,
                }
            )
            return len(self._refunds)

    def set_ref(self, number: int, ref: str) -> None:
        with self._lock:
            self._refunds[number - 1]["payout_ref"] = ref

    def refunds(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._refunds]

    @property
    def port(self) -> int:
        return int(self.server_address[1])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=cfg.PORTS["payments"])
    parser.add_argument(
        "--run-dir", default=None, help="accepted for uniformity; unused"
    )
    args = parser.parse_args(argv)
    server = PaymentsServer((args.host, args.port))
    log(
        "payments-api",
        "READY",
        "",
        url=f"http://{args.host}:{server.port}",
        refunds_path=cfg.REFUNDS_PATH,
        inspect="GET /refunds",
        mock="yes",
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
