"""Mock bank API behind the gate: payments, transfers, FX.

    python -m demos.treasury.services.bank_api --port 8714

    POST /v1/payments   {kind: payment, counterparty_id, beneficiary_account, amount_usd, ...facts}
    POST /v1/transfers  {kind: transfer, from_account, to_account, amount_usd, ...}
    POST /v1/fx         {kind: fx, from_account, to_account, amount_usd, to_currency, ...}
    GET  /ledger        everything executed so far (the agents' ledger tool reads it)

It validates the shape, executes every well-formed request it receives,
and answers 201 with a bank reference. ``POST /_reset`` clears the ledger
so each run starts from the same state (demo only; it is reached directly,
never through the gate). The decided facts travel in the
same bytes the permit is bound to; the bank stores and ignores them. It
does not dedupe and does not authenticate. DEMO ONLY; the gate is its only
intended network path.
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

from demos.live_checkout.events import log  # noqa: E402
from demos.treasury import config as cfg  # noqa: E402

PATHS = {"/v1/payments": "payment", "/v1/transfers": "transfer", "/v1/fx": "fx"}
COMMON = (
    "kind",
    "agent_id",
    "counterparty_id",
    "amount_usd",
    "currency",
    "reference",
    "desk_clock",
)
REQUIRED = {
    "payment": COMMON + ("counterparty_name", "beneficiary_account"),
    "transfer": COMMON + ("from_account", "to_account"),
    "fx": COMMON + ("from_account", "to_account", "to_currency"),
}
FACTS = (
    "counterparty_on_master",
    "bank_details_verified",
    "vendor_paid_today_incl_usd",
    "agent_payments_last_hour",
    "within_business_hours",
)
IBAN = re.compile(r"^[A-Z]{2}[0-9A-Z]{10,32}$")


def validate(kind: str, body: Any) -> list[str]:
    if not isinstance(body, dict):
        return ["body must be a JSON object"]
    required = REQUIRED[kind]
    problems = [f"missing {f}" for f in required if f not in body]
    problems += [
        f"unexpected {k}" for k in sorted(set(body) - set(required) - set(FACTS))
    ]
    if problems:
        return problems
    if body["kind"] != kind:
        problems.append(f"kind must be {kind}")
    amount = body["amount_usd"]
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        problems.append("amount_usd must be a positive whole number")
    if body["currency"] != "USD":
        problems.append("currency must be USD")
    for field in ("beneficiary_account", "from_account", "to_account"):
        if field in body and not (
            isinstance(body[field], str) and IBAN.match(body[field])
        ):
            problems.append(f"{field} must be an account number")
    return problems


class _Handler(BaseHTTPRequestHandler):
    server: BankServer

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
        elif path == "/ledger":
            self._json(200, self.server.ledger())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler name
        if self.path == "/_reset":  # DEMO ONLY: a fresh ledger per run
            self.server.reset()
            log("bank-api", "RESET", "", note="ledger cleared for a new run")
            self._json(200, {"ok": True})
            return
        kind = PATHS.get(self.path)
        if kind is None:
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            body: Any = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            body = None
        problems = validate(kind, body)
        if problems:
            log(
                "bank-api",
                kind.upper(),
                "REJECTED",
                http=400,
                problems=";".join(problems),
            )
            self._json(400, {"error": "invalid_request", "problems": problems})
            return
        number = self.server.record(body, raw)
        ref = (
            f"{kind[:3].upper()}-"
            + hashlib.sha256(raw + str(number).encode()).hexdigest()[:10].upper()
        )
        self.server.set_ref(number, ref)
        log(
            "bank-api",
            kind.upper(),
            "EXECUTED",
            agent=body["agent_id"],
            counterparty=body["counterparty_id"],
            account=body.get("beneficiary_account") or body.get("to_account"),
            amount_usd=body["amount_usd"],
            ref=ref,
        )
        self._json(
            201,
            {
                "status": "executed",
                "bank_ref": ref,
                "kind": kind,
                "amount_usd": body["amount_usd"],
            },
        )


class BankServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, _Handler)
        self._lock = threading.Lock()
        self._ledger: list[dict[str, Any]] = []

    def record(self, body: dict[str, Any], raw: bytes) -> int:
        with self._lock:
            self._ledger.append(
                {
                    **body,
                    "body_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "bank_ref": None,
                }
            )
            return len(self._ledger)

    def set_ref(self, number: int, ref: str) -> None:
        with self._lock:
            self._ledger[number - 1]["bank_ref"] = ref

    def ledger(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._ledger]

    def reset(self) -> None:
        with self._lock:
            self._ledger.clear()

    @property
    def port(self) -> int:
        return int(self.server_address[1])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=cfg.PORTS["bank"])
    parser.add_argument(
        "--run-dir", default=None, help="accepted for uniformity; unused"
    )
    args = parser.parse_args(argv)
    server = BankServer((args.host, args.port))
    log(
        "bank-api",
        "READY",
        "",
        url=f"http://{args.host}:{server.port}",
        paths=";".join(PATHS),
        inspect="GET /ledger",
        mock="yes",
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
