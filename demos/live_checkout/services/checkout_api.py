"""Mock payment-order API behind the gate.

    python -m demos.live_checkout.services.checkout_api --port 8704

Reuses the order API from ``demos/agent_checkout/checkout_api.py`` (shape
validation, order store, ``GET /orders``) and logs one line per order it
creates. DEMO ONLY: it does not authenticate; the gate is its only intended
network path.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # run as a script

from demos.agent_checkout.checkout_api import CheckoutServer  # noqa: E402
from demos.live_checkout import config as cfg  # noqa: E402
from demos.live_checkout.events import log  # noqa: E402


def _on_order(record: dict[str, Any]) -> None:
    body = record.get("body_json") or {}
    log(
        "checkout-api",
        "ORDER",
        "CREATED",
        order_id=body.get("order_id"),
        amount=body.get("amount"),
        currency=body.get("currency"),
        merchant=body.get("merchant_id"),
        ref=record.get("gateway_ref"),
        body=record.get("body_sha256", "")[:25] + "…",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--run-dir", default=None, help="accepted for uniformity; unused"
    )
    parser.add_argument("--port", type=int, default=cfg.PORTS["checkout"])
    args = parser.parse_args(argv)
    server = CheckoutServer((args.host, args.port))
    server.on_order = _on_order
    log(
        "checkout-api",
        "READY",
        "",
        url=f"http://{args.host}:{server.port}",
        orders_path=cfg.ORDERS_PATH,
        inspect="GET /orders",
        mock="yes",
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
