"""The real receiver gate (receiver kit) in front of the mock bank, with the
live demo's one-line event log and this demo's field names.

    python -m demos.treasury.services.gate --port 8713
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # run as a script

from agent_dna.receiver.permit_header import (  # noqa: E402
    PERMIT_HEADER_LOWER,
    decode_permit_header,
)
from demos.live_checkout.events import log, short  # noqa: E402
from demos.live_checkout.services._asgi_log import EventLog, json_or_none  # noqa: E402
from demos.treasury import config as cfg  # noqa: E402
from network.receiver_kit.config import build_app as build_gate_app  # noqa: E402
from network.receiver_kit.config import describe, settings_from_env  # noqa: E402


def observed(
    method: str,
    path: str,
    request_headers: dict[str, str],
    request_body: bytes,
    status: int,
    response_headers: dict[str, str],
    response_body: bytes,
) -> None:
    if method == "GET":
        return  # unprotected reads (/_health, /ledger) are forwarded, not gated
    permit_id = None
    subject = None
    header = request_headers.get(PERMIT_HEADER_LOWER)
    if header:
        try:
            permit = decode_permit_header(header)
            permit_id = permit.get("execution_authorization_id")
            subject = (permit.get("action") or {}).get("subject_key_id")
        except Exception:
            permit_id = "malformed"
    body: Any = json_or_none(request_body)
    body = body if isinstance(body, dict) else {}
    res: Any = json_or_none(response_body)
    res = res if isinstance(res, dict) else {}
    seq = response_headers.get("x-pv-receiver-sequence") or res.get("receipt_sequence")
    receipt = response_headers.get("x-pv-receiver-receipt") or res.get("receipt_digest")
    common = {
        "op": f"{method} {path}",
        "agent": body.get("agent_id"),
        "amount_usd": body.get("amount_usd"),
        "counterparty": body.get("counterparty_id"),
        "account": body.get("beneficiary_account") or body.get("to_account"),
        "permit": permit_id,
        "permit_subject": subject,
        "seq": seq,
        "receipt": short(receipt, 25),
    }
    if res.get("admitted") is False:
        log(
            "gate",
            "REFUSED",
            "REFUSED",
            http=status,
            reason=res.get("reason_code"),
            **common,
        )
    elif res.get("upstream") == "INDETERMINATE":
        log("gate", "ADMITTED", "INDETERMINATE", http=status, **common)
    else:
        log("gate", "ADMITTED", "ADMITTED", upstream=status, **common)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=cfg.PORTS["gate"])
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    if args.run_dir:
        os.environ["PV_TREASURY_RUN_DIR"] = args.run_dir
    cfg.load_env([cfg.run_dir() / "services.env"])
    settings = settings_from_env()
    proxy = build_gate_app(settings)
    for line in describe(settings, proxy.gate).splitlines()[1:]:
        print("  " + line.strip(), flush=True)
    app = EventLog(proxy, observed)
    import uvicorn

    log(
        "gate",
        "READY",
        "",
        url=f"http://{args.host}:{args.port}",
        receiver=settings.receiver_id,
        upstream=settings.upstream,
        bundle=short(settings.trust_bundle_digest, 25),
        receipt_key=settings.receipt_key_id,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
