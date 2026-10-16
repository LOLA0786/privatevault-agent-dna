"""The real PrivateVault API server for the treasury demo, with the live
demo's one-line event log and this demo's field names.

    python -m demos.treasury.services.privatevault --port 8712
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # run as a script

from demos.live_checkout.events import log, short  # noqa: E402
from demos.live_checkout.services._asgi_log import json_or_none  # noqa: E402
from demos.live_checkout.services.privatevault import REQUIRED  # noqa: E402
from demos.treasury import config as cfg  # noqa: E402


def observed(
    method: str,
    path: str,
    request_headers: dict[str, str],
    request_body: bytes,
    status: int,
    response_headers: dict[str, str],
    response_body: bytes,
) -> None:
    if method != "POST" or path not in ("/v1/decide", "/v1/authorize"):
        return
    req: Any = json_or_none(request_body) or {}
    res: Any = json_or_none(response_body) or {}
    if path == "/v1/decide":
        record = res.get("record") or {}
        args = req.get("arguments") or {}
        log(
            "privatevault",
            "DECIDE",
            str(res.get("decision", f"http-{status}")),
            via=res.get("triggered_by"),
            agent=req.get("agent_id"),
            capability=req.get("capability"),
            amount_usd=args.get("amount_usd"),
            counterparty=args.get("counterparty_id"),
            policy=record.get("policy_id"),
            decision=short(record.get("decision_id"), 13),
            approval=short(record.get("approval_ref"), 22)
            if res.get("triggered_by") == "approval"
            else None,
            http=status,
        )
        return
    auth = res.get("authorization") or {}
    detail = res.get("detail") if isinstance(res.get("detail"), dict) else {}
    log(
        "privatevault",
        "AUTHORIZE",
        "MINTED" if status == 200 else "REFUSED",
        agent=req.get("agent_id"),
        permit=auth.get("execution_authorization_id"),
        decision=short(req.get("decision_id"), 13),
        wire=short(auth.get("expected_wire_bytes_digest"), 25),
        reason=detail.get("reason_code") if status != 200 else None,
        http=status,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=cfg.PORTS["privatevault"])
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    if args.run_dir:
        os.environ["PV_TREASURY_RUN_DIR"] = args.run_dir
    cfg.load_env([cfg.run_dir() / "services.env"])
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        raise SystemExit(
            f"privatevault: missing {', '.join(missing)}; run bootstrap.py"
        )
    from demos.live_checkout.services.privatevault import build_app

    app = build_app()
    app.observed = observed  # same wrapper, this demo's fields
    import uvicorn

    log(
        "privatevault",
        "READY",
        "",
        url=f"http://{args.host}:{args.port}",
        policy=os.environ["PV_POLICY_FILE"],
        replay_fields=os.environ.get("PV_REPLAY_FIELDS", ""),
        auth="api-key per agent",
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
