"""The real PrivateVault API server with a one-line event log.

    python -m demos.live_checkout.services.privatevault --port 8702

Configuration comes from ``services.env`` in the run directory (written by
``bootstrap.py``) or from the process environment under Docker. The app is
``api.server.app`` unchanged; the wrapper only reads what goes by on
``/v1/decide`` and ``/v1/authorize`` and prints one line per call.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import logging
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # run as a script

from demos.live_checkout import config as cfg  # noqa: E402
from demos.live_checkout.events import log, short  # noqa: E402
from demos.live_checkout.services._asgi_log import EventLog, json_or_none  # noqa: E402

REQUIRED = (
    "PV_DB_PATH",
    "PV_API_KEYS_FILE",
    "PV_EXECUTION_SIGNER_KEY",
    "PV_TRUST_BUNDLE",
    "PV_GRANTS_FILE",
    "PV_POLICY_FILE",
    "PV_APPROVER_TRUST_BUNDLE",
    "PV_BASELINE_CAPABILITIES",
)


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
            capability=req.get("capability"),
            amount=args.get("amount"),
            merchant=args.get("merchant_id"),
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
        permit=auth.get("execution_authorization_id"),
        decision=short(req.get("decision_id"), 13),
        wire=short(auth.get("expected_wire_bytes_digest"), 25),
        approval=short(auth.get("approval_artifact_digest"), 22)
        if auth.get("approval_artifact_digest")
        else None,
        expires=auth.get("expires_at"),
        reason=detail.get("reason_code") if status != 200 else None,
        http=status,
    )


def build_app() -> Any:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        raise SystemExit(
            f"privatevault: missing {', '.join(missing)}; run bootstrap.py"
        )
    os.environ.pop("PV_ALLOW_NO_AUTH", None)
    # The server prints its "not attached" banner to stderr at import and
    # logs JSON at INFO; the pane shows one line per call instead. Run with
    # PV_LIVE_VERBOSE=1 to see the banner.
    quiet = os.environ.get("PV_LIVE_VERBOSE", "") not in {"1", "true"}
    with (
        contextlib.redirect_stderr(io.StringIO()) if quiet else contextlib.nullcontext()
    ):
        import api.server as server
    if quiet:
        logging.getLogger("pv.api").setLevel(logging.WARNING)
    return EventLog(server.app, observed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=cfg.PORTS["privatevault"])
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    if args.run_dir:
        os.environ["PV_LIVE_RUN_DIR"] = args.run_dir
    cfg.load_env([cfg.run_dir() / "services.env"])
    app = build_app()
    import uvicorn

    log(
        "privatevault",
        "READY",
        "",
        url=f"http://{args.host}:{args.port}",
        policy=os.environ["PV_POLICY_FILE"],
        approvers=os.environ["PV_APPROVER_TRUST_BUNDLE"],
        auth="api-key",
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
