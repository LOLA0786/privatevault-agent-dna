"""Shared configuration for the treasury demo."""

from __future__ import annotations

import os
from pathlib import Path

from demos.live_checkout.config import load_env, parse_env_file  # noqa: F401

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

ORGANISATION_ID = "corp.example"
RECEIVER_ID = "bank.gateway.example"
DESTINATION = "https://bank.gateway.example"
TOOL_ID = "bank.treasury.v1"
RECEIPT_KEY_ID = "bank-receiver-01"
EXECUTION_SIGNER_KEY_ID = "ea-signer"
WITNESS_KEY_ID = "witness-01"
PEER_LABEL = f"tls-spki:{RECEIVER_ID}"
UNPROTECTED_OPERATIONS = "GET /_health;GET /ledger"

AP_AGENT = "ap-agent-01"
TREASURY_AGENT = "treasury-agent-01"
AGENTS = (AP_AGENT, TREASURY_AGENT)

APPROVER_PRINCIPAL = "treasury-approver@corp.example"
APPROVER_KEY_ID = "approver-treasury"

OPERATIONS = {
    "treasury.pay_vendor": "POST /v1/payments",
    "treasury.move_liquidity": "POST /v1/transfers",
    "treasury.fx_convert": "POST /v1/fx",
}

# Fields the API retains (opt-in) so PolicyReplay can re-evaluate the live
# policy over this run's sealed decisions. Only rule inputs, never the
# whole payload.
REPLAY_FIELDS = (
    "amount_usd",
    "currency",
    "counterparty_on_master",
    "bank_details_verified",
    "vendor_paid_today_incl_usd",
    "agent_payments_last_hour",
    "within_business_hours",
)

PORTS = {"privatevault": 8712, "gate": 8713, "bank": 8714}

BUSINESS_HOURS = (9, 18)  # local, inclusive start, exclusive end
BUSINESS_DAYS = (0, 1, 2, 3, 4)  # Monday to Friday

QUEUE_FILE = HERE / "queue.json"
VENDORS_FILE = HERE / "vendors.json"
RUNS_DIR = HERE / "runs"


def run_dir() -> Path:
    return Path(os.environ.get("PV_TREASURY_RUN_DIR", str(HERE / ".run"))).resolve()


def url(service: str) -> str:
    env = f"PV_TREASURY_{service.upper()}_URL"
    return os.environ.get(env, f"http://127.0.0.1:{PORTS[service]}").rstrip("/")


def load_demo_env() -> None:
    load_env(
        [
            HERE / ".env",
            HERE.parent / "live_checkout" / ".env",
            REPO / ".env",
            run_dir() / "services.env",
        ]
    )
