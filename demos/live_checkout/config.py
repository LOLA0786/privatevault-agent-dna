"""Shared configuration for the live refund demo.

Everything the three services and the two terminals (agent, approver) need
to find each other and the run directory. Identities are fixed; ports and
URLs have defaults that environment variables override, so the same code
runs as local processes, under Docker Compose, or in tests on free ports.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

ORGANISATION_ID = "buyer.example"
AGENT_ID = "refund-agent-01"
RECEIVER_ID = "payments.gateway.example"
DESTINATION = "https://payments.gateway.example"
OPERATION = "POST /v1/refunds"
REFUNDS_PATH = "/v1/refunds"
TOOL_ID = "payments.refunds.v1"
RECEIPT_KEY_ID = "gateway-receiver-01"
EXECUTION_SIGNER_KEY_ID = "ea-signer"
WITNESS_KEY_ID = "witness-01"
PEER_LABEL = f"tls-spki:{RECEIVER_ID}"
UNPROTECTED_OPERATIONS = "GET /_health;GET /refunds"

APPROVER_PRINCIPAL = "payments-lead@buyer.example"
APPROVER_KEY_ID = "approver-payments-lead"

PORTS = {"privatevault": 8702, "gate": 8703, "payments": 8704}

QUEUE_FILE = HERE / "refund_queue.json"
RUNS_DIR = HERE / "runs"


def run_dir() -> Path:
    return Path(os.environ.get("PV_LIVE_RUN_DIR", str(HERE / ".run"))).resolve()


def url(service: str) -> str:
    """Base URL of a service as seen from the agent and approver (host side)."""
    env = f"PV_LIVE_{service.upper()}_URL"
    return os.environ.get(env, f"http://127.0.0.1:{PORTS[service]}").rstrip("/")


def parse_env_file(path: Path) -> dict[str, str]:
    """``KEY=VALUE`` lines; ``export`` prefix, quotes and comments allowed."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def load_env(paths: Iterable[Path]) -> None:
    """Load env files into ``os.environ`` without overriding what is set."""
    for path in paths:
        for key, value in parse_env_file(path).items():
            os.environ.setdefault(key, value)


def load_demo_env() -> None:
    """``.env`` (secrets such as the Anthropic key) then the run's services
    env (paths and identities written by ``bootstrap.py``)."""
    load_env([HERE / ".env", REPO / ".env", run_dir() / "services.env"])
