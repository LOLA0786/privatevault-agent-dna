"""Fineract lab fixtures. Loaded only for tests under this directory.

Do not add these fixtures, markers, or env vars to the root tests/conftest.py.
"""

from __future__ import annotations

import importlib.util
import json
import re
import ssl
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[2]
_PILOT = _REPO / "pilot" / "fineract"
_SEED_STATE = _PILOT / "seed-state.json"
_SEED_CMD = "cd pilot/fineract && python3 seed.py"
_REQUIRED_STATE = (
    "account_a_id",
    "account_b_id",
    "account_c_id",
    "client_a_id",
    "client_b_id",
    "office_id",
    "tenant_header",
    "tenant_id",
    "payment_type_id",
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "pilot: live Apache Fineract lab counterparty (opt-in; pytest -m pilot)",
    )


def pilot_markexpr_selected(config: pytest.Config) -> bool:
    """True only when -m selects pilot. Env vars cannot opt in."""
    markexpr = (config.option.markexpr or "").strip()
    cleaned = re.sub(r"\bnot\s+pilot\b", "", markexpr)
    return bool(re.search(r"\bpilot\b", cleaned))


def require_seed_state() -> dict[str, Any]:
    if not _SEED_STATE.is_file():
        _fail_seed(f"{_SEED_STATE} is missing.")
    try:
        data = json.loads(_SEED_STATE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail_seed(f"{_SEED_STATE} is malformed ({exc}).")
    if not isinstance(data, dict):
        _fail_seed(f"{_SEED_STATE} is malformed (not an object).")
    missing = [key for key in _REQUIRED_STATE if key not in data]
    if missing:
        _fail_seed(
            f"{_SEED_STATE} is missing (stale seed file, required keys "
            f"{missing} absent)."
        )
    return data


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if pilot_markexpr_selected(config):
        return
    skip = pytest.mark.skip(
        reason="Fineract lab pilot; run with pytest -m pilot after: " + _SEED_CMD
    )
    for item in items:
        if item.get_closest_marker("pilot"):
            item.add_marker(skip)


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("pilot") is None:
        return
    if not pilot_markexpr_selected(item.config):
        pytest.skip("Fineract lab pilot; run with pytest -m pilot after: " + _SEED_CMD)
    require_seed_state()


def _seed_module() -> Any:
    path = _PILOT / "seed.py"
    spec = importlib.util.spec_from_file_location("fineract_lab_seed", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fail_seed(reason: str) -> None:
    raise RuntimeError(f"{reason} Run: {_SEED_CMD}")


def transfer_description(
    *, request_id: str | None = None, action_digest: str | None = None
) -> str:
    """Opaque string for POST /accounttransfers transferDescription.

    Hop 1: we choose this string; Fineract stores it on the
    /v1/accounttransfers record as transferDescription. That is not a
    cryptographic binding.
    Hop 2: the savings transaction has no description field. Join by
    transactions[].transfer.id to the accounttransfers id.
    """
    if request_id is not None and str(request_id):
        token = str(request_id)
    elif action_digest is not None and str(action_digest):
        hexpart = str(action_digest).split(":")[-1]
        token = hexpart[:16]
    else:
        raise ValueError("request_id or action_digest is required")
    return f"pv:{token}"


def _accounttransfer_items(payload: Any) -> list[dict[str, Any]]:
    """Expected live 1.11.0 envelope: {totalFilteredRecords, pageItems}.

    A bare list was never observed; still accepted so a shape change fails
    at the join instead of at parse, with the expected keys named first.
    """
    if isinstance(payload, dict):
        missing = [
            key for key in ("totalFilteredRecords", "pageItems") if key not in payload
        ]
        if not missing:
            items = payload["pageItems"]
            if not isinstance(items, list):
                raise RuntimeError(
                    f"accounttransfers pageItems is not a list: {type(items)}"
                )
            return items
        if "pageItems" in payload and isinstance(payload["pageItems"], list):
            return payload["pageItems"]
        raise RuntimeError(
            "GET /accounttransfers expected {totalFilteredRecords, pageItems} "
            f"(captured live at 1.11.0). missing={missing} keys={sorted(payload)}"
        )
    if isinstance(payload, list):
        return payload
    raise RuntimeError(
        "GET /accounttransfers expected {totalFilteredRecords, pageItems} "
        f"(captured live at 1.11.0); got {type(payload).__name__}"
    )


def accounttransfer_ids_for_description(payload: Any, description: str) -> set[int]:
    """Hop 1: ids of /v1/accounttransfers rows with this transferDescription."""
    found: set[int] = set()
    for item in _accounttransfer_items(payload):
        if not isinstance(item, dict):
            raise RuntimeError(
                f"accounttransfers item is not an object: {item!r}"[:500]
            )
        missing = [k for k in ("id", "transferDescription") if k not in item]
        if missing:
            raise RuntimeError(
                f"accounttransfers item missing {missing}: {sorted(item)}"
            )
        if item["transferDescription"] == description:
            found.add(int(item["id"]))
    return found


def all_accounttransfer_ids(payload: Any) -> set[int]:
    found: set[int] = set()
    for item in _accounttransfer_items(payload):
        if not isinstance(item, dict) or "id" not in item:
            raise RuntimeError(f"accounttransfers item missing id: {item!r}"[:500])
        found.add(int(item["id"]))
    return found


def savings_nested_transfer_ids(transactions: Any) -> set[int]:
    """Hop 2: transactions[].transfer.id. The savings row has no description."""
    if not isinstance(transactions, list):
        raise RuntimeError(f"savings transactions is not a list: {type(transactions)}")
    found: set[int] = set()
    for txn in transactions:
        if not isinstance(txn, dict):
            raise RuntimeError(f"savings transaction is not an object: {txn!r}"[:500])
        nested = txn.get("transfer")
        if nested is None:
            continue
        if not isinstance(nested, dict) or "id" not in nested:
            raise RuntimeError(
                f"savings transaction.transfer missing id: {nested!r}"[:500]
            )
        found.add(int(nested["id"]))
    return found


@dataclass(frozen=True)
class LedgerSnapshot:
    """Per-test starting balances. Assertions must use delta(), not absolutes."""

    before: dict[str, Decimal]
    account_ids: dict[str, int]
    client: Any
    seed: Any

    def current(self) -> dict[str, Decimal]:
        return {
            name: Decimal(
                str(
                    self.seed.account_snapshot(self.client, account_id)[
                        "accountBalance"
                    ]
                )
            )
            for name, account_id in self.account_ids.items()
        }

    def delta(self) -> dict[str, Decimal]:
        now = self.current()
        return {name: now[name] - self.before[name] for name in self.before}


@pytest.fixture(scope="session")
def dispatched_transfers() -> list[dict[str, str]]:
    """action_digest + transferDescription pairs that actually reached Fineract."""
    return []


@pytest.fixture(scope="session")
def seed_state() -> dict[str, Any]:
    return require_seed_state()


@pytest.fixture(scope="session")
def fineract_seed():
    return _seed_module()


@pytest.fixture(scope="session")
def fineract_client(seed_state: dict[str, Any], fineract_seed: Any) -> Any:
    ctx = fineract_seed.ssl_context()
    if not ctx.check_hostname:
        raise RuntimeError(
            "ssl_context().check_hostname is False; the lab client must "
            "verify the compose cert SAN"
        )
    return fineract_seed.Fineract(ctx)


@pytest.fixture
def ledger_snapshot(
    seed_state: dict[str, Any], fineract_client: Any, fineract_seed: Any
) -> LedgerSnapshot:
    ids = {
        "A": int(seed_state["account_a_id"]),
        "B": int(seed_state["account_b_id"]),
        "C": int(seed_state["account_c_id"]),
    }
    before = {
        name: Decimal(
            str(
                fineract_seed.account_snapshot(fineract_client, account_id)[
                    "accountBalance"
                ]
            )
        )
        for name, account_id in ids.items()
    }
    return LedgerSnapshot(
        before=before,
        account_ids=ids,
        client=fineract_client,
        seed=fineract_seed,
    )


@pytest.fixture
def tls_context(fineract_seed: Any) -> ssl.SSLContext:
    return fineract_seed.ssl_context()
