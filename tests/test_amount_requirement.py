"""PV-01: budgeted/capped paths reject absent amount before mutation."""

from __future__ import annotations

import importlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_dna.amount import INVALID_AMOUNT, InvalidAmountError, coerce_amount
from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker, GuardedEngine
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.grants import GrantRegistry
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.trace import AgentAction
from tests.test_p0_audit import StubScorer

CAP = "payments.initiate_wire"
AGENT = "amt-req-agent"
HTTP_AGENT = "treasury-agent"
HTTP_CAP = "crm.read_contact"


def _act(amount=..., *, agent_id: str = AGENT, capability: str = CAP) -> AgentAction:
    if amount is ...:
        args: dict = {}
    else:
        args = {"amount": amount}
    return AgentAction(
        agent_id=agent_id,
        capability=capability,
        timestamp=time.time(),
        arguments=args,
    )


def _grant_engine(budget: float | None) -> tuple[GrantRegistry, DecisionEngine]:
    reg = GrantRegistry()
    kwargs = {"agent_id": AGENT, "capability": CAP, "granted_by": "cfo"}
    if budget is not None:
        kwargs["budget"] = budget
    reg.grant(**kwargs)
    return reg, DecisionEngine(scorer=StubScorer(), authorizer=reg)


def _assert_invalid(result) -> None:
    assert result.decision is Decision.BLOCK
    assert INVALID_AMOUNT in result.reason


def test_budgeted_grant_omitted_amount_is_invalid_amount() -> None:
    _reg, engine = _grant_engine(100.0)
    result = engine.decide(_act())
    _assert_invalid(result)


def test_budgeted_grant_none_amount_is_invalid_amount() -> None:
    _reg, engine = _grant_engine(100.0)
    result = engine.decide(_act(None))
    _assert_invalid(result)


def test_budgeted_grant_empty_amount_is_invalid_amount() -> None:
    _reg, engine = _grant_engine(100.0)
    result = engine.decide(_act(""))
    _assert_invalid(result)


def test_unbudgeted_grant_omitted_amount_still_allows() -> None:
    _reg, engine = _grant_engine(None)
    result = engine.decide(_act())
    assert result.decision is Decision.ALLOW


def test_budgeted_grant_valid_zero_is_allowed() -> None:
    _reg, engine = _grant_engine(100.0)
    result = engine.decide(_act(0))
    assert result.decision is Decision.ALLOW


def test_budgeted_grant_rejects_absent_before_spend() -> None:
    reg, engine = _grant_engine(100.0)
    grant = next(iter(reg._grants.values()))
    spent_before = Decimal(str(grant.spent))
    _assert_invalid(engine.decide(_act()))
    assert Decimal(str(grant.spent)) == spent_before


def test_capped_breaker_omitted_amount_rejects_before_row(tmp_path: Path) -> None:
    breaker = CircuitBreaker(
        tmp_path / "cap.db",
        BreakerConfig(
            max_decisions=None,
            max_cumulative_amount=Decimal("100"),
            max_consecutive_refusals=None,
        ),
    )
    guarded = GuardedEngine(
        DecisionEngine(scorer=StubScorer(), authorizer=OpenAuthorizer()),
        breaker,
    )
    _assert_invalid(guarded.decide(_act()))
    (events,) = breaker._conn.execute("SELECT COUNT(*) FROM breaker_events").fetchone()
    assert events == 0


def test_uncapped_breaker_omitted_amount_still_allows(tmp_path: Path) -> None:
    breaker = CircuitBreaker(
        tmp_path / "uncap.db",
        BreakerConfig(
            max_decisions=None,
            max_cumulative_amount=None,
            max_consecutive_refusals=None,
        ),
    )
    guarded = GuardedEngine(
        DecisionEngine(scorer=StubScorer(), authorizer=OpenAuthorizer()),
        breaker,
    )
    result = guarded.decide(_act())
    assert result.decision is Decision.ALLOW


def test_coerce_amount_rejects_excessive_precision() -> None:
    with pytest.raises(InvalidAmountError) as excinfo:
        coerce_amount("1.123456789")
    assert excinfo.value.reason_code == INVALID_AMOUNT
    assert coerce_amount("1.12345678") == Decimal("1.12345678")
    assert coerce_amount(0) == Decimal("0")


def test_concurrent_capped_reserve_rejects_absent_without_rows(tmp_path: Path) -> None:
    breaker = CircuitBreaker(
        tmp_path / "race.db",
        BreakerConfig(
            max_decisions=None,
            max_cumulative_amount=Decimal("50"),
            max_consecutive_refusals=None,
        ),
    )
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def _race() -> None:
        local = CircuitBreaker(
            tmp_path / "race.db",
            BreakerConfig(
                max_decisions=None,
                max_cumulative_amount=Decimal("50"),
                max_consecutive_refusals=None,
            ),
        )
        try:
            barrier.wait()
            local.reserve(AGENT, None)
        except InvalidAmountError:
            pass
        except Exception as exc:  # noqa: BLE001 — collect unexpected
            errors.append(exc)
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_race) for _ in range(8)]
        for fut in futs:
            fut.result()
    assert errors == []
    (events,) = breaker._conn.execute("SELECT COUNT(*) FROM breaker_events").fetchone()
    assert events == 0
    breaker.close()


def test_capped_breaker_restart_has_no_null_amount_row(tmp_path: Path) -> None:
    db = tmp_path / "restart.db"
    cfg = BreakerConfig(
        max_decisions=None,
        max_cumulative_amount=Decimal("100"),
        max_consecutive_refusals=None,
    )
    first = CircuitBreaker(db, cfg)
    with pytest.raises(InvalidAmountError):
        first.reserve(AGENT, None)
    first.close()

    restarted = CircuitBreaker(db, cfg)
    rows = list(restarted._conn.execute("SELECT amount FROM breaker_events"))
    assert rows == []
    restarted.close()


@pytest.fixture()
def budget_http_env(tmp_path, monkeypatch):
    from nacl.signing import SigningKey

    from agent_dna.apikeys import generate_key
    from agent_dna.authority_v01 import CANONICALIZATION, TRUST_SPEC, encode_public_key

    op = generate_key(HTTP_AGENT, "full")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({op["hash"]: {"name": op["name"], "scope": "full"}}),
        encoding="utf-8",
    )
    sk = SigningKey.generate()
    (tmp_path / "exec.key").write_bytes(bytes(sk))
    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": "org-demo",
        "bundle_version": 1,
        "pinned_at": "2026-07-31T11:00:00Z",
        "keys": [
            {
                "key_id": "k1",
                "principal": "execution-runtime@org-demo",
                "algorithm": "ed25519",
                "public_key": encode_public_key(sk),
                "usages": ["execution_authorization_signer"],
            }
        ],
    }
    (tmp_path / "trust.json").write_text(json.dumps(bundle), encoding="utf-8")
    (tmp_path / "grants.json").write_text(
        json.dumps(
            [
                {
                    "agent_id": HTTP_AGENT,
                    "capability": HTTP_CAP,
                    "granted_by": "test",
                    "budget": 100,
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", str(tmp_path / "exec.key"))
    monkeypatch.setenv("PV_TRUST_BUNDLE", str(tmp_path / "trust.json"))
    monkeypatch.setenv("PV_GRANTS_FILE", str(tmp_path / "grants.json"))
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()
    with TestClient(server.app) as client:
        yield {"client": client, "key": op["key"]}


def test_http_budgeted_grant_omitted_amount_is_invalid(budget_http_env) -> None:
    client, key = budget_http_env["client"], budget_http_env["key"]
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": HTTP_AGENT,
            "capability": HTTP_CAP,
            "timestamp": time.time(),
            "arguments": {},
        },
    )
    assert r.status_code == 403, r.text
    body = r.json()
    assert body["decision"] == "block"
    assert INVALID_AMOUNT in body["reason"]


def test_http_budgeted_grant_valid_zero_allows(budget_http_env) -> None:
    client, key = budget_http_env["client"], budget_http_env["key"]
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": HTTP_AGENT,
            "capability": HTTP_CAP,
            "timestamp": time.time(),
            "arguments": {"amount": 0},
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "allow"
