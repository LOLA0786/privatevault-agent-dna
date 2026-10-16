"""Grant budgets survive restarts and are shared by every worker.

Security review 2026-10: spend was process memory, so a restart or a second
worker restored spending authority that had already been consumed.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.grant_spend import GrantSpendLedger
from agent_dna.grants import GrantRegistry
from agent_dna.policy.checker import PolicyCheckResult
from agent_dna.trace import AgentAction

CAP = "payments.transfer"


def _runtime(tmp_path, monkeypatch, grants):
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", CAP)
    (tmp_path / "grants.json").write_text(json.dumps(grants))
    cfg = RuntimeConfig(db_path=str(tmp_path / "pv.db"))
    cfg.grants_file = str(tmp_path / "grants.json")
    cfg.breaker_max_amount = 10_000_000
    cfg.breaker_max_refusals = None
    return build_production_runtime(cfg)


def _pay(rt, amount):
    action = AgentAction(
        agent_id="a1",
        capability=CAP,
        timestamp=time.time(),
        arguments={"amount": amount},
    )
    return rt.engine.decide(action)


def _grant(budget=100, **extra):
    return [{"agent_id": "a1", "capability": CAP, "budget": budget, **extra}]


def test_spend_survives_restart(tmp_path, monkeypatch):
    first = _runtime(tmp_path, monkeypatch, _grant())
    assert _pay(first, 100).decision.value == "allow"
    restarted = _runtime(tmp_path, monkeypatch, _grant())
    again = _pay(restarted, 1)
    assert again.decision.value != "allow"
    assert "budget exceeded" in again.reason


def test_two_workers_share_one_budget(tmp_path, monkeypatch):
    workers = [_runtime(tmp_path, monkeypatch, _grant()) for _ in range(2)]

    class SlowPolicy:  # widen the check-then-commit window in both workers
        def check(self, **_kw):
            time.sleep(0.2)
            return PolicyCheckResult(fired=False)

    for rt in workers:
        rt.engine.engine.policy = SlowPolicy()
    verdicts: list[str] = []
    lock = threading.Lock()

    def go(rt):
        v = _pay(rt, 100).decision.value
        with lock:
            verdicts.append(v)

    threads = [threading.Thread(target=go, args=(workers[i % 2],)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert verdicts.count("allow") == 1
    grant_id = next(iter(workers[0].engine.authorizer._grants))
    assert GrantSpendLedger(tmp_path / "pv.db").spent(grant_id) == 100


def test_raising_a_budget_keeps_prior_spend(tmp_path, monkeypatch):
    first = _runtime(tmp_path, monkeypatch, _grant(budget=100))
    assert _pay(first, 60).decision.value == "allow"
    raised = _runtime(tmp_path, monkeypatch, _grant(budget=150))
    assert _pay(raised, 100).decision.value != "allow"  # 160 > 150
    assert _pay(raised, 90).decision.value == "allow"  # 150 <= 150


def test_explicit_grant_id_is_used_and_must_be_unique(tmp_path, monkeypatch):
    rt = _runtime(tmp_path, monkeypatch, _grant(grant_id="grant-treasury-01"))
    assert "grant-treasury-01" in rt.engine.authorizer._grants
    reg = GrantRegistry()
    reg.grant(agent_id="a", capability=CAP, granted_by="t", grant_id="g1")
    with pytest.raises(ValueError, match="duplicate grant_id"):
        reg.grant(agent_id="b", capability=CAP, granted_by="t", grant_id="g1")


def test_runtime_reports_durable_spend(tmp_path, monkeypatch):
    rt = _runtime(tmp_path, monkeypatch, _grant())
    assert rt.composition["authorization"]["spend"] == "durable (sqlite)"
