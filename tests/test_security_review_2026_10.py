"""Regression tests for the 2026-10 security review.

1. L2 policy: a numeric string amount must not evade a numeric rule.
2. Execution events are signed; the verifier requires their envelopes,
   rejects duplicate JSON keys, and fails an empty export.
3. Grant budget: concurrent ALLOWs cannot jointly overspend.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.policy.checker import PolicyChecker, PolicyCheckResult
from agent_dna.policy.schema import parse_policy_dict
from agent_dna.trace import AgentAction

REPO = Path(__file__).resolve().parents[1]
VERIFIER = REPO / "tools" / "verify_records.py"


def _act(agent: str, cap: str, **arguments) -> AgentAction:
    return AgentAction(
        agent_id=agent, capability=cap, timestamp=time.time(), arguments=arguments
    )


def _runtime(tmp_path, monkeypatch, *, policy=None, grants=None):
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", "payments.transfer")
    cfg = RuntimeConfig(db_path=str(tmp_path / "pv.db"))
    if policy is not None:
        p = tmp_path / "policy.json"
        p.write_text(json.dumps(policy))
        cfg.policy_file = str(p)
    if grants is not None:
        g = tmp_path / "grants.json"
        g.write_text(json.dumps(grants))
        cfg.grants_file = str(g)
    cfg.breaker_max_amount = 10_000_000
    cfg.breaker_max_refusals = None
    return build_production_runtime(cfg)


# ---- 1. policy numeric strings ---------------------------------------------

_RULE = {
    "id": "big-wire",
    "capability": "payments.transfer",
    "outcome": "block",
    "reason": "wires over 10k blocked",
    "condition": {"field": "arguments.amount", "operator": ">", "value": 10000},
}


@pytest.mark.parametrize("amount", [50000, "50000", " 50000 ", "5e4", "50000.00"])
def test_policy_numeric_string_amount_fires(amount):
    checker = PolicyChecker(parse_policy_dict({"policies": [_RULE]}))
    result = checker.check("a1", "payments.transfer", arguments={"amount": amount})
    assert result.fired and result.outcome == "block"


@pytest.mark.parametrize("amount", [500, "500", "1e2"])
def test_policy_numeric_string_below_threshold_does_not_fire(amount):
    checker = PolicyChecker(parse_policy_dict({"policies": [_RULE]}))
    result = checker.check("a1", "payments.transfer", arguments={"amount": amount})
    assert not result.fired


def test_policy_string_amount_blocks_end_to_end(tmp_path, monkeypatch):
    rt = _runtime(
        tmp_path,
        monkeypatch,
        policy={"policies": [_RULE]},
        grants=[{"agent_id": "a1", "capability": "payments.transfer", "budget": 10**6}],
    )
    for amount in (50000, "50000", "5e4"):
        r = rt.engine.decide(_act("a1", "payments.transfer", amount=amount))
        assert r.decision.value == "block", amount
        assert r.triggered_by == "policy"


# ---- 3. grant budget race --------------------------------------------------


def test_concurrent_allows_cannot_overspend_grant(tmp_path, monkeypatch):
    rt = _runtime(
        tmp_path,
        monkeypatch,
        grants=[{"agent_id": "a1", "capability": "payments.transfer", "budget": 100}],
    )

    class SlowPolicy:  # widens the check-then-spend window (e.g. OPA latency)
        def check(self, **_kw):
            time.sleep(0.2)
            return PolicyCheckResult(fired=False)

    rt.engine.engine.policy = SlowPolicy()
    verdicts: list[str] = []

    def go():
        verdicts.append(
            rt.engine.decide(_act("a1", "payments.transfer", amount=100)).decision.value
        )

    threads = [threading.Thread(target=go) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    grant = next(iter(rt.engine.authorizer._grants.values()))
    assert verdicts.count("allow") == 1
    assert grant.spent == 100


# ---- 2. signed executions + verifier hardening -----------------------------


@pytest.fixture()
def signed_export(tmp_path):
    pytest.importorskip("nacl")
    sys.path.insert(0, str(REPO / "tools"))
    try:
        from generate_test_vectors import Invariants, Scorer
    finally:
        sys.path.pop(0)
    from agent_dna.decision import DecisionEngine
    from agent_dna.decision_recorder import DecisionRecorder
    from agent_dna.signer_python import ReceiptSigner, generate_keypair
    from agent_dna.sqlite_store import SQLiteDecisionStore

    kp = generate_keypair()
    store = SQLiteDecisionStore(tmp_path / "db.sqlite")
    rec = DecisionRecorder(store=store, signer=ReceiptSigner(kp["signing_key"]))
    eng = DecisionEngine(scorer=Scorer(), invariants=Invariants())
    for cap in ("crm.read_contact", "payments.drain_account"):
        a = AgentAction(agent_id="agent-01", capability=cap, timestamp=time.time())
        d = rec.record(a, eng.decide(a, None))
        rec.report_outcome(d.decision_id, "refused")
    records = tmp_path / "records.jsonl"
    envs = tmp_path / "env.jsonl"
    store.export_jsonl(records)
    store.export_envelopes_jsonl(envs)
    return records, envs, kp["public_key"]


def _verify(records, envs, key, *extra) -> int:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(records), "--envelopes", str(envs),
         "--trusted-key", key, *extra],
        capture_output=True,
        text=True,
    ).returncode


def _lines(p: Path) -> list[str]:
    return [line for line in p.read_text().splitlines() if line.strip()]


def _rehash(d: dict) -> str:
    body = {k: v for k, v in d.items() if k != "record_hash"}
    d["record_hash"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def test_clean_signed_export_passes(signed_export):
    records, envs, key = signed_export
    assert len(_lines(envs)) == 4  # 2 decisions + 2 executions
    assert _verify(records, envs, key) == 0


def test_rehashed_execution_rewrite_fails(signed_export, tmp_path):
    records, envs, key = signed_export
    out = []
    for line in _lines(records):
        rec = json.loads(line)
        if rec["kind"] == "execution":
            rec["status"] = "ok"
            out.append(_rehash(rec))
        else:
            out.append(line)
    forged = tmp_path / "forged.jsonl"
    forged.write_text("\n".join(out) + "\n")
    assert _verify(forged, envs, key) == 1


def test_deleted_execution_with_envelope_left_fails(signed_export, tmp_path):
    records, envs, key = signed_export
    kept = [ln for ln in _lines(records) if json.loads(ln)["kind"] != "execution"]
    forged = tmp_path / "forged.jsonl"
    forged.write_text("\n".join(kept) + "\n")
    assert _verify(forged, envs, key) == 1


def test_execution_envelope_stripped_fails_unless_legacy_flag(signed_export, tmp_path):
    records, envs, key = signed_export
    dec_hashes = {
        json.loads(ln)["record_hash"]
        for ln in _lines(records)
        if json.loads(ln)["kind"] == "decision"
    }
    only_dec = [ln for ln in _lines(envs) if json.loads(ln)["signed_hash"] in dec_hashes]
    stripped = tmp_path / "env_stripped.jsonl"
    stripped.write_text("\n".join(only_dec) + "\n")
    assert _verify(records, stripped, key) == 1
    assert _verify(records, stripped, key, "--allow-unsigned-executions") == 0


def test_duplicate_json_keys_rejected(signed_export, tmp_path):
    records, envs, key = signed_export
    lines = _lines(records)
    lines[0] = lines[0][:-1] + ',"kind":"decision"}'
    forged = tmp_path / "dup.jsonl"
    forged.write_text("\n".join(lines) + "\n")
    assert _verify(forged, envs, key) == 1


def test_empty_export_fails(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    r = subprocess.run(
        [sys.executable, str(VERIFIER), str(empty)], capture_output=True, text=True
    )
    assert r.returncode == 1
