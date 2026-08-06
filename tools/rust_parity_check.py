#!/usr/bin/env python3
"""Cross-implementation parity gate: seal the SAME record in Python
(agent_dna, source of truth) and in Rust (pv_runtime), assert the
record_hash is byte-identical. Includes unicode + float landmines.

Run after `maturin develop` in rust/:
    python tools/rust_parity_check.py
Exit 0 = parity. Exit 1 = the chains would fork; Rust is wrong.
"""

import json
import sys

sys.path.insert(0, ".")

from agent_dna.decision_record import DRP_V01, DRP_V02
from agent_dna.decision_record import DecisionRecord as PyDecision
from agent_dna.execution_record import ExecutionEvent as PyExec

try:
    import pv_runtime
except ImportError:
    print("FAIL: pv_runtime not built. cd rust && maturin develop")
    sys.exit(1)

GENESIS = "0" * 64
FAILURES = []
HASHES = {}


def check(name, py_hash, rs_hash):
    ok = py_hash == rs_hash
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"         python: {py_hash}")
        print(f"         rust  : {rs_hash}")
        FAILURES.append(name)
    HASHES[name] = (py_hash, rs_hash)


def decision_case(name, **kw):
    evidence = kw.pop("evidence", [])
    edges = kw.pop("edges", [])
    version = kw.pop("protocol_version", DRP_V01)
    action_digest = kw.pop("action_digest", None)

    py = PyDecision(
        protocol_version=version,
        action_digest=action_digest,
        decision_id=kw["decision_id"],
        parent_decision=kw.get("parent_decision"),
        agent_id=kw["agent_id"],
        capability=kw["capability"],
        decision=kw["decision"],
        triggered_by=kw["triggered_by"],
        reason=kw.get("reason", ""),
        severity=kw.get("severity", "none"),
        drift_score=kw.get("drift_score", 0.0),
        evidence=evidence,
        evidence_strength=kw.get("evidence_strength", 0.0),
        arguments_digest=kw.get("arguments_digest", ""),
        outcome=kw.get("outcome", "pending"),
        request_id=kw.get("request_id"),
        edges=edges,
        timestamp=kw["timestamp"],
        prev_hash=kw.get("prev_hash", GENESIS),
    ).seal()

    rs = pv_runtime.DecisionRecord(
        protocol_version=version,
        action_digest=action_digest,
        decision_id=kw["decision_id"],
        agent_id=kw["agent_id"],
        capability=kw["capability"],
        decision=kw["decision"],
        triggered_by=kw["triggered_by"],
        timestamp=kw["timestamp"],
        parent_decision=kw.get("parent_decision"),
        prev_hash=kw.get("prev_hash", GENESIS),
        reason=kw.get("reason", ""),
        severity=kw.get("severity", "none"),
        drift_score=kw.get("drift_score", 0.0),
        evidence_json=json.dumps(evidence),
        evidence_strength=kw.get("evidence_strength", 0.0),
        arguments_digest=kw.get("arguments_digest", ""),
        outcome=kw.get("outcome", "pending"),
        request_id=kw.get("request_id"),
        edges_json=json.dumps(edges),
    )
    rs.seal()
    check(name, py.record_hash, rs.record_hash)


def execution_case(name, **kw):
    edges = kw.pop("edges", [])
    py = PyExec(
        event_id=kw["event_id"],
        agent_id=kw["agent_id"],
        decision_ref=kw["decision_ref"],
        status=kw["status"],
        detail=kw.get("detail", ""),
        edges=edges,
        timestamp=kw["timestamp"],
        prev_hash=kw["prev_hash"],
    ).seal()

    rs = pv_runtime.ExecutionEvent(
        event_id=kw["event_id"],
        agent_id=kw["agent_id"],
        decision_ref=kw["decision_ref"],
        status=kw["status"],
        detail=kw.get("detail", ""),
        timestamp=kw["timestamp"],
        prev_hash=kw["prev_hash"],
        edges_json=json.dumps(edges),
    )
    rs.seal()
    check(name, py.record_hash, rs.record_hash)


print("DecisionRecord parity:")
decision_case(
    "baseline allow",
    decision_id="d-0001",
    agent_id="sales-agent-01",
    capability="crm.read_contact",
    decision="allow",
    triggered_by="baseline",
    reason="within trusted manifold",
    severity="none",
    drift_score=0.0,
    timestamp=1751700000.0,
)
decision_case(
    "block w/ evidence + edges + parent",
    decision_id="d-0002",
    parent_decision="d-0001",
    agent_id="sales-agent-01",
    capability="storage.bulk_export",
    decision="block",
    triggered_by="invariant",
    reason="storage.bulk_export is contractually forbidden",
    severity="critical",
    drift_score=0.9,
    evidence=[
        {
            "check": "invariant",
            "detail": "forbidden capability",
            "weight": 1.0,
            "count": 3,
        }
    ],
    evidence_strength=1.0,
    arguments_digest="ab" * 32,
    edges=[{"type": "follows", "target": "d-0001"}],
    timestamp=1751700000.123,
    prev_hash="cd" * 32,
)
decision_case(
    "unicode reason (ensure_ascii fork check)",
    decision_id="d-0003",
    agent_id="agent-é-😀",
    capability="email.send",
    decision="allow",
    triggered_by="baseline",
    reason='approuvé — señal 😀 \n\t"quoted"',
    drift_score=0.25,
    timestamp=1751700000.0,
)
decision_case(
    "float landmines (1e17 / 1e-5 fork check)",
    decision_id="d-0004",
    agent_id="a",
    capability="x",
    decision="allow",
    triggered_by="drift",
    drift_score=1e-5,
    evidence_strength=1e17 * 1.0,
    evidence=[{"v": 1e16, "w": 0.0001, "neg": -2.5e-7}],
    timestamp=1e15,
)

# drp/0.2. The digest is inside the hashed payload, so the two records
# below must differ in BOTH implementations: if action_digest were
# decoration rather than a binding, these would collide.
_BOUND = "sha256:" + "3f" * 32
_OTHER = "sha256:" + "7c" * 32

decision_case(
    "v0.2 bound to an execution action",
    protocol_version=DRP_V02,
    action_digest=_BOUND,
    decision_id="d-0101",
    agent_id="service-agent-07",
    capability="refunds.issue",
    decision="allow",
    triggered_by="baseline",
    reason="within standing grant",
    severity="none",
    drift_score=0.0,
    timestamp=1785000000.0,
)

decision_case(
    "v0.2 differing only in action_digest",
    protocol_version=DRP_V02,
    action_digest=_OTHER,
    decision_id="d-0101",
    agent_id="service-agent-07",
    capability="refunds.issue",
    decision="allow",
    triggered_by="baseline",
    reason="within standing grant",
    severity="none",
    drift_score=0.0,
    timestamp=1785000000.0,
)

decision_case(
    "v0.1 alongside v0.2, same fields otherwise",
    decision_id="d-0101",
    agent_id="service-agent-07",
    capability="refunds.issue",
    decision="allow",
    triggered_by="baseline",
    reason="within standing grant",
    severity="none",
    drift_score=0.0,
    timestamp=1785000000.0,
)

# Agreement alone is not enough. If action_digest were decoration rather
# than part of the hashed payload, both implementations could agree on a
# single hash for all three variants below -- and every case above would
# still report PASS.
_DISTINCT = [
    "v0.2 bound to an execution action",
    "v0.2 differing only in action_digest",
    "v0.1 alongside v0.2, same fields otherwise",
]
for _side, _label in ((0, "python"), (1, "rust")):
    _seen = {HASHES[n][_side] for n in _DISTINCT if n in HASHES}
    _ok = len(_seen) == len(_DISTINCT)
    print(
        f"  [{'PASS' if _ok else 'FAIL'}] {_label}: version and digest reach the hash"
    )
    if not _ok:
        FAILURES.append(f"{_label} collision across version/digest variants")

print("ExecutionEvent parity:")
execution_case(
    "ok outcome",
    event_id="e-0001",
    agent_id="sales-agent-01",
    decision_ref="d-0001",
    status="ok",
    detail="executed",
    timestamp=1751700001.0,
    prev_hash="ef" * 32,
)
execution_case(
    "refused w/ edges + unicode",
    event_id="e-0002",
    agent_id="sales-agent-01",
    decision_ref="d-0002",
    status="refused",
    detail="runtime refused — señal",
    edges=[{"type": "reports_on", "target": "d-0002"}],
    timestamp=1751700002.5,
    prev_hash="0a" * 32,
)

print()
if FAILURES:
    print(f"PARITY: FAIL ({len(FAILURES)} forked vector(s)) — Rust is wrong, fix Rust")
    sys.exit(1)
print("PARITY: PASS — Rust and Python hashes are byte-identical")
