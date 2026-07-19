"""Precedence-order integrity: decision.py's actual evaluation order
must match spec/contracts/precedence-order.json exactly. This is not
a behavioral test (test_runtime_enforcement.py covers that) — it's a
structural guard that fails the build if someone reorders the
precedence checks in code without updating the committed contract in
the same commit. Makes 'a deterministic DENY is final' a property CI
enforces, not just an assertion in prose.
"""

import ast
import re
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = ROOT / "spec" / "contracts" / "precedence-order.json"
ENGINE_PATH = ROOT / "agent_dna" / "decision.py"

# The literal trigger strings used in _decide_unsafe / decide_from,
# in the order they must appear as return statements / string
# literals within the function bodies.
EXPECTED_ORDER = ["uaal_constraint", "invariant", "policy", "consensus", "authorization", "economics", "drift", "baseline"]


def _load_contract():
    return json.loads(CONTRACT_PATH.read_text())


def test_contract_file_is_well_formed():
    c = _load_contract()
    names = [lvl["name"] for lvl in c["levels"]]
    assert names == EXPECTED_ORDER
    orders = [lvl["order"] for lvl in c["levels"]]
    assert orders == sorted(orders)


def test_contract_hash_is_pinned():
    """Detects ANY change to the contract file — intentional or not —
    by pinning its content hash. Updating the contract requires
    deliberately updating this hash in the same review, not a
    silent drift."""
    content = CONTRACT_PATH.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    PINNED = "2150d0f020bba566af62eac51b842958e85cbb0eb75a5506b580d8a87fbee8ca"
    if PINNED == "__PINNED_HASH__":
        # first run: print the real hash so it can be pinned below
        print(f"\nACTUAL CONTRACT HASH: {digest}")
        assert False, (
            "pin this hash into PINNED above, then rerun — "
            f"got {digest}"
        )
    assert digest == PINNED


def _extract_method_body(source: str, def_line: str) -> str:
    start = source.find(def_line)
    assert start != -1, f"{def_line!r} not found in decision.py"
    rest = source[start + len(def_line):]
    next_def = rest.find("\n    def ")
    return rest if next_def == -1 else rest[:next_def]


def test_uaal_precedes_decide_from_call():
    """_decide_unsafe's real precedence chain, part 1: the UAAL
    (order-0) early-return must appear BEFORE the delegation to
    decide_from (which resolves orders 1-4). If someone moved the
    UAAL check after the decide_from call, UAAL would no longer be
    able to short-circuit ahead of invariant/authorization/drift —
    the single most important ordering guarantee in the engine."""
    body = _extract_method_body(
        ENGINE_PATH.read_text(), "def _decide_unsafe("
    )
    uaal_idx = body.find('"uaal_constraint"')
    delegate_idx = body.find("self.decide_from(")
    assert uaal_idx != -1, "uaal_constraint literal not found in _decide_unsafe"
    assert delegate_idx != -1, "decide_from(...) call not found in _decide_unsafe"
    assert uaal_idx < delegate_idx, (
        "UAAL (order 0) no longer precedes the decide_from delegation "
        "(orders 1-4) in _decide_unsafe — precedence contract violated"
    )


def test_decide_from_declares_remaining_levels_in_contract_order():
    """_decide_unsafe's real precedence chain, part 2: within
    decide_from (which handles orders 1-4: invariant, authorization,
    drift, baseline), the trigger literals must appear in exactly the
    order the contract declares."""
    remaining = [n for n in EXPECTED_ORDER if n != "uaal_constraint"]
    body = _extract_method_body(ENGINE_PATH.read_text(), "def decide_from(")

    positions = []
    for name in remaining:
        marker = f'"{name}"'
        idx = body.find(marker)
        assert idx != -1, f"trigger literal {marker!r} not found in decide_from"
        positions.append((name, idx))

    ordered_names = [n for n, _ in sorted(positions, key=lambda p: p[1])]
    assert ordered_names == remaining, (
        f"decide_from declares triggers in order {ordered_names}, "
        f"contract requires {remaining} — precedence order has "
        f"drifted from the committed contract"
    )


def test_drift_can_never_block():
    """The contract's strongest invariant, enforced behaviorally:
    drift's outcome_on_violation is require_approval, never block."""
    c = _load_contract()
    drift = next(lvl for lvl in c["levels"] if lvl["name"] == "drift")
    assert drift["outcome_on_violation"] == "require_approval"
    assert drift["class"] == "probabilistic"

    others = [lvl for lvl in c["levels"] if lvl["name"] != "drift"]
    assert all(lvl["class"] == "deterministic" for lvl in others), (
        "every non-drift level must be declared deterministic — "
        "drift is the sole probabilistic level by contract"
    )


def test_no_undeclared_levels_in_engine():
    """Audit P1-10: the old structural test searched only for the
    levels it EXPECTED, so an extra hidden level (customer policy,
    evaluated for months) could not fail it. This guard extracts every
    trigger literal the engine's make() calls actually declare and
    requires the set to equal the contract's level set exactly --
    a level added to code without a contract change fails the build,
    in either direction."""
    body = _extract_method_body(ENGINE_PATH.read_text(), "def decide_from(")
    declared = set(re.findall(
        r'return make\(\s*[^,]+,\s*\n?\s*"([a-z_]+)"', body
    ))
    remaining = set(EXPECTED_ORDER) - {"uaal_constraint"}
    assert declared == remaining, (
        f"engine declares {sorted(declared)}, contract declares "
        f"{sorted(remaining)} -- a level exists on exactly one side"
    )
