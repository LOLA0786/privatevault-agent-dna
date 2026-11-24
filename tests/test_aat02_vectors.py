"""Replay PrivateVault's AAT -02 vectors (vectors/aat02/pv-delegation-2.json)
through the real pv-delegation/2 code: ``within_scope``, which runs
``verify_chain`` first, under the suite's trust anchors. One test replays
them all and names every disagreement, as CleiMesh's draft -02 harness does.
Regenerate the suite with tools/gen_aat02_vectors.py; docs/AAT02-VECTORS.md
says what it covers and what it does not."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import re
from pathlib import Path
from typing import Any

from agent_dna.multi_agent_security import delegation as dl

ROOT = Path(__file__).resolve().parent.parent
SUITE_PATH = ROOT / "vectors" / "aat02" / "pv-delegation-2.json"

# PrivateVault's refusal messages, reduced to stable reason codes. The most
# specific pattern comes first.
REASONS = [
    (r"^delegation_in_scope", "in_scope"),
    (r"chain is deeper than", "chain_too_deep"),
    (r"a root link has no parent", "root_has_parent"),
    (r"is not a pinned root authority", "untrusted_root"),
    (r"but the authority was held by", "holder_mismatch"),
    (r"does not name the link before it", "parent_mismatch"),
    (r"has no pinned agent key", "unknown_agent"),
    (r"was not allowed to delegate further", "may_not_delegate"),
    (r"may not delegate further \(max_depth reached\)", "depth_exhausted"),
    (r"max_depth \S+ widens", "depth_widened"),
    (r"capability .* widens", "scope_widened"),
    (r"max_amount \S+ widens", "amount_widened"),
    (r"budget \S+ widens", "budget_widened"),
    (r"constraint .* widens", "constraint_widened"),
    (r"outlives the link it was derived from", "outlives_parent"),
    (r"issued before the link it derives from", "issued_before_parent"),
    (r"already appears in the chain", "cycle"),
    (r"signature does not verify", "bad_signature"),
    (r"link \d+: revoked", "revoked"),
    (r"is revoked", "agent_revoked"),
    (r"issued in the future", "issued_in_future"),
    (r"link \d+: expired", "expired"),
    (r"^delegation_not_yours", "not_final_delegate"),
    (r"^delegation_out_of_scope", "out_of_scope"),
    (r"^delegation_constraint_violated", "constraint_violated"),
]


def suite() -> dict[str, Any]:
    return json.loads(SUITE_PATH.read_text(encoding="utf-8"))


def reason_code(message: str) -> str:
    for pattern, code in REASONS:
        if re.search(pattern, message):
            return code
    return f"unclassified: {message}"


def replay(
    vector: dict[str, Any], anchors_in: list[dict[str, str]]
) -> tuple[str, str, str]:
    by_role = {
        role: {
            a["name"]: a["ed25519_public_key_hex"]
            for a in anchors_in
            if a["role"] == role
        }
        for role in ("root", "agent")
    }
    anchors = dl.TrustAnchors(
        roots=by_role["root"],
        agents=by_role["agent"],
        revoked=frozenset(vector["policy"].get("revoked", [])),
    )
    links = [entry["link"] for entry in vector["chain"]]
    decision = dl.within_scope(
        links,
        anchors,
        agent_id=vector["policy"].get("agent_id", links[-1]["delegate"]),
        capability=vector["tool"],
        now=vector["now"],
        arguments=json.loads(vector["args_json"]),
    )
    return (
        ("PERMIT" if decision.allowed else "DENY"),
        reason_code(decision.reason),
        decision.reason,
    )


def disagreements(data: dict[str, Any]) -> list[str]:
    out = []
    for v in data["vectors"]:
        verdict, code, message = replay(v, data["trust_anchors"])
        want = v["expected"]
        if (verdict, code) != (want["verdict"], want["reason"]):
            out.append(
                f"{v['id']} {v['title']!r}: expected {want['verdict']}/{want['reason']}, "
                f"got {verdict}/{code} ({message})"
            )
    return out


def test_every_vector_agrees():
    data = suite()
    failed = disagreements(data)
    total = len(data["vectors"])
    print(f"pv-delegation/2 AAT -02 vectors: {total - len(failed)}/{total} agree")
    assert not failed, f"{len(failed)} of {total} vectors disagree:\n" + "\n".join(
        failed
    )


def test_negative_control_a_wrong_expectation_is_caught():
    data = suite()
    data["vectors"] = [copy.deepcopy(data["vectors"][0])]
    data["vectors"][0]["expected"] = {"verdict": "DENY", "reason": "in_scope"}
    assert len(disagreements(data)) == 1


def test_suite_is_regenerated_from_the_code():
    spec = importlib.util.spec_from_file_location(
        "gen_aat02", ROOT / "tools" / "gen_aat02_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert SUITE_PATH.read_text(encoding="utf-8") == gen.render(), (
        "stale: run python tools/gen_aat02_vectors.py"
    )


def _b64url(digest_hex: str) -> str:
    return base64.urlsafe_b64encode(bytes.fromhex(digest_hex)).rstrip(b"=").decode()


def test_each_aat_view_describes_its_link():
    for v in suite()["vectors"]:
        for entry in v["chain"]:
            view, link = entry["aat"], entry["link"]
            where = f"{v['id']} {link['delegator']}->{link['delegate']}"
            assert (view["pv_delegator"], view["pv_delegate"]) == (
                link["delegator"],
                link["delegate"],
            ), where
            assert (view["iat"], view["exp"]) == (
                link["issued_at"],
                link["expires_at"],
            ), where
            assert view.get("par_hash") == (
                _b64url(link["parent"]) if link["parent"] else None
            ), where
            depth = link.get("max_depth")
            assert view.get("del_max_depth") == (
                None if depth is None else view["del_depth"] + depth
            ), where
            tools = view["authorization_details"][0]["tools"]
            assert sorted(tools) == sorted(link["capabilities"]), where
            assert view.get("pv_budget") == link.get("budget"), where


def test_covers_every_required_case():
    vectors = suite()["vectors"]
    ids = [v["id"] for v in vectors]
    assert ids == [f"PV.{i}" for i in range(1, len(ids) + 1)]
    reasons = {v["expected"]["reason"] for v in vectors}
    required = {
        "in_scope",
        "budget_widened",
        "scope_widened",
        "constraint_widened",
        "depth_exhausted",
        "depth_widened",
        "chain_too_deep",
        "parent_mismatch",
        "root_has_parent",
        "holder_mismatch",
        "revoked",
        "bad_signature",
        "untrusted_root",
        "constraint_violated",
    }
    assert required <= reasons, required - reasons
    cases = {v.get("interpretations", {}).get("case") for v in vectors}
    assert {"constraint-comparison CC-1", "constraint-comparison CC-3"} <= cases
