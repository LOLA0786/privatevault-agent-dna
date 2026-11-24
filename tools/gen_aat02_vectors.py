"""Generate PrivateVault's delegation conformance vectors (pv-delegation/2,
ADR 0042) in the layout of the AAT -02 JWS test suite.

    uv run python tools/gen_aat02_vectors.py           # write the suite
    uv run python tools/gen_aat02_vectors.py --check   # fail if it is stale

The layout follows tenuo-ai/tenuo ``tests/vectors/aat-jws-vectors.json``
(draft-niyikiza-oauth-attenuating-agent-tokens-02), the 229-vector suite that
CleiMesh's ``cleimesh-aat/tests/vectors_02.rs`` replays: suite-level ``spec``,
``conventions``, ``params``, ``keys`` and ``trust_anchors``, then ``vectors``,
each with ``id``, ``title``, ``description``, ``notes``, ``now``, ``tool``,
``args``, ``args_json``, ``policy``, ``params``, ``replay_state``, ``chain``
and ``expected``.

The tokens are not AAT JWS. Each chain is real pv-delegation/2 links, issued
by ``agent_dna.multi_agent_security.delegation.issue_link`` and signed with
deterministic Ed25519 test keys. Each link also carries its AAT -02 view
(``del_depth``, ``del_max_depth``, ``par_hash``, ``authorization_details``),
so the scenario can be read beside the AAT suite: a property-level export, as
the AAT interop guide describes for implementations in another format.

Expected verdicts are written here from the design, never computed by running
the code; ``tests/test_aat02_vectors.py`` replays every vector through
``verify_chain`` and ``within_scope`` and fails on any disagreement.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_dna.multi_agent_security import delegation as dl  # noqa: E402

OUT = ROOT / "vectors" / "aat02" / "pv-delegation-2.json"
AAT_SPEC = "draft-niyikiza-oauth-attenuating-agent-tokens-02"
NOW = 1704067500  # the AAT -02 suite's default "now"
IAT = 1704067200
EXP = IAT + 3600
TOOL = "payments.refund.issue"
OTHER_TOOL = "payments.payout.create"
MERCHANTS = ["M-101", "M-102"]
PARTIES = ["operator"] + [f"agent-{i}" for i in range(1, 11)]
UNPINNED = ("mallory", "rogue-root")


# ------------------------------------------------------------------ keys
def seed(name: str) -> str:
    """Deterministic test key: never use outside these vectors."""
    return hashlib.sha256(b"pv-aat02-vectors/" + name.encode()).hexdigest()


def public_key(name: str) -> str:
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey

    key = SigningKey(seed(name).encode(), encoder=HexEncoder)
    return key.verify_key.encode(encoder=HexEncoder).decode()


def sign(link: dict[str, Any], signer: str) -> dict[str, Any]:
    """Sign as ``issue_link`` does: Ed25519 over ``link_hash``."""
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey

    body = {k: v for k, v in link.items() if k != "signature"}
    key = SigningKey(seed(signer).encode(), encoder=HexEncoder)
    body["signature"] = key.sign(dl.link_hash(body).encode()).signature.hex()
    return body


# ----------------------------------------------------------------- chains
def b64url(digest_hex: str) -> str:
    return base64.urlsafe_b64encode(bytes.fromhex(digest_hex)).rstrip(b"=").decode()


def aat_view(link: dict[str, Any], depth: int) -> dict[str, Any]:
    """The AAT -02 claims this link corresponds to, at the depth it was
    issued at (a reordered or spliced link keeps its own depth)."""
    cmap = {
        name: {"constraint_type": "one_of", "values": values}
        for name, values in (link.get("constraints") or {}).items()
    }
    view: dict[str, Any] = {
        "pv_delegator": link["delegator"],
        "pv_delegate": link["delegate"],
        "iat": link["issued_at"],
        "exp": link["expires_at"],
        "del_depth": depth,
        "authorization_details": [
            {
                "type": "attenuating_agent_token",
                "tools": {tool: dict(cmap) for tool in link["capabilities"]},
            }
        ],
    }
    if link.get("max_depth") is not None:
        view["del_max_depth"] = depth + link["max_depth"]
    if link["parent"] is not None:
        view["par_hash"] = b64url(link["parent"])
    if link.get("budget") is not None:
        view["pv_budget"] = link["budget"]
    return view


def mint(
    delegator: str,
    delegate: str,
    tag: str,
    *,
    parent: dict[str, Any] | None = None,
    signer: str | None = None,
    caps: list[str] | None = None,
    budget: int | None = None,
    constraints: dict[str, list[str]] | None = None,
    max_depth: int | None = None,
    may_delegate: bool = True,
    exp: int = EXP,
    clamp: bool = True,
) -> dict[str, Any]:
    link = dl.issue_link(
        seed(delegator),
        delegator=delegator,
        delegate=delegate,
        capabilities=caps or [TOOL],
        ttl=float(exp - IAT),
        may_delegate=may_delegate,
        parent=parent,
        clamp_to_parent=clamp,
        now=float(IAT),
        budget=budget,
        constraints=constraints,
        max_depth=max_depth,
    )
    link["nonce"] = hashlib.sha256(tag.encode()).hexdigest()[:32]
    return sign(link, signer or delegator)


def chain(tag: str, hops: list[dict[str, Any]]) -> list[tuple[dict[str, Any], int]]:
    """operator -> agent-1 -> agent-2 ...; each hop's kwargs go to ``mint``.
    Returns (link, depth issued at) pairs."""
    out: list[tuple[dict[str, Any], int]] = []
    for i, hop in enumerate(hops):
        hop = dict(hop)
        hop.setdefault("may_delegate", i < len(hops) - 1)
        parent = out[-1][0] if out else None
        out.append(
            (mint(PARTIES[i], PARTIES[i + 1], f"{tag}/{i}", parent=parent, **hop), i)
        )
    return out


def base_hops() -> list[dict[str, Any]]:
    """Every limit narrows at each hop: scope, budget, arguments, depth."""
    return [
        {
            "caps": [TOOL, OTHER_TOOL],
            "budget": 100000,
            "constraints": {"merchant": MERCHANTS, "currency": ["INR"]},
            "max_depth": 2,
        },
        {
            "budget": 50000,
            "constraints": {"merchant": ["M-101"], "currency": ["INR"]},
            "max_depth": 1,
        },
        {
            "budget": 20000,
            "constraints": {"merchant": ["M-101"], "currency": ["INR"]},
            "max_depth": 0,
        },
    ]


def depth_hops(limit: int, links: int) -> list[dict[str, Any]]:
    """A chain of ``links`` links under a root depth limit of ``limit``,
    each child taking the most the rules allow."""
    return [{"max_depth": max(limit - i, 0), "budget": 1000} for i in range(links)]


ARGS = {"merchant": "M-101", "currency": "INR"}


# ---------------------------------------------------------------- vectors
def vec(
    vid,
    title,
    description,
    pairs,
    *,
    verdict,
    reason,
    aat,
    args=None,
    tool=TOOL,
    notes=(),
    policy=None,
    now=NOW,
    interpretations=None,
):
    args = ARGS if args is None else args
    vector = {
        "id": vid,
        "title": title,
        "description": description,
        "notes": list(notes),
        "now": now,
        "tool": tool,
        "args": args,
        "args_json": json.dumps(args, sort_keys=True, separators=(",", ":")),
        "policy": policy or {},
        "params": {},
        "replay_state": None,
        "chain": [
            {"aat": aat_view(link, depth), "link": link} for link, depth in pairs
        ],
        "expected": {"verdict": verdict, "reason": reason},
        "aat_02": aat,
    }
    if interpretations:
        vector["interpretations"] = interpretations
    return vector


def aat(
    verdict: str, step: str | None = None, note: str | None = None
) -> dict[str, Any]:
    out: dict[str, Any] = {"verdict": verdict, "step": step}
    if note:
        out["note"] = note
    return out


NO_BUDGET = aat(
    "n/a", note="AAT -02 has no cumulative budget; pv_budget is PrivateVault's."
)


def vectors() -> list[dict[str, Any]]:
    good = chain("good", base_hops())
    out = []

    # --- valid narrowing ------------------------------------------------
    out.append(
        vec(
            "PV.1",
            "Every limit narrows at every hop",
            "Scope, budget, argument values and depth each narrow from root to leaf.",
            good,
            verdict="PERMIT",
            reason="in_scope",
            aat=aat("PERMIT"),
        )
    )
    eq = base_hops()
    eq[0]["caps"] = [TOOL]
    eq[1] = {
        "budget": 100000,
        "constraints": {"merchant": MERCHANTS, "currency": ["INR"]},
        "max_depth": 1,
    }
    eq[2] = {
        "budget": 100000,
        "constraints": {"merchant": MERCHANTS, "currency": ["INR"]},
        "max_depth": 0,
    }
    out.append(
        vec(
            "PV.2",
            "Children keep their parent's limits unchanged",
            "An equal budget, scope and value set is narrowing; depth still drops by one.",
            chain("equal", eq),
            verdict="PERMIT",
            reason="in_scope",
            aat=aat("PERMIT"),
        )
    )
    out.append(
        vec(
            "PV.3",
            "A root link alone",
            "A one-link chain at depth 0, used inside its own limits.",
            chain("root", base_hops()[:1]),
            verdict="PERMIT",
            reason="in_scope",
            aat=aat("PERMIT"),
            args={"merchant": "M-102", "currency": "INR"},
        )
    )

    # --- widening ---------------------------------------------------------
    h = base_hops()
    h[1]["budget"] = 150000
    out.append(
        vec(
            "PV.4",
            "Widened budget",
            "Link 1 raises the budget from 100000 to 150000.",
            chain("budget-up", h),
            verdict="DENY",
            reason="budget_widened",
            aat=NO_BUDGET,
        )
    )
    h = base_hops()
    h[1]["budget"] = None
    out.append(
        vec(
            "PV.5",
            "Dropped budget",
            "Link 1 carries no budget under a parent budget of 100000.",
            chain("budget-drop", h),
            verdict="DENY",
            reason="budget_widened",
            aat=NO_BUDGET,
        )
    )
    h = base_hops()
    h[0]["caps"] = [TOOL]
    h[1]["caps"] = [TOOL, OTHER_TOOL]
    out.append(
        vec(
            "PV.6",
            "Widened scope",
            "Link 1 adds a tool its parent was not given.",
            chain("scope-up", h),
            verdict="DENY",
            reason="scope_widened",
            aat=aat("DENY", "4p1"),
        )
    )
    h = base_hops()
    h[1]["constraints"] = {"merchant": ["M-101", "M-999"], "currency": ["INR"]}
    out.append(
        vec(
            "PV.7",
            "Added argument value",
            "Link 1 allows merchant M-999, which the parent's set does not contain.",
            chain("value-up", h),
            verdict="DENY",
            reason="constraint_widened",
            aat=aat("DENY", "4p4"),
        )
    )
    h = base_hops()
    h[1]["constraints"] = {"merchant": ["M-101"]}
    out.append(
        vec(
            "PV.8",
            "Dropped argument constraint",
            "Link 1 omits the parent's currency constraint.",
            chain("constraint-drop", h),
            verdict="DENY",
            reason="constraint_widened",
            aat=aat("DENY", "4p2", "The parent's constraint is not marked optional."),
        )
    )
    h = base_hops()
    for hop in h[1:]:
        hop["constraints"] = {
            "merchant": ["M-101"],
            "currency": ["INR"],
            "region": ["IN-MH"],
        }
    out.append(
        vec(
            "PV.9",
            "Child constrains an argument its parent never named",
            "Link 1 adds a region constraint. In PrivateVault an unnamed argument is free, so naming "
            "it narrows; in AAT an unnamed argument is denied, so naming it widens.",
            chain("key-added", h),
            verdict="PERMIT",
            reason="in_scope",
            args={"merchant": "M-101", "currency": "INR", "region": "IN-MH"},
            aat=aat("DENY", "4p2"),
            interpretations={
                "aat-02": 'DENY (4p2: a child names only keys its parent names, unless the parent has "*")',
                "asor-03": "PERMIT (an input no constraint names is unbounded, so a new constraint narrows)",
                "pv-delegation/2": "PERMIT (follows asor)",
                "case": "constraint-comparison CC-3",
            },
        )
    )
    out.append(
        vec(
            "PV.10",
            "Argument no constraint names",
            "The action passes a note argument that no link constrains.",
            good,
            verdict="PERMIT",
            reason="in_scope",
            args={**ARGS, "note": "customer called"},
            aat=aat("DENY", "6b"),
            interpretations={
                "aat-02": 'DENY (6b: an input the leaf\'s map does not name, without "*")',
                "asor-03": "PERMIT (unbounded)",
                "pv-delegation/2": "PERMIT (follows asor)",
                "case": "constraint-comparison CC-3a",
            },
        )
    )

    # --- depth ------------------------------------------------------------
    out.append(
        vec(
            "PV.11",
            "Depth beyond the limit",
            "Root limit 1: link 1 is terminal (remaining 0), so link 2 exceeds del_max_depth.",
            chain("depth-over", depth_hops(1, 3)),
            verdict="DENY",
            reason="depth_exhausted",
            aat=aat("DENY", "4e"),
        )
    )
    h = base_hops()
    h[1]["max_depth"] = 2
    out.append(
        vec(
            "PV.12",
            "Child raises the depth limit",
            "Link 1 keeps 2 remaining hops under a parent with 2: del_max_depth rises from 2 to 3.",
            chain("depth-up", h),
            verdict="DENY",
            reason="depth_widened",
            aat=aat("DENY", "4g"),
        )
    )
    h = base_hops()
    h[1]["max_depth"] = None
    out.append(
        vec(
            "PV.13",
            "Child drops the depth limit",
            "Link 1 carries no depth limit under a parent with one.",
            chain("depth-drop", h),
            verdict="DENY",
            reason="depth_widened",
            aat=aat("DENY", "4b4", "del_max_depth is absent."),
        )
    )
    out.append(
        vec(
            "PV.14",
            "A terminal root delegates",
            "Root limit 0 is terminal; its child is refused.",
            chain("terminal-root", depth_hops(0, 2)),
            verdict="DENY",
            reason="depth_exhausted",
            aat=aat("DENY", "4e"),
        )
    )
    cc1 = {
        "case": "constraint-comparison CC-1",
        "aat-02": "A limit of N admits del_depth 0..N: N+1 tokens.",
        "asor-03": "A limit of N admits N tokens.",
    }
    out.append(
        vec(
            "PV.15",
            "Depth limit 3, four tokens",
            "Root limit 3 and four links (depths 0..3).",
            chain("cc1-3-4", depth_hops(3, 4)),
            verdict="PERMIT",
            reason="in_scope",
            args={},
            aat=aat("PERMIT"),
            interpretations={
                **cc1,
                "verdicts": {
                    "aat-02": "PERMIT",
                    "asor-03": "DENY",
                    "pv-delegation/2": "PERMIT",
                },
                "pv-delegation/2": "Follows AAT for the limit a link carries.",
            },
        )
    )
    out.append(
        vec(
            "PV.16",
            "Depth limit 3, five tokens",
            "Root limit 3 and five links.",
            chain("cc1-3-5", depth_hops(3, 5)),
            verdict="DENY",
            reason="depth_exhausted",
            args={},
            aat=aat("DENY", "4e"),
            interpretations={
                **cc1,
                "verdicts": {
                    "aat-02": "DENY",
                    "asor-03": "DENY",
                    "pv-delegation/2": "DENY",
                },
            },
        )
    )
    out.append(
        vec(
            "PV.17",
            "Depth limit 8, nine tokens",
            "Root limit 8 and nine links (depths 0..8). PrivateVault's cap counts delegations, "
            "as AAT's does (ADR 0048), so the format's largest limit is reachable.",
            chain("cc1-8-9", depth_hops(8, 9)),
            verdict="PERMIT",
            reason="in_scope",
            args={},
            aat=aat(
                "PERMIT",
                note="del_depth 8 <= del_max_depth 8 <= MAX_DELEGATION_DEPTH 8",
            ),
            interpretations={
                **cc1,
                "verdicts": {
                    "aat-02": "PERMIT",
                    "asor-03": "DENY",
                    "pv-delegation/2": "PERMIT",
                },
                "pv-delegation/2": "Follows AAT at the cap too (ADR 0048).",
            },
        )
    )
    out.append(
        vec(
            "PV.18",
            "Depth limit 8, eight tokens",
            "Root limit 8 and eight links (depths 0..7).",
            chain("cc1-8-8", depth_hops(8, 8)),
            verdict="PERMIT",
            reason="in_scope",
            args={},
            aat=aat("PERMIT"),
            interpretations={
                **cc1,
                "verdicts": {
                    "aat-02": "PERMIT",
                    "asor-03": "PERMIT",
                    "pv-delegation/2": "PERMIT",
                },
            },
        )
    )

    # --- par_hash -----------------------------------------------------------
    other = chain("other", base_hops())
    (l0, _), (l1, _), (l2, _) = good
    l1_other = mint(
        "agent-1",
        "agent-2",
        "wrong-parent/1",
        parent=other[0][0],
        **{k: v for k, v in base_hops()[1].items()},
    )
    out.append(
        vec(
            "PV.19",
            "Wrong par_hash",
            "Link 1 names the root of a different chain held by the same agents.",
            [(l0, 0), (l1_other, 1)],
            verdict="DENY",
            reason="parent_mismatch",
            aat=aat("DENY", "4q"),
        )
    )
    orphan = mint(
        "agent-1",
        "agent-2",
        "orphan/1",
        parent=None,
        may_delegate=False,
        **{k: v for k, v in base_hops()[1].items()},
    )
    out.append(
        vec(
            "PV.20",
            "Missing par_hash on a derived link",
            "Link 1 carries no parent.",
            [(l0, 0), (orphan, 1)],
            verdict="DENY",
            reason="parent_mismatch",
            aat=aat("DENY", "4b5"),
        )
    )
    rooted = mint(
        "operator", "agent-1", "rooted/0", parent=other[0][0], **base_hops()[0]
    )
    out.append(
        vec(
            "PV.21",
            "par_hash on the root",
            "The root link names a parent.",
            [(rooted, 0)],
            verdict="DENY",
            reason="root_has_parent",
            aat=aat("DENY", "3d"),
        )
    )
    out.append(
        vec(
            "PV.22",
            "Spliced link",
            "Link 2 comes from a different chain whose agents match.",
            [(l0, 0), (l1, 1), (other[2][0], 2)],
            verdict="DENY",
            reason="parent_mismatch",
            aat=aat("DENY", "4q"),
        )
    )
    out.append(
        vec(
            "PV.23",
            "Reordered links",
            "Links 1 and 2 swapped.",
            [(l0, 0), (l2, 2), (l1, 1)],
            verdict="DENY",
            reason="holder_mismatch",
            aat=aat(
                "DENY", "4b", "The child is not signed by the parent's holder key."
            ),
        )
    )

    # --- replay, signature, keys -------------------------------------------
    out.append(
        vec(
            "PV.24",
            "Replayed link",
            "The same link presented twice in one chain.",
            [(l0, 0), (l1, 1), (l1, 1)],
            verdict="DENY",
            reason="holder_mismatch",
            aat=aat("DENY", "2c", "Duplicate jti in the chain."),
        )
    )
    out.append(
        vec(
            "PV.25",
            "Revoked link presented again",
            "Link 1's hash is on the revocation list.",
            good,
            verdict="DENY",
            reason="revoked",
            policy={"revoked": [dl.link_hash(l1)]},
            aat=aat(
                "n/a", note="Revocation is outside the -02 verification algorithm."
            ),
        )
    )
    out.append(
        vec(
            "PV.26",
            "Expired chain presented again",
            "Presented at the root's expiry.",
            good,
            verdict="DENY",
            reason="expired",
            now=EXP,
            aat=aat("DENY", "3e"),
        )
    )
    forged = dict(l1)
    forged["signature"] = l1["signature"][:-1] + (
        "0" if l1["signature"][-1] != "0" else "1"
    )
    out.append(
        vec(
            "PV.27",
            "Forged signature",
            "One hex digit of link 1's signature changed.",
            [(l0, 0), (forged, 1), (l2, 2)],
            verdict="DENY",
            reason="bad_signature",
            aat=aat("DENY", "4b"),
        )
    )
    wrong_key = sign(l1, "mallory")
    out.append(
        vec(
            "PV.28",
            "Signed with the wrong key",
            "Link 1 says agent-1 delegated, but an unpinned key signed it.",
            [(l0, 0), (wrong_key, 1)],
            verdict="DENY",
            reason="bad_signature",
            aat=aat("DENY", "4b"),
        )
    )
    rogue = mint("rogue-root", "agent-1", "rogue/0", **base_hops()[0])
    out.append(
        vec(
            "PV.29",
            "Root not pinned",
            "The root's delegator is not a trust anchor.",
            [(rogue, 0)],
            verdict="DENY",
            reason="untrusted_root",
            aat=aat("DENY", "3b"),
        )
    )
    tampered = dict(l1)
    tampered["budget"] = 40000
    out.append(
        vec(
            "PV.30",
            "Field changed after signing",
            "Link 1's budget lowered after it was signed: still narrower, but the signature no longer covers it.",
            [(l0, 0), (tampered, 1), (l2, 2)],
            verdict="DENY",
            reason="bad_signature",
            aat=aat("DENY", "4b"),
        )
    )
    late = mint(
        "agent-1",
        "agent-2",
        "late/1",
        parent=l0,
        exp=EXP + 600,
        clamp=False,
        may_delegate=False,
        **{k: v for k, v in base_hops()[1].items()},
    )
    out.append(
        vec(
            "PV.31",
            "Child outlives its parent",
            "Link 1 expires ten minutes after the root.",
            [(l0, 0), (late, 1)],
            verdict="DENY",
            reason="outlives_parent",
            aat=aat("DENY", "4h"),
        )
    )

    # --- constrained arguments at the leaf -----------------------------------
    out.append(
        vec(
            "PV.32",
            "Swapped constrained argument",
            "Merchant M-102: the root allows it, link 1 narrowed it away.",
            good,
            verdict="DENY",
            reason="constraint_violated",
            args={"merchant": "M-102", "currency": "INR"},
            aat=aat("DENY", "6b"),
        )
    )
    out.append(
        vec(
            "PV.33",
            "Omitted constrained argument",
            "No currency argument.",
            good,
            verdict="DENY",
            reason="constraint_violated",
            args={"merchant": "M-101"},
            aat=aat("DENY", "6b", "The constraint is not marked optional."),
        )
    )
    out.append(
        vec(
            "PV.34",
            "Tool outside the leaf's scope",
            "The root allows payouts; the leaf does not.",
            good,
            verdict="DENY",
            reason="out_of_scope",
            tool=OTHER_TOOL,
            aat=aat("DENY", "6b"),
        )
    )
    out.append(
        vec(
            "PV.35",
            "Presented by an agent that is not the leaf",
            "agent-2 presents the chain that ends at agent-3.",
            good,
            verdict="DENY",
            reason="not_final_delegate",
            policy={"agent_id": "agent-2"},
            aat=aat("DENY", "7b", "The PoP is not signed by the leaf's holder key."),
        )
    )
    out.append(
        vec(
            "PV.36",
            "Depth limit 8, ten tokens",
            "Root limit 8 and ten links: one delegation past the cap.",
            chain("cc1-8-10", depth_hops(8, 10)),
            verdict="DENY",
            reason="chain_too_deep",
            args={},
            aat=aat("DENY", "4e"),
            interpretations={
                **cc1,
                "verdicts": {
                    "aat-02": "DENY",
                    "asor-03": "DENY",
                    "pv-delegation/2": "DENY",
                },
            },
        )
    )
    return out


def suite() -> dict[str, Any]:
    return {
        "spec": dl.SPEC_V2,
        "profile_of": AAT_SPEC,
        "conventions": {
            "verdict": "PERMIT or DENY, as in the AAT -02 suite; PERMIT is accept, DENY reject.",
            "expected": "PrivateVault's verdict and reason code for the pv-delegation/2 chain in 'link'.",
            "aat_02": "The verdict and Section 8 step of the AAT -02 reference verifier "
            "(tenuo-ai/tenuo ietf/vectors/gen_vectors.py) for the same scenario, built as AAT "
            "-02 tokens by tools/check_aat02_analogues.py; aat-analogues.json records the "
            "tokens and the verifier commit. 'n/a' where AAT has no counterpart.",
            "chain": "Root first. 'link' is the signed pv-delegation/2 link the replay verifies; "
            "'aat' is its AAT -02 view at the depth it was issued at.",
            "par_hash": "SHA-256 over PrivateVault's link encoding ('pv-delegation/1:' + canonical "
            "JSON without the signature), base64url without padding; the link carries "
            "the same digest in hex as 'parent'. AAT hashes a JWS signing input instead.",
            "del_max_depth": "del_depth + the link's max_depth (PrivateVault counts remaining hops).",
            "policy": "agent_id: who presents the chain (default: the leaf's delegate); revoked: link hashes.",
            "keys": "Ed25519 seed = SHA-256('pv-aat02-vectors/' + name), hex. Test keys only.",
        },
        "params": {
            "now": NOW,
            "max_chain_links": dl.MAX_CHAIN_LINKS,
            "max_depth_claim": dl.MAX_DEPTH,
        },
        "keys": {name: public_key(name) for name in [*PARTIES, *UNPINNED]},
        "trust_anchors": [
            {
                "name": "operator",
                "role": "root",
                "ed25519_public_key_hex": public_key("operator"),
            }
        ]
        + [
            {"name": p, "role": "agent", "ed25519_public_key_hex": public_key(p)}
            for p in PARTIES[1:]
        ],
        "vectors": vectors(),
    }


def render() -> str:
    return json.dumps(suite(), indent=1, sort_keys=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument(
        "--check", action="store_true", help="fail if the committed suite is stale"
    )
    args = p.parse_args(argv)
    text = render()
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print(
                f"STALE: {OUT.relative_to(ROOT)} -- run python tools/gen_aat02_vectors.py"
            )
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(suite()['vectors'])} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
