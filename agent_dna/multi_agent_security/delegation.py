"""
Delegation that can only shrink (pv-delegation/1).

The failure this stops: agent A is not allowed to do something, so it asks
agent B, which is. Without a record of where B's authority for THIS task
came from, B acts under its own standing grant and A's limit is gone.

A delegation chain makes the authority travel with the task:

    operator --signs--> A --signs--> B --signs--> C

Each link names who delegates to whom, which capabilities, a per-action
amount ceiling, an expiry and whether the delegate may delegate further.
Each link is signed by its delegator's Ed25519 key and names the hash of the
link before it. The receiver verifies the whole chain with nothing but the
operator-pinned keys (``TrustAnchors``); no service call is needed.

The rule that matters: a link can never grant more than the link before it.

    capabilities   every capability must be covered by the parent's
    max_amount     at most the parent's; unlimited only under unlimited
    expires_at     no later than the parent's
    may_delegate   false ends the chain: the delegate cannot pass it on

So the authority C holds is at most what the operator gave A, however many
hands it passed through, and a chain that tries to widen fails to verify.

Capability patterns are an exact name (``payments.pay_invoice``) or a prefix
ending in a dot (``payments.``). There is no match-everything pattern.

Limits, stated plainly:
    * ``max_amount`` is a ceiling per action. Cumulative spend is the grant
      ledger's job, not this module's.
    * Revocation is a list of link hashes in ``TrustAnchors``; distributing
      that list to receivers is the deployment's job. Short expiries are the
      dependable control.
    * A chain proves which keys signed. It does not prove the agent behind a
      key behaved well.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

SPEC = "pv-delegation/1"
MAX_DEPTH = 8
MAX_TTL = 24 * 3600.0
CLOCK_SKEW_SECONDS = 30.0
_TAG = b"pv-delegation/1:"
_FIELDS = frozenset(
    {
        "spec",
        "delegator",
        "delegate",
        "capabilities",
        "max_amount",
        "issued_at",
        "expires_at",
        "may_delegate",
        "parent",
        "nonce",
        "signature",
    }
)


class DelegationError(ValueError):
    """The chain does not verify. The message says which rule failed."""


@dataclass(frozen=True)
class TrustAnchors:
    """Operator-pinned keys. Nothing in a chain can add to these.

    ``roots``   who may start a chain (the operator, a human principal)
    ``agents``  every agent that may appear as a delegator after the root
    ``revoked`` link hashes that no longer count
    """

    roots: Mapping[str, str]
    agents: Mapping[str, str]
    revoked: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class DelegationDecision:
    allowed: bool
    reason: str
    chain_hash: str | None = None
    depth: int = 0


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int | float)
        and math.isfinite(value)
    )


def _valid_pattern(pattern: Any) -> bool:
    return isinstance(pattern, str) and len(pattern) > 1 and "*" not in pattern


def covers(pattern: str, capability: str) -> bool:
    """Does ``pattern`` cover ``capability`` (an exact name or a prefix)?"""
    if pattern.endswith("."):
        return capability.startswith(pattern)
    return capability == pattern


def link_hash(link: Mapping[str, Any]) -> str:
    """Hash a link's signature covers: every field except the signature."""
    body = {k: v for k, v in link.items() if k != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(_TAG + canonical.encode()).hexdigest()


def issue_link(
    signing_key_hex: str,
    *,
    delegator: str,
    delegate: str,
    capabilities: Sequence[str],
    max_amount: float | None = None,
    ttl: float = 900.0,
    may_delegate: bool = False,
    parent: Mapping[str, Any] | None = None,
    clamp_to_parent: bool = True,
    now: float | None = None,
) -> dict[str, Any]:
    """Sign one link. ``parent`` is the link this one narrows, if any.

    The expiry is clamped to the parent's, since a link issued a moment
    after its parent with the same ``ttl`` would otherwise outlive it.
    Nothing else is checked here: a delegator can sign anything, and the
    receiver's ``verify_chain`` is what refuses a link that widens.
    """
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey

    issued_at = time.time() if now is None else float(now)
    expires_at = issued_at + float(ttl)
    if parent is not None and clamp_to_parent:
        expires_at = min(expires_at, float(parent["expires_at"]))
    link: dict[str, Any] = {
        "spec": SPEC,
        "delegator": delegator,
        "delegate": delegate,
        "capabilities": list(capabilities),
        "max_amount": max_amount,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "may_delegate": bool(may_delegate),
        "parent": link_hash(parent) if parent is not None else None,
        "nonce": uuid.uuid4().hex,
    }
    key = SigningKey(signing_key_hex.encode(), encoder=HexEncoder)
    link["signature"] = key.sign(link_hash(link).encode()).signature.hex()
    return link


def _check_shape(link: Any, index: int) -> None:  # noqa: C901 - checklist
    where = f"link {index}"
    if not isinstance(link, dict):
        raise DelegationError(f"{where}: not an object")
    if set(link) != _FIELDS:
        raise DelegationError(f"{where}: unexpected or missing fields")
    if link["spec"] != SPEC:
        raise DelegationError(f"{where}: spec is not {SPEC}")
    for name in ("delegator", "delegate", "nonce"):
        if not isinstance(link[name], str) or not link[name]:
            raise DelegationError(f"{where}: {name} must be a non-empty string")
    if link["delegator"] == link["delegate"]:
        raise DelegationError(f"{where}: an agent cannot delegate to itself")
    capabilities = link["capabilities"]
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or not all(_valid_pattern(p) for p in capabilities)
    ):
        raise DelegationError(f"{where}: capabilities must be a non-empty list")
    amount = link["max_amount"]
    if amount is not None and (not _number(amount) or amount < 0):
        raise DelegationError(f"{where}: max_amount must be null or >= 0")
    if not _number(link["issued_at"]) or not _number(link["expires_at"]):
        raise DelegationError(f"{where}: timestamps must be finite numbers")
    lifetime = link["expires_at"] - link["issued_at"]
    if lifetime <= 0 or lifetime > MAX_TTL:
        raise DelegationError(f"{where}: lifetime must be within (0, {MAX_TTL:g}] s")
    if not isinstance(link["may_delegate"], bool):
        raise DelegationError(f"{where}: may_delegate must be a boolean")
    if link["parent"] is not None and not _is_hex(link["parent"], 64):
        raise DelegationError(f"{where}: parent must be null or a link hash")
    if not _is_hex(link["signature"], 128):
        raise DelegationError(f"{where}: signature must be 128 lowercase hex")


def _check_signature(link: Mapping[str, Any], public_key: str, index: int) -> None:
    from nacl.encoding import HexEncoder
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    try:
        VerifyKey(public_key.encode(), encoder=HexEncoder).verify(
            link_hash(link).encode(), bytes.fromhex(link["signature"])
        )
    except (BadSignatureError, ValueError) as exc:
        raise DelegationError(
            f"link {index}: signature does not verify under "
            f"{link['delegator']!r}'s pinned key"
        ) from exc


def _check_narrows(child: Mapping[str, Any], parent: Mapping[str, Any], i: int) -> None:
    where = f"link {i}"
    if not parent["may_delegate"]:
        raise DelegationError(
            f"{where}: {parent['delegate']!r} was not allowed to delegate further"
        )
    for pattern in child["capabilities"]:
        if not any(covers(held, pattern) for held in parent["capabilities"]):
            raise DelegationError(
                f"{where}: capability {pattern!r} widens what "
                f"{parent['delegate']!r} was given"
            )
    held_amount, amount = parent["max_amount"], child["max_amount"]
    if held_amount is not None and (amount is None or amount > held_amount):
        raise DelegationError(
            f"{where}: max_amount {amount} widens the parent's {held_amount}"
        )
    if child["expires_at"] > parent["expires_at"]:
        raise DelegationError(f"{where}: outlives the link it was derived from")
    if child["issued_at"] < parent["issued_at"]:
        raise DelegationError(f"{where}: issued before the link it derives from")


def verify_chain(  # noqa: C901 - ordered refusal checklist
    chain: Any, anchors: TrustAnchors, *, now: float | None = None
) -> dict[str, Any]:
    """Verify a chain end to end and return its last link.

    Raises ``DelegationError`` naming the first rule that failed.
    """
    moment = time.time() if now is None else float(now)
    if not isinstance(chain, list) or not chain:
        raise DelegationError("chain must be a non-empty list of links")
    if len(chain) > MAX_DEPTH:
        raise DelegationError(f"chain is deeper than {MAX_DEPTH} links")

    seen: set[str] = set()
    previous: dict[str, Any] | None = None
    for index, link in enumerate(chain):
        _check_shape(link, index)
        digest = link_hash(link)
        if digest in anchors.revoked:
            raise DelegationError(f"link {index}: revoked")
        if link["issued_at"] > moment + CLOCK_SKEW_SECONDS:
            raise DelegationError(f"link {index}: issued in the future")
        if moment >= link["expires_at"]:
            raise DelegationError(f"link {index}: expired")

        if previous is None:
            if link["parent"] is not None:
                raise DelegationError("link 0: a root link has no parent")
            key = anchors.roots.get(link["delegator"])
            if key is None:
                raise DelegationError(
                    f"link 0: {link['delegator']!r} is not a pinned root authority"
                )
            seen.add(link["delegator"])
        else:
            if link["delegator"] != previous["delegate"]:
                raise DelegationError(
                    f"link {index}: signed by {link['delegator']!r}, but the "
                    f"authority was held by {previous['delegate']!r}"
                )
            if link["parent"] != link_hash(previous):
                raise DelegationError(f"link {index}: does not name the link before it")
            key = anchors.agents.get(link["delegator"])
            if key is None:
                raise DelegationError(
                    f"link {index}: {link['delegator']!r} has no pinned agent key"
                )
            _check_narrows(link, previous, index)

        if link["delegate"] in seen:
            raise DelegationError(
                f"link {index}: {link['delegate']!r} already appears in the chain"
            )
        seen.add(link["delegate"])
        _check_signature(link, key, index)
        previous = link

    assert previous is not None
    return previous


def authorize(  # noqa: C901 - ordered refusal checklist
    chain: Any,
    anchors: TrustAnchors,
    *,
    agent_id: str,
    capability: str,
    amount: float | None = None,
    now: float | None = None,
) -> DelegationDecision:
    """May ``agent_id`` perform ``capability`` (for ``amount``) under ``chain``?

    Never raises: any problem is a refusal with the reason.
    """
    try:
        last = verify_chain(chain, anchors, now=now)
    except DelegationError as exc:
        return DelegationDecision(False, f"delegation_invalid: {exc}")
    depth = len(chain)
    digest = link_hash(last)
    if last["delegate"] != agent_id:
        return DelegationDecision(
            False,
            f"delegation_not_yours: the chain ends at {last['delegate']!r}, "
            f"not {agent_id!r}",
            digest,
            depth,
        )
    if not any(covers(pattern, capability) for pattern in last["capabilities"]):
        return DelegationDecision(
            False,
            f"delegation_out_of_scope: {capability!r} is not covered",
            digest,
            depth,
        )
    ceiling = last["max_amount"]
    if ceiling is not None:
        if amount is None or not _number(amount) or amount < 0:
            return DelegationDecision(
                False,
                "delegation_amount_required: the chain carries a ceiling and "
                "the action states no valid amount",
                digest,
                depth,
            )
        if amount > ceiling:
            return DelegationDecision(
                False,
                f"delegation_over_ceiling: {amount:g} exceeds {ceiling:g}",
                digest,
                depth,
            )
    return DelegationDecision(True, "delegation_ok", digest, depth)
