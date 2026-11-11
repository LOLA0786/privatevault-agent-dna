"""
ConsensusChecker -- multi-agent quorum over pv-vote/2 signed votes.

Who decides what
----------------
The OPERATOR pins, at startup, everything that defines a quorum
(``ConsensusConfig``, loaded from ``PV_CONSENSUS_FILE``):

    * the voter roster: who may vote, each voter's weight and Ed25519
      public key;
    * the threshold: the approving weight a quorum needs;
    * ``required_for``: capability prefixes that must carry a quorum.

The CALLER supplies only the votes:

    evidence["consensus"] = {
        "action_id": "sha256:<hex>",      # consensus_action_id(...)
        "votes": [
            {"agent_id": str, "vote": "APPROVE" | "REJECT",
             "nonce": str, "issued_at": float, "expires_at": float,
             "signature": "<128 hex>"},
            ...
        ],
    }

Before 2026-11 the threshold, the trust weights and the action id all
arrived in that same caller-supplied object, so whoever submitted the votes
also chose how many were needed, how much each counted and which action they
applied to. A ``threshold`` or ``trust_scores`` key in the evidence is now
refused outright -- silently ignoring it would leave a caller believing it
had been honoured.

What a passing quorum proves
----------------------------
    * every counted vote was signed by a roster member's pinned key
      (Ed25519: the service verifies, it cannot forge);
    * every counted vote names THIS action: ``action_id`` is recomputed by
      the service from the agent, capability and arguments under decision,
      and a vote signed for anything else does not verify;
    * each voter counts once, at the operator's weight;
    * the approving weight reaches the operator's threshold, which by
      default must exceed half the roster's total weight, so votes the
      submitter withholds cannot change the outcome;
    * the votes have not cleared a quorum in this process before.

Evidence honesty
----------------
    no evidence, capability not in required_for -> SKIPPED (recorded)
    no evidence, capability in required_for     -> flagged
    evidence, no roster configured              -> flagged (unverifiable)
    evidence, quorum not reached                -> flagged

Never blocks -- ceiling is REQUIRE_APPROVAL, and a consensus hold is not
satisfiable by an approval. Malformed evidence is a hold, never a crash.

Limit: single-use tracking of cleared votes is per process. Several API
replicas each keep their own; vote TTL (default 300 s, capped at
``MAX_VOTE_TTL``) bounds the replay window across replicas.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..multi_agent_security.independence import (
    ATTRIBUTES,
    independence_shortfall,
    normalize_label,
)
from ..multi_agent_security.nonce_ledger import (
    LedgerUnavailable,
    MemoryNonceLedger,
    NonceLedger,
)
from .signing import (
    APPROVE,
    REJECT,
    consensus_action_id,
    verify_vote_v2,
)


class ConsensusConfigError(ValueError):
    """The pinned quorum configuration is unusable. Startup must refuse."""


@dataclass(frozen=True)
class Voter:
    agent_id: str
    weight: float
    public_key: str  # 64 lowercase hex, Ed25519
    # What the operator declares about the voter, for independence rules.
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ConsensusConfig:
    threshold: float
    voters: Mapping[str, Voter]
    required_for: tuple[str, ...] = ()
    allow_minority_threshold: bool = False
    # e.g. {"provider": 2}: approving voters must span two providers.
    require_distinct: Mapping[str, int] = field(default_factory=dict)

    @property
    def total_weight(self) -> float:
        return sum(v.weight for v in self.voters.values())

    def requires(self, capability: str | None) -> bool:
        return bool(capability) and any(
            capability == p or capability.startswith(p)  # type: ignore[union-attr]
            for p in self.required_for
        )

    @classmethod
    def from_dict(cls, raw: Any) -> ConsensusConfig:  # noqa: C901 - checklist
        if not isinstance(raw, dict):
            raise ConsensusConfigError("consensus config must be a JSON object")
        unknown = set(raw) - {
            "threshold",
            "voters",
            "required_for",
            "allow_minority_threshold",
            "require_distinct",
        }
        if unknown:
            raise ConsensusConfigError(f"unknown field(s) {sorted(unknown)}")

        voters_raw = raw.get("voters")
        if not isinstance(voters_raw, list) or not voters_raw:
            raise ConsensusConfigError("voters must be a non-empty list")
        voters: dict[str, Voter] = {}
        for entry in voters_raw:
            if not isinstance(entry, dict):
                raise ConsensusConfigError("each voter must be an object")
            agent_id = entry.get("agent_id")
            key = entry.get("public_key")
            weight = entry.get("weight", 1.0)
            if not isinstance(agent_id, str) or not agent_id:
                raise ConsensusConfigError("voter agent_id must be a string")
            if agent_id != agent_id.strip() or not agent_id.isprintable():
                # "v1" and "v1 " would both load and read alike.
                raise ConsensusConfigError(
                    f"voter agent_id {agent_id!r} has surrounding whitespace or "
                    "non-printable characters"
                )
            if agent_id in voters:
                raise ConsensusConfigError(f"duplicate voter {agent_id!r}")
            if not _is_hex(key, 64):
                raise ConsensusConfigError(
                    f"voter {agent_id!r}: public_key must be 64 lowercase hex"
                )
            if isinstance(weight, bool) or not isinstance(weight, int | float):
                raise ConsensusConfigError(f"voter {agent_id!r}: weight not a number")
            weight = float(weight)
            if not math.isfinite(weight) or weight <= 0.0:
                raise ConsensusConfigError(
                    f"voter {agent_id!r}: weight must be positive and finite"
                )
            attributes: dict[str, str] = {}
            for name in ATTRIBUTES:
                value = entry.get(name)
                if value is None:
                    continue
                if not isinstance(value, str) or not value:
                    raise ConsensusConfigError(
                        f"voter {agent_id!r}: {name} must be a non-empty string"
                    )
                try:
                    attributes[name] = normalize_label(value)
                except ValueError as exc:
                    raise ConsensusConfigError(
                        f"voter {agent_id!r}: {name}: {exc}"
                    ) from exc
            extra = set(entry) - {"agent_id", "public_key", "weight", *ATTRIBUTES}
            if extra:
                raise ConsensusConfigError(
                    f"voter {agent_id!r}: unknown field(s) {sorted(extra)}"
                )
            voters[agent_id] = Voter(agent_id, weight, str(key), attributes)
        if len({v.public_key for v in voters.values()}) != len(voters):
            raise ConsensusConfigError("two voters share one public key")

        threshold = raw.get("threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, int | float):
            raise ConsensusConfigError("threshold must be a number")
        threshold = float(threshold)
        total = sum(v.weight for v in voters.values())
        if not math.isfinite(threshold) or threshold <= 0.0:
            raise ConsensusConfigError("threshold must be positive and finite")
        if threshold > total:
            raise ConsensusConfigError(
                f"threshold {threshold} exceeds total voter weight {total}: "
                "no quorum could ever be reached"
            )
        minority = raw.get("allow_minority_threshold", False)
        if not isinstance(minority, bool):
            raise ConsensusConfigError("allow_minority_threshold must be a boolean")
        if not minority and threshold <= total / 2:
            raise ConsensusConfigError(
                f"threshold {threshold} is not more than half the total voter "
                f"weight {total}: votes withheld by the submitter could change "
                "the outcome. Raise it, or set allow_minority_threshold: true"
            )

        required = raw.get("required_for", [])
        if not isinstance(required, list) or not all(
            isinstance(p, str) and p for p in required
        ):
            raise ConsensusConfigError("required_for must be a list of strings")

        distinct_raw = raw.get("require_distinct", {})
        if not isinstance(distinct_raw, dict):
            raise ConsensusConfigError("require_distinct must be an object")
        distinct: dict[str, int] = {}
        for name, needed in distinct_raw.items():
            if name not in ATTRIBUTES:
                raise ConsensusConfigError(
                    f"require_distinct: {name!r} is not one of {list(ATTRIBUTES)}"
                )
            if isinstance(needed, bool) or not isinstance(needed, int) or needed < 2:
                raise ConsensusConfigError(
                    f"require_distinct.{name} must be an integer of at least 2"
                )
            available = {
                v.attributes[name] for v in voters.values() if name in v.attributes
            }
            if len(available) < needed:
                raise ConsensusConfigError(
                    f"require_distinct.{name} needs {needed} distinct values; the "
                    f"roster declares {len(available)}: no quorum could ever clear"
                )
            distinct[name] = needed

        return cls(
            threshold=threshold,
            voters=voters,
            required_for=tuple(required),
            allow_minority_threshold=minority,
            require_distinct=distinct,
        )

    @classmethod
    def from_file(cls, path: str | Path) -> ConsensusConfig:
        try:
            raw = json.loads(
                Path(path).read_text(encoding="utf-8"),
                object_pairs_hook=_no_duplicate_keys,
            )
        except (OSError, ValueError) as exc:
            raise ConsensusConfigError(
                f"cannot load consensus config {str(path)!r}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        return cls.from_dict(raw)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


@dataclass
class ConsensusResult:
    flagged: bool
    reason: str = ""
    checks_run: list[str] = field(default_factory=list)
    checks_skipped: list[str] = field(default_factory=list)


_CALLER_MAY_NOT_SET = ("threshold", "trust_scores", "voters", "weights")


class ConsensusChecker:
    def __init__(
        self,
        config: ConsensusConfig | None = None,
        clock: Callable[[], float] = time.time,
        ledger: NonceLedger | None = None,
    ) -> None:
        self.config = config
        self._clock = clock
        self._lock = threading.Lock()
        # Votes that already cleared a quorum. In memory by default (one
        # process); a SqliteNonceLedger makes it hold across replicas.
        self._ledger: NonceLedger = (
            ledger if ledger is not None else MemoryNonceLedger()
        )
        self._ledger_shared = ledger is not None

    # ------------------------------------------------------------------

    def use_ledger(self, ledger: NonceLedger) -> None:
        """Attach the shared single-use ledger once the runtime has one."""
        self._ledger = ledger
        self._ledger_shared = True

    def describe(self) -> dict[str, str]:
        """Composition-manifest entry: what this level can and cannot do."""
        if self.config is None:
            return {
                "status": "attached",
                "detail": (
                    "no voter roster pinned (PV_CONSENSUS_FILE unset): supplied "
                    "vote evidence cannot be verified and is held; ceiling "
                    "REQUIRE_APPROVAL"
                ),
            }
        cfg = self.config
        required = ", ".join(cfg.required_for) if cfg.required_for else "none"
        distinct = (
            ", ".join(f"{n}>={k}" for n, k in sorted(cfg.require_distinct.items()))
            or "none"
        )
        return {
            "status": "attached",
            "detail": (
                f"pv-vote/2 quorum: {len(cfg.voters)} pinned voter(s), threshold "
                f"{cfg.threshold} of total weight {cfg.total_weight}; required "
                f"for: {required}; independence: {distinct}; single-use: "
                f"{'shared ledger' if self._ledger_shared else 'this process only'}"
                "; ceiling REQUIRE_APPROVAL"
            ),
        }

    @staticmethod
    def _flag(reason: str) -> ConsensusResult:
        return ConsensusResult(flagged=True, reason=reason, checks_run=["quorum"])

    def check(  # noqa: C901 - ordered refusal checklist
        self,
        evidence: dict[str, Any] | None = None,
        *,
        agent_id: str | None = None,
        capability: str | None = None,
        arguments: dict[str, Any] | None = None,
    ) -> ConsensusResult:
        consensus = (evidence or {}).get("consensus")
        cfg = self.config

        if consensus is None:
            if cfg is not None and cfg.requires(capability):
                return self._flag(
                    f"consensus_required: capability {capability!r} needs a "
                    "quorum and no vote evidence was supplied"
                )
            return ConsensusResult(flagged=False, checks_skipped=["quorum"])

        if cfg is None:
            return self._flag(
                "consensus_not_configured: vote evidence was supplied but no "
                "voter roster is pinned (PV_CONSENSUS_FILE); votes cannot be "
                "verified, so the quorum_shortfall stands"
            )
        if not isinstance(consensus, dict):
            return self._flag("consensus_malformed: evidence must be an object")

        refused = [k for k in _CALLER_MAY_NOT_SET if k in consensus]
        if refused:
            return self._flag(
                f"consensus_malformed: {', '.join(refused)} cannot be set by the "
                "caller; the operator pins them (quorum_shortfall)"
            )

        if not agent_id or not capability:
            return self._flag(
                "consensus_unbound: the action under decision was not supplied, "
                "so votes cannot be bound to it"
            )
        try:
            expected = consensus_action_id(agent_id, capability, arguments)
        except (TypeError, ValueError):
            return self._flag(
                "consensus_unbound: action arguments are not canonical JSON"
            )
        if consensus.get("action_id") != expected:
            return self._flag(
                "consensus_action_mismatch: votes do not name the action under "
                f"decision (expected action_id {expected}); quorum_shortfall"
            )

        votes = consensus.get("votes")
        if not isinstance(votes, list):
            return self._flag("consensus_malformed: votes must be a list")

        try:
            return self._count(cfg, votes, expected)
        except LedgerUnavailable as exc:
            # A quorum that cannot be recorded as spent must not clear.
            return self._flag(
                f"consensus_ledger_unavailable: {exc}; no quorum can clear until "
                "the single-use ledger is writable (quorum_shortfall)"
            )

    def health(self) -> str | None:
        """None when a quorum could be recorded now, else why not."""
        probe = getattr(self._ledger, "health", None)
        return probe() if callable(probe) else None

    def _count(
        self, cfg: ConsensusConfig, votes: list[Any], expected: str
    ) -> ConsensusResult:
        now = self._clock()
        counted: dict[str, dict[str, Any]] = {}
        nonces: set[str] = set()
        with self._lock:
            for vote in votes:
                if not isinstance(vote, dict):
                    continue
                voter = cfg.voters.get(str(vote.get("agent_id", "")))
                if voter is None or voter.agent_id in counted:
                    continue  # not on the roster, or already voted
                nonce = vote.get("nonce")
                if not isinstance(nonce, str) or not nonce or nonce in nonces:
                    continue
                if self._ledger.seen(voter.agent_id, nonce, now):
                    continue  # already cleared a quorum: single use
                if not verify_vote_v2(
                    vote, action_id=expected, public_key=voter.public_key, now=now
                ):
                    continue
                counted[voter.agent_id] = vote
                nonces.add(nonce)

            approve = sum(
                cfg.voters[a].weight for a, v in counted.items() if v["vote"] == APPROVE
            )
            reject = sum(
                cfg.voters[a].weight for a, v in counted.items() if v["vote"] == REJECT
            )
            if approve >= cfg.threshold:
                approvers = [a for a, v in counted.items() if v["vote"] == APPROVE]
                shortfall = independence_shortfall(
                    approvers,
                    {a: cfg.voters[a].attributes for a in approvers},
                    cfg.require_distinct,
                )
                if shortfall:
                    return self._flag(
                        "independence_shortfall: the approving weight reaches the "
                        "threshold, but the approving voters are not independent "
                        "enough (" + "; ".join(shortfall) + "); quorum_shortfall"
                    )
                spent = [
                    (a, v["nonce"], float(v["expires_at"])) for a, v in counted.items()
                ]
                # One transaction: with a shared ledger, two replicas racing
                # on the same votes cannot both clear.
                if not self._ledger.consume(spent, now):
                    return self._flag(
                        "quorum_replayed: these votes already cleared a quorum "
                        "(quorum_shortfall)"
                    )
                return ConsensusResult(flagged=False, checks_run=["quorum"])

        return self._flag(
            f"quorum_shortfall: approving weight {approve:g} of threshold "
            f"{cfg.threshold:g} (rejecting weight {reject:g}) from "
            f"{len(counted)} valid vote(s) out of {len(votes)} submitted; votes "
            "that are unsigned, off-roster, for another action, expired, "
            "duplicated or already used count zero"
        )
