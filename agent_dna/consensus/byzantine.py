"""Byzantine fault-tolerant quorum over legacy-signed votes.

PBFT-inspired: with n >= 3f + 1 verified voters, up to f Byzantine
agents cannot force approval, provided thresholds are configured
accordingly. Votes are HMAC-signed (legacy raw-message primitive from
``signing.py``); the serving-path consensus (``SecureQuorum`` /
pv-vote/1) binds vote value and freshness inside the MAC and should
be preferred for new integrations -- this class remains for
chain-linked multi-round scenarios and the coding-agents demo.

Approval requires ALL of, over the fresh + signature-verified vote
set only:

    1. verified voters  >= min_nodes
    2. APPROVE voters   >  half of verified voters (strict majority)
    3. sum of APPROVE voters' trust scores >= threshold

Note on semantics (deliberately preserved from the original): the
threshold is an ABSOLUTE trust-mass sum, not a fraction. With the
default registry every agent weighs ``default_trust`` (0.5), so e.g.
threshold=0.67 means "at least two default-trust approvals".

2026-07 rewrite: same public API, five behavioral security fixes,
each pinned in tests/test_byzantine_quorum.py:

  F1  future-dated votes rejected at submission (beyond clock skew);
      previously ``now - ts > expiry`` let any future timestamp pass.
  F2  replay protection is real: a duplicate (agent, nonce) for the
      same action is rejected. Previously the nonce was stored and
      never checked, despite the module docstring claiming replay
      protection.
  F3  one ballot per agent per action -- a re-vote REPLACES the
      previous ballot. Previously each duplicate APPROVE inflated
      both the trust sum and the approve count.
  F4  expired votes are excluded from numerator AND denominator.
      Previously they were excluded from the approve count but still
      widened the majority denominator.
  F5  the trust registry is injectable. Previously ``check_quorum``
      constructed a fresh ``TrustRegistry()`` on every call, so every
      agent always weighed the default 0.5 and configured trust
      scores could never take effect.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from .secure_quorum import TrustRegistry
from .signing import verify_signature

CLOCK_SKEW_SECONDS = 30.0
NO_NONCE = "none"  # legacy sentinel: nonce-less votes skip replay dedup


@dataclass(frozen=True)
class _Ballot:
    agent: str
    vote: str
    signature: str
    linked_hash: str
    timestamp: float
    nonce: str

    def as_dict(self) -> dict:
        """Legacy dict shape, kept for callers that inspect .votes."""
        return {
            "agent": self.agent,
            "vote": self.vote,
            "signature": self.signature,
            "hash": self.linked_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }


class ByzantineQuorum:
    DEFAULT_EXPIRY = 30
    DEFAULT_MIN_NODES = 4

    def __init__(
        self,
        threshold: float = 0.67,
        min_nodes: int = DEFAULT_MIN_NODES,
        expiry: int = DEFAULT_EXPIRY,
        trust_registry: TrustRegistry | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if threshold <= 0:
            raise ValueError(f"threshold must be positive, got {threshold!r}")
        if min_nodes < 1:
            raise ValueError(f"min_nodes must be >= 1, got {min_nodes!r}")
        if expiry <= 0:
            raise ValueError(f"expiry must be positive, got {expiry!r}")
        self.threshold = threshold
        self.min_nodes = min_nodes
        self.expiry = expiry
        self.prev_decision_hash: str | None = None
        self._clock = clock
        self._registry = trust_registry  # None => fresh default per check (legacy)
        self._ballots: dict[str, dict[str, _Ballot]] = {}  # action -> agent -> ballot
        self._seen_nonces: dict[
            str, set[tuple[str, str]]
        ] = {}  # action -> {(agent, nonce)}

    # ------------------------------------------------------------------ chain

    def set_prev_hash(self, h: str) -> None:
        """Link subsequent votes to a prior decision hash. Votes signed
        before this call keep their original link -- the linked hash is
        fixed at submission time, matching the original behavior."""
        self.prev_decision_hash = h

    # ------------------------------------------------------------ vote intake

    def submit_vote(
        self,
        action_id: str,
        agent_id: str,
        vote: str,
        signature: str,
        message_hash: str,
        timestamp: float | None = None,
        nonce: str | None = None,
    ) -> None:
        now = self._clock()
        ts = now if timestamp is None else float(timestamp)

        if now - ts > self.expiry:
            raise ValueError("vote expired")
        if ts - now > CLOCK_SKEW_SECONDS:  # F1
            raise ValueError("vote timestamp is in the future")

        effective_nonce = nonce or NO_NONCE
        if effective_nonce != NO_NONCE:  # F2
            seen = self._seen_nonces.setdefault(action_id, set())
            key = (agent_id, effective_nonce)
            if key in seen:
                raise ValueError(
                    f"replayed vote: nonce {effective_nonce!r} already "
                    f"used by {agent_id!r} for action {action_id!r}"
                )
            seen.add(key)

        linked = (
            f"{self.prev_decision_hash}:{message_hash}"
            if self.prev_decision_hash
            else message_hash
        )
        # F3: one ballot per agent per action; a re-vote replaces.
        self._ballots.setdefault(action_id, {})[agent_id] = _Ballot(
            agent=agent_id,
            vote=vote,
            signature=signature,
            linked_hash=linked,
            timestamp=ts,
            nonce=effective_nonce,
        )

    # -------------------------------------------------------------- decision

    def check_quorum(self, action_id: str) -> bool:
        now = self._clock()
        registry = self._registry if self._registry is not None else TrustRegistry()

        # F4: one filtered set drives every count -- fresh AND verified.
        valid = [
            b
            for b in self._ballots.get(action_id, {}).values()
            if now - b.timestamp <= self.expiry
            and verify_signature(b.agent, b.linked_hash, b.signature)
        ]

        verified = len(valid)
        if verified < self.min_nodes:
            return False

        approvals = [b for b in valid if b.vote == "APPROVE"]
        strict_majority = len(approvals) >= (verified // 2 + 1)
        trust_mass = sum(registry.get(b.agent, 0.5) for b in approvals)

        return strict_majority and trust_mass >= self.threshold

    # ------------------------------------------------------- legacy interface

    @property
    def votes(self) -> dict[str, list[dict]]:
        """Read-only view in the original ``{action: [vote dicts]}``
        shape, for callers and tests that inspected the attribute."""
        return {
            action: [b.as_dict() for b in per_agent.values()]
            for action, per_agent in self._ballots.items()
        }
