"""
Trust-weighted quorum over pv-vote/1 signed votes.

Originally vendored from PrivateVault.ai's coordination/mesh. Rebuilt
2026-07 (P0-6). The vendored version stored every submission in a
list and summed every valid APPROVE: one low-trust agent submitting
the same signed vote three times cleared a threshold alone, and a
signature bound only the message hash, so a captured vote replayed
into any other action sharing that hash.

Now:
  * one vote per authenticated voter per action -- the first VALID
    submission for (action, agent) is binding; later submissions are
    ignored (idempotent redelivery, no re-voting);
  * a vote is stored only if verify_vote passes: signature bound to
    action_id + vote value + nonce + freshness window, evaluated
    against this quorum's clock. Invalid, unbound, expired, or
    malformed votes are dropped and contribute ZERO -- the same
    evidence-honesty rule the forged-vote path always had;
  * nonces are single-use per action;
  * expiry is re-checked at count time (a vote valid at submission
    does not outlive its window);
  * threshold is absolute trust mass (weights may sum past 1.0 by
    design -- e.g. two 0.9-trust approvers = 1.8); it must be a
    positive finite number. Trust scores must lie in [0, 1].
"""

from __future__ import annotations

import math
import time
from typing import Callable, Dict

from .signing import verify_vote


class TrustRegistry:
    def __init__(self) -> None:
        self.scores: Dict[str, float] = {}

    def set_score(self, agent_id: str, score: float) -> None:
        s = float(score)
        if not (0.0 <= s <= 1.0) or math.isnan(s):
            raise ValueError(
                f"trust score must be in [0, 1], got {score!r}"
            )
        self.scores[agent_id] = s

    def get(self, agent_id: str, default: float = 0.5) -> float:
        return self.scores.get(agent_id, default)


class SecureQuorum:
    def __init__(
        self,
        threshold: float,
        trust_registry: TrustRegistry,
        clock: Callable[[], float] = time.time,
    ) -> None:
        t = float(threshold)
        if not math.isfinite(t) or t <= 0.0:
            raise ValueError(
                f"threshold must be a positive finite trust mass, got "
                f"{threshold!r}"
            )
        self.threshold = t
        self.trust_registry = trust_registry
        self.clock = clock
        # action_id -> agent_id -> validated vote dict
        self.votes: Dict[str, Dict[str, dict]] = {}
        # action_id -> set of consumed nonces
        self._nonces: Dict[str, set] = {}

    # ------------------------------------------------------------------

    def submit(self, action_id: str, vote: dict) -> bool:
        """Validate and store one pv-vote/1 vote dict. Returns True if
        the vote was accepted as this agent's binding vote for this
        action; False if it was dropped (invalid) or ignored
        (duplicate agent / reused nonce). Never raises on malformed
        input -- a bad vote is zero weight, not a crash."""
        agent_id = vote.get("agent_id", "")
        nonce = vote.get("nonce", "")

        action_votes = self.votes.setdefault(action_id, {})
        used_nonces = self._nonces.setdefault(action_id, set())

        if agent_id in action_votes:      # one vote per voter per action
            return False
        if nonce in used_nonces:          # single-use nonce per action
            return False

        if not verify_vote(
            agent_id,
            action_id=action_id,
            vote=vote.get("vote", ""),
            message_hash=vote.get("message_hash", ""),
            nonce=nonce,
            issued_at=vote.get("issued_at", float("nan")),
            expires_at=vote.get("expires_at", float("nan")),
            signature=vote.get("signature", ""),
            now=self.clock(),
        ):
            return False

        action_votes[agent_id] = dict(vote)
        used_nonces.add(nonce)
        return True

    def submit_vote(
        self, action_id: str, agent_id: str, vote: str,
        signature: str, message_hash: str, nonce: str,
        issued_at: float, expires_at: float,
    ) -> bool:
        """Explicit-argument form of submit()."""
        return self.submit(action_id, {
            "agent_id": agent_id, "vote": vote, "signature": signature,
            "message_hash": message_hash, "nonce": nonce,
            "issued_at": issued_at, "expires_at": expires_at,
        })

    def check_quorum(self, action_id: str) -> bool:
        now = self.clock()
        score = 0.0
        for agent_id, v in self.votes.get(action_id, {}).items():
            if now >= float(v["expires_at"]):   # expired since submit
                continue
            if v["vote"] == "APPROVE":
                score += self.trust_registry.get(agent_id)
        return score >= self.threshold
