"""
Shadow policy evaluation — test a candidate policy against the LIVE
decision stream without enforcing it.

The scariest operation in a bank is a control change: nobody ships a
new payment rule because nobody can answer "what will this break?".
Shadow mode answers it with production traffic. A candidate policy
rides alongside the real enforcement path; for every live decision it
records what it WOULD have done, enforcing nothing. After a soak
window the divergence report says, in the bank's own words: "this
rule would have blocked 211 payments your team approved last week."

Design:
  * Zero effect on enforcement. The shadow evaluator runs AFTER the
    authoritative verdict, inside the same lock, and its result is
    never returned to the caller. A crash in a candidate policy is
    swallowed and counted, never propagated -- an experimental rule
    cannot take down the enforcement path.
  * Every observation is chained and hash-linked in its OWN log,
    separate from the authoritative decision chain, so shadow activity
    never pollutes the audit trail a regulator reads.
  * A candidate sees the SAME action and evidence the real engine saw,
    so its verdict is directly comparable.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# A candidate is any object with .check(agent_id, capability, arguments,
# evidence) -> PolicyResult-like (fired, outcome, [matched_rule_id]);
# i.e. exactly a PolicyChecker or OPAPolicyAdapter. No new interface.
Candidate = Any


@dataclass
class ShadowObservation:
    seq: int
    ts: float
    candidate: str
    agent_id: str
    capability: str
    arguments_digest: str        # same privacy posture as real records
    live_decision: str           # what the real engine enforced
    shadow_outcome: str          # allow | block | require_approval | skip | error
    shadow_rule_id: Optional[str]
    diverged: bool               # would the candidate have changed the verdict?
    prev_hash: str
    record_hash: str = ""

    def seal(self) -> "ShadowObservation":
        payload = {k: v for k, v in self.__dict__.items()
                   if k != "record_hash"}
        canonical = json.dumps(payload, sort_keys=True,
                               separators=(",", ":"), allow_nan=False)
        self.record_hash = hashlib.sha256(canonical.encode()).hexdigest()
        return self


def _digest(arguments: Dict) -> str:
    canonical = json.dumps(arguments or {}, sort_keys=True,
                           separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class ShadowPolicySet:
    """A named set of candidate policies observed against live traffic.

    Attach to a ConnectorMiddleware / runtime; it does the rest. Query
    report() after a soak window."""

    candidates: Dict[str, Candidate] = field(default_factory=dict)
    _log: List[ShadowObservation] = field(default_factory=list)
    _seq: int = 0
    _GENESIS: str = "0" * 64

    def add(self, name: str, candidate: Candidate) -> "ShadowPolicySet":
        self.candidates[name] = candidate
        return self

    def observe(self, action, live_result, evidence: Optional[dict]) -> None:
        """Called after the authoritative verdict. Never raises into
        the caller -- a candidate fault is recorded as 'error', not
        propagated onto the enforcement path."""
        live = live_result.decision.value if hasattr(
            live_result.decision, "value") else str(live_result.decision)
        digest = _digest(getattr(action, "arguments", {}))
        prev = self._log[-1].record_hash if self._log else self._GENESIS

        for name, candidate in self.candidates.items():
            outcome, rule_id = "skip", None
            try:
                pr = candidate.check(
                    agent_id=action.agent_id,
                    capability=action.capability,
                    arguments=getattr(action, "arguments", {}),
                    evidence=evidence,
                )
                if getattr(pr, "fired", False):
                    outcome = pr.outcome
                    rule_id = getattr(pr, "matched_rule_id", None)
                else:
                    outcome = "allow"      # candidate raised no objection
            except Exception as exc:       # noqa: BLE001 - must not escape
                outcome = "error"
                rule_id = f"{type(exc).__name__}"

            diverged = (
                outcome not in ("skip", "error") and outcome != live
            )
            obs = ShadowObservation(
                seq=self._seq, ts=time.time(), candidate=name,
                agent_id=action.agent_id, capability=action.capability,
                arguments_digest=digest, live_decision=live,
                shadow_outcome=outcome, shadow_rule_id=rule_id,
                diverged=diverged, prev_hash=prev,
            ).seal()
            self._log.append(obs)
            prev = obs.record_hash
            self._seq += 1

    def verify_chain(self) -> bool:
        """The shadow log is hash-chained too -- a shadow report handed
        to a bank must itself be tamper-evident."""
        prev = self._GENESIS
        for obs in self._log:
            if obs.prev_hash != prev:
                return False
            recomputed = ShadowObservation(
                **{k: v for k, v in obs.__dict__.items()
                   if k != "record_hash"}
            ).seal().record_hash
            if recomputed != obs.record_hash:
                return False
            prev = obs.record_hash
        return True

    def report(self, candidate: Optional[str] = None) -> Dict[str, Any]:
        names = [candidate] if candidate else list(self.candidates)
        out = {}
        for name in names:
            obs = [o for o in self._log if o.candidate == name]
            observed = len(obs)
            newly_blocked = [
                o for o in obs
                if o.shadow_outcome in ("block", "require_approval")
                and o.live_decision == "allow"
            ]
            newly_allowed = [
                o for o in obs
                if o.shadow_outcome == "allow"
                and o.live_decision in ("block", "require_approval")
            ]
            errors = [o for o in obs if o.shadow_outcome == "error"]
            by_cap: Dict[str, int] = {}
            for o in newly_blocked:
                by_cap[o.capability] = by_cap.get(o.capability, 0) + 1
            out[name] = {
                "observed": observed,
                "would_newly_block": len(newly_blocked),
                "would_newly_allow": len(newly_allowed),
                "candidate_errors": len(errors),
                "unchanged": observed - len(newly_blocked)
                - len(newly_allowed) - len(errors),
                "newly_blocked_by_capability": dict(
                    sorted(by_cap.items(), key=lambda kv: -kv[1])
                ),
                "sample_newly_blocked": [
                    {"seq": o.seq, "capability": o.capability,
                     "agent_id": o.agent_id, "live": o.live_decision,
                     "shadow": o.shadow_outcome, "rule": o.shadow_rule_id,
                     "arguments_digest": o.arguments_digest[:12] + "..",
                     "record_hash": o.record_hash[:12] + ".."}
                    for o in newly_blocked[:10]
                ],
                "chain_verified": self.verify_chain(),
            }
        return {"shadow_report": out}
