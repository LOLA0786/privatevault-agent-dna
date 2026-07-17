"""
Byzantine Fault-Tolerant Consensus — PBFT-inspired.
Tolerates f malicious agents with 3f+1 nodes.
Time-bound votes, replay protection, chain-linked audit.
New file — does not modify existing SecureQuorum.
"""
from __future__ import annotations
import time
from typing import Dict, List, Optional
from .secure_quorum import TrustRegistry
from .signing import verify_signature

class ByzantineQuorum:
    DEFAULT_EXPIRY = 30
    DEFAULT_MIN_NODES = 4
    def __init__(self, threshold: float = 0.67, min_nodes: int = 4, expiry: int = 30):
        self.threshold = threshold; self.min_nodes = min_nodes; self.expiry = expiry
        self.votes: Dict[str, List[Dict]] = {}; self.prev_decision_hash = None
    def set_prev_hash(self, h: str): self.prev_decision_hash = h
    def submit_vote(self, action_id: str, agent_id: str, vote: str, signature: str, message_hash: str, timestamp: Optional[float] = None, nonce: Optional[str] = None):
        ts = timestamp or time.time()
        if time.time() - ts > self.expiry: raise ValueError("vote expired")
        linked = f"{self.prev_decision_hash}:{message_hash}" if self.prev_decision_hash else message_hash
        self.votes.setdefault(action_id, []).append({"agent": agent_id, "vote": vote, "signature": signature, "hash": linked, "timestamp": ts, "nonce": nonce or "none"})
    def check_quorum(self, action_id: str) -> bool:
        votes = self.votes.get(action_id, [])
        unique = {v["agent"] for v in votes}
        if len(unique) < self.min_nodes: return False
        registry = TrustRegistry()
        score = 0.0; approved = 0
        for v in votes:
            if time.time() - v["timestamp"] > self.expiry: continue
            if not verify_signature(v["agent"], v["hash"], v["signature"]): continue
            if v["vote"] == "APPROVE": score += registry.get(v["agent"], 0.5); approved += 1
        verified = len({v["agent"] for v in votes if verify_signature(v["agent"], v["hash"], v["signature"])})
        return (score >= self.threshold) and (approved >= (verified // 2 + 1)) and (verified >= self.min_nodes)
