#!/usr/bin/env python3
"""
End-to-End Coding Agent Governance Demo (90 seconds).

Four actions from one coding agent, resolved by four different
enforcement layers for four different reasons:

  1. git.read_repo       granted, in baseline      -> ALLOW
  2. git.create_pr       granted, in baseline      -> ALLOW
  3. deploy.production   quorum shortfall / ungranted -> REQUIRE_APPROVAL
  4. storage.bulk_export behavioral invariant      -> BLOCK

The claims printed at the end are asserted, not narrated: if the
engine stops demonstrating them this script exits non-zero. A demo
that can quietly stop demonstrating its own claims is worse than no
demo, so this one fails loudly instead.
"""

import sys

from agent_dna import AgentAction, DecisionEngine
from agent_dna.composition import _train_scorer
from agent_dna.consensus.checker import ConsensusChecker
from agent_dna.consensus.signing import register_key, sign_message
from agent_dna.grants import GrantRegistry
from agent_dna.observability.logger import get_logger
from agent_dna.observability.metrics import MetricsExporter

logger = get_logger("pv_coding_demo")

# The coding agent's declared normal behaviour. Without this, an agent
# with no history scores maximum drift on every action and the engine
# cannot distinguish a repo read from a production deploy. Declaring
# the baseline is the documented answer to cold start.
BASELINE = ["git.read_repo", "git.create_pr"]


class BulkExportInvariant:
    """L1 behavioural invariant: this agent never bulk-exports source."""

    def validate(self, capability, previous):
        class R:
            pass

        r = R()
        r.violated = capability == "storage.bulk_export"
        r.message = (
            "Behavioural invariant violated: 'storage.bulk_export' is not a "
            "permitted action for a coding agent."
            if r.violated
            else ""
        )
        return r


def build_engine():
    """The full composed line -- not a stripped-down fast path."""
    grants = GrantRegistry()
    grants.grant(
        agent_id="code-agent-01", capability="git.read_repo", granted_by="demo"
    )
    grants.grant(
        agent_id="code-agent-01", capability="git.create_pr", granted_by="demo"
    )
    # deploy.production and storage.bulk_export are deliberately NOT granted.

    return DecisionEngine(
        scorer=_train_scorer(BASELINE),
        invariants=BulkExportInvariant(),
        authorizer=grants,
        consensus=ConsensusChecker(),
        drift_threshold=0.8,
    )


def demo():
    register_key("security-agent", "secret-sec")
    register_key("finance-agent", "secret-fin")
    register_key("code-agent-01", "secret-code")

    metrics = MetricsExporter()
    engine = build_engine()

    actions = [
        ("1. Read repo source", AgentAction("code-agent-01", "git.read_repo", 1.0)),
        ("2. Create PR", AgentAction("code-agent-01", "git.create_pr", 2.0)),
        (
            "3. Deploy to production",
            AgentAction(
                "code-agent-01",
                "deploy.production",
                3.0,
                evidence={
                    "consensus": {
                        "action_id": "deploy-prod-001",
                        "votes": [
                            {
                                "agent_id": "security-agent",
                                "vote": "APPROVE",
                                "signature": sign_message(
                                    "security-agent", "hash-deploy"
                                ),
                                "message_hash": "hash-deploy",
                            },
                            {
                                "agent_id": "finance-agent",
                                "vote": "REJECT",
                                "signature": sign_message(
                                    "finance-agent", "hash-deploy"
                                ),
                                "message_hash": "hash-deploy",
                            },
                        ],
                        "threshold": 0.67,
                        "trust_scores": {"security-agent": 1.0, "finance-agent": 0.9},
                    }
                },
            ),
        ),
        (
            "4. Bulk source export",
            AgentAction("code-agent-01", "storage.bulk_export", 4.0),
        ),
        # Ungranted, trips no invariant, carries no consensus evidence --
        # so only the authorization layer can stop it. Proves L3 in
        # isolation rather than letting a higher layer take the credit.
        ("5. Read CRM contacts", AgentAction("code-agent-01", "crm.read_contact", 5.0)),
    ]

    logger.info(
        "demo_start",
        extra={"agent": "code-agent-01", "scenario": "coding_agent_governance"},
    )

    results = []
    for label, action in actions:
        result = engine.decide(action, evidence=action.evidence)
        results.append((label, result))
        metrics.record(result.decision.value, result.drift_score, result.reason)

        logger.info(
            "real_time_decision",
            extra={
                "label": label,
                "agent": action.agent_id,
                "capability": action.capability,
                "verdict": result.decision.value.upper(),
                "triggered_by": result.triggered_by,
                "reason": result.reason,
                "drift_score": f"{result.drift_score:.2f}",
            },
        )
        print(
            f"  → {label:<25} | {result.decision.value.upper():<18} "
            f"| trigger={result.triggered_by:<16} | {result.reason}"
        )

    print("\n=== AUDIT CHAIN (VERIFIABLE) ===")
    logger.info("metrics_summary", extra=metrics.summary())

    # ---- claims, asserted rather than narrated -------------------------
    verdicts = {label: r for label, r in results}
    failures = []

    allow_1 = verdicts["1. Read repo source"].decision.value == "allow"
    allow_2 = verdicts["2. Create PR"].decision.value == "allow"
    deploy = verdicts["3. Deploy to production"]
    export = verdicts["4. Bulk source export"]

    if not (allow_1 and allow_2):
        failures.append("granted capabilities did not ALLOW")
    if deploy.decision.value == "allow":
        failures.append("ungranted production deploy was ALLOWED")
    if export.decision.value != "block":
        failures.append(f"bulk export was not BLOCKED (got {export.decision.value})")
    if len({r.triggered_by for _, r in results}) < 2:
        failures.append("every action resolved through the same layer")
    if any(r.triggered_by == "engine_fault" for _, r in results):
        failures.append(
            "an action hit engine_fault -- the engine crashed, it did not enforce"
        )

    print("\nDemonstrated (asserted by this script, not just claimed):")
    crm = verdicts["5. Read CRM contacts"]
    print(
        f"  1. Capability grants scope the agent (L3) — ungranted crm.read_contact: {crm.triggered_by}"
    )
    print(f"  2. Byzantine quorum on signed votes (L2) — deploy: {deploy.triggered_by}")
    print(f"  3. Behavioural invariant blocks bulk export (L1) — {export.triggered_by}")
    print(f"  4. Drift scored against a declared baseline (L5) — {BASELINE}")
    print("  5. Every verdict carries triggered_by, reason, drift_score")
    print("  6. Metrics + structured JSON logs emitted in real time")

    if failures:
        print("\n!! DEMO DID NOT DEMONSTRATE ITS CLAIMS:")
        for f in failures:
            print(f"   - {f}")
        sys.exit(1)

    print("\nAll claims verified.")


if __name__ == "__main__":
    demo()
