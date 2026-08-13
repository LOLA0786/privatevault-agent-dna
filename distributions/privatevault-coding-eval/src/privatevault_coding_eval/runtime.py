"""Construction of actual PrivateVault runtime components for evaluation."""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from typing import Any

from agent_dna import (
    AgentAction,
    BehaviorDynamics,
    CapabilityManifold,
    DecisionEngine,
    DriftScorer,
    ExecutionTrace,
)
from agent_dna.consensus.checker import ConsensusChecker
from agent_dna.grants import GrantRegistry
from agent_dna.policy.checker import PolicyChecker
from agent_dna.policy.schema import parse_policy_dict
from agent_dna.reference_policies import SequenceInvariantEngine


def trusted_training_traces() -> tuple[ExecutionTrace, ...]:
    """Return the explicit trusted coding-agent behavior fixture."""

    capabilities = (
        "git.read_repo",
        "file.write",
        "test.run",
        "git.create_pr",
        "git.push",
        "deploy.production",
        "dependency.install",
        "secrets.read",
    )

    traces: list[ExecutionTrace] = []

    for run in range(20):
        trace = ExecutionTrace(agent_id="code-agent-01")
        timestamp = 1_700_000_000.0 + run * 100

        for index, capability in enumerate(capabilities):
            trace.add(
                AgentAction(
                    agent_id="code-agent-01",
                    capability=capability,
                    timestamp=timestamp + index,
                    arguments={},
                )
            )

        traces.append(trace)

    return tuple(traces)


def actual_drift_scorer() -> DriftScorer:
    """Fit the actual Agent DNA manifold and Markov dynamics."""

    traces = trusted_training_traces()

    manifold = CapabilityManifold().fit(traces)
    dynamics = BehaviorDynamics().fit(traces)

    return DriftScorer(
        manifold,
        dynamics,
    )


def actual_grant_registry(
    grants: Sequence[Mapping[str, Any]],
) -> GrantRegistry:
    """Populate the actual GrantRegistry from scenario configuration."""

    registry = GrantRegistry()
    now = time.time()

    for item in grants:
        expires_in = item.get("expires_in")

        if expires_in is not None and not isinstance(
            expires_in,
            (int, float),
        ):
            raise ValueError("grant.expires_in must be numeric")

        grant = registry.grant(
            agent_id=str(item["agent_id"]),
            capability=str(item["capability"]),
            granted_by=str(item["granted_by"]),
            expires_at=(now + float(expires_in) if expires_in is not None else None),
            budget=(float(item["budget"]) if item.get("budget") is not None else None),
        )

        if item.get("revoked"):
            registry.revoke(
                grant.grant_id,
                revoked_by="evaluation-owner",
            )

    return registry


def actual_decision_engine(
    *,
    grants: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    consensus_enabled: bool,
) -> DecisionEngine:
    """Construct the actual production decision-engine composition."""

    policy_document = parse_policy_dict(dict(policy))
    policy_checker = PolicyChecker(policy_document)

    invariants = SequenceInvariantEngine(
        {
            (
                "git.read_repo",
                "deploy.production",
            ),
            (
                "git.read_repo",
                "secrets.read",
            ),
        }
    )

    consensus = ConsensusChecker() if consensus_enabled else None

    return DecisionEngine(
        scorer=actual_drift_scorer(),
        invariants=invariants,
        authorizer=actual_grant_registry(grants),
        drift_threshold=0.8,
        consensus=consensus,
        policy=policy_checker,
    )
