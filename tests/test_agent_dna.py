from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    DeterministicGate,
    DriftScorer,
    PolicyDecision,
    Posture,
    Severity,
)

from agent_dna.adapters import (
    synthetic_compromised_trace,
    synthetic_normal_trace,
)

from agent_dna.trace import AgentAction


def _fit():
    training = [
        synthetic_normal_trace(seed=i, loops=6)
        for i in range(8)
    ]

    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)

    return DriftScorer(
        manifold,
        dynamics,
    )


def test_manifold_learns_vocabulary():
    manifold = CapabilityManifold().fit(
        [synthetic_normal_trace(seed=1)]
    )

    assert manifold.fitted
    assert manifold.known_capability("crm.read_contact")
    assert not manifold.known_capability("payments.initiate_wire")


def test_normal_actions_score_low():
    scorer = _fit()

    trace = synthetic_normal_trace(
        seed=123,
        loops=2,
    )

    prev = None

    for action in trace.actions:
        signal = scorer.score(
            action,
            prev,
        )

        assert signal.drift_score < 0.30, (
            action.capability,
            signal.drift_score,
        )

        prev = action.capability


def test_unseen_capability_is_critical():
    scorer = _fit()

    action = AgentAction(
        "sales-agent-01",
        "payments.initiate_wire",
        1.0,
        {
            "amount": 480000.0,
            "beneficiary": "x",
        },
    )

    signal = scorer.score(
        action,
        prev_capability="crm.read_contact",
    )

    assert signal.severity == Severity.CRITICAL
    assert signal.components["novelty"] == 1.0
    assert any(
        "never appeared" in r
        for r in signal.reasons
    )


def test_novel_categorical_argument_flagged():
    scorer = _fit()

    action = AgentAction(
        "sales-agent-01",
        "email.send",
        1.0,
        {
            "recipient_domain": "exfil-drop.ru",
            "attachments": 0,
        },
    )

    signal = scorer.score(
        action,
        prev_capability="crm.update_contact",
    )

    assert signal.components["arguments"] == 1.0

    assert any(
        "exfil-drop.ru" in r
        for r in signal.reasons
    )


def test_numeric_outlier_flagged():
    scorer = _fit()

    action = AgentAction(
        "sales-agent-01",
        "email.send",
        1.0,
        {
            "recipient_domain": "acme.com",
            "attachments": 99.0,
        },
    )

    signal = scorer.score(
        action,
        prev_capability="crm.update_contact",
    )

    assert signal.components["arguments"] > 0.0


def test_gate_cannot_override_policy_deny():
    scorer = _fit()
    gate = DeterministicGate()

    action = AgentAction(
        "sales-agent-01",
        "payments.initiate_wire",
        1.0,
        {"amount": 1.0},
    )

    signal = scorer.score(
        action,
        prev_capability="crm.read_contact",
    )

    decision = gate.decide(
        PolicyDecision.DENY,
        signal,
    )

    assert decision.decision == PolicyDecision.DENY


def test_gate_escalates_allow_on_critical():
    scorer = _fit()
    gate = DeterministicGate()

    action = AgentAction(
        "sales-agent-01",
        "storage.bulk_export",
        1.0,
        {
            "records": 50000,
            "destination": "unknown-host.io",
        },
    )

    signal = scorer.score(
        action,
        prev_capability="crm.read_contact",
    )

    decision = gate.decide(
        PolicyDecision.ALLOW,
        signal,
    )

    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL

    assert signal.recommended_posture in (
        Posture.RECOMMEND_BLOCK,
        Posture.REQUIRE_APPROVAL,
    )


def test_compromised_run_has_critical_actions():
    scorer = _fit()

    trace = synthetic_compromised_trace()

    severities = []
    prev = None

    for action in trace.actions:
        signal = scorer.score(
            action,
            prev,
        )

        severities.append(signal.severity)
        prev = action.capability

    assert Severity.CRITICAL in severities
