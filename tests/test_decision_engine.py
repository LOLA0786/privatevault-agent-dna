from agent_dna import (
    BehaviorDynamics,
    CapabilityGrant,
    CapabilityManifold,
    Decision,
    DecisionEngine,
    DriftScorer,
    GrantAuthorizationPolicy,
    SequenceInvariantEngine,
    Severity,
    InvariantViolation,
)
from agent_dna.advisory import AdvisorySignal, Posture
from agent_dna.adapters import synthetic_normal_trace
from agent_dna.trace import AgentAction


def _signal(
    drift: float,
    capability: str = "x.cap",
    severity: Severity = Severity.INFO,
):
    return AdvisorySignal(
        agent_id="agent-1",
        capability=capability,
        drift_score=drift,
        severity=severity,
        components={},
        reasons=[],
        recommended_posture=Posture.LOG,
    )


# ------------------------------------------------------------------
# Pure precedence
# ------------------------------------------------------------------

def test_invariant_violation_blocks():

    engine = DecisionEngine()

    res = engine.decide_from(
        signal=_signal(0.0),
        invariant=InvariantViolation(
            violated=True,
            message="forbidden transition",
        ),
        authorized=True,
    )

    assert res.decision == Decision.BLOCK
    assert res.triggered_by == "invariant"


def test_invariant_wins_over_everything():

    engine = DecisionEngine()

    res = engine.decide_from(
        signal=_signal(
            0.95,
            severity=Severity.CRITICAL,
        ),
        invariant=InvariantViolation(
            violated=True,
            message="blocked",
        ),
        authorized=False,
    )

    assert res.decision == Decision.BLOCK
    assert res.triggered_by == "invariant"


def test_unauthorized_requires_approval():

    engine = DecisionEngine()

    res = engine.decide_from(
        signal=_signal(0.0),
        invariant=InvariantViolation(
            violated=False,
            message="",
        ),
        authorized=False,
    )

    assert res.decision == Decision.REQUIRE_APPROVAL
    assert res.triggered_by == "authorization"


def test_authorized_but_high_drift_requires_approval():

    engine = DecisionEngine(
        drift_threshold=0.30,
    )

    res = engine.decide_from(
        signal=_signal(
            0.90,
            severity=Severity.CRITICAL,
        ),
        invariant=InvariantViolation(
            violated=False,
            message="",
        ),
        authorized=True,
    )

    assert res.decision == Decision.REQUIRE_APPROVAL
    assert res.triggered_by == "drift"


def test_normal_allows():

    engine = DecisionEngine(
        drift_threshold=0.30,
    )

    res = engine.decide_from(
        signal=_signal(0.05),
        invariant=InvariantViolation(
            violated=False,
            message="",
        ),
        authorized=True,
    )

    assert res.decision == Decision.ALLOW
    assert res.triggered_by == "baseline"


def test_drift_threshold_is_honoured():

    engine = DecisionEngine(
        drift_threshold=0.50,
    )

    res = engine.decide_from(
        signal=_signal(0.45),
        invariant=InvariantViolation(
            violated=False,
            message="",
        ),
        authorized=True,
    )

    assert res.decision == Decision.ALLOW


def test_precedence_order():

    engine = DecisionEngine(
        drift_threshold=0.30,
    )

    res = engine.decide_from(
        signal=_signal(
            0.95,
            severity=Severity.CRITICAL,
        ),
        invariant=InvariantViolation(
            violated=True,
            message="policy invariant",
        ),
        authorized=False,
    )

    assert res.decision == Decision.BLOCK
    assert res.triggered_by == "invariant"


# ------------------------------------------------------------------
# Wired integration
# ------------------------------------------------------------------

def _engine():

    training = [
        synthetic_normal_trace(
            seed=i,
            loops=6,
        )
        for i in range(8)
    ]

    manifold = CapabilityManifold().fit(training)

    dynamics = BehaviorDynamics().fit(training)

    scorer = DriftScorer(
        manifold,
        dynamics,
    )

    invariants = SequenceInvariantEngine(
        [
            (
                "email.send",
                "payments.initiate_wire",
            ),
        ]
    )

    authz = GrantAuthorizationPolicy(
        baseline_capabilities=list(
            manifold.capability_counts.keys()
        ),
        grants=[
            CapabilityGrant(
                capability="storage.bulk_export",
                approved_by="Security Team",
                ticket="OPS-842",
            ),
        ],
    )

    return DecisionEngine(
        scorer=scorer,
        invariants=invariants,
        authorizer=authz,
    )


def test_wired_authorized_novel_capability():

    engine = _engine()

    action = AgentAction(
        "sales-agent-01",
        "storage.bulk_export",
        1.0,
        {
            "records": 50000,
        },
    )

    res = engine.decide(
        action,
        prev_capability="crm.update_contact",
    )

    assert res.decision == Decision.REQUIRE_APPROVAL
    assert res.triggered_by == "drift"


def test_wired_invariant_blocks():

    engine = _engine()

    action = AgentAction(
        "sales-agent-01",
        "payments.initiate_wire",
        1.0,
        {
            "amount": 480000,
        },
    )

    res = engine.decide(
        action,
        prev_capability="email.send",
    )

    assert res.decision == Decision.BLOCK
    assert res.triggered_by == "invariant"


def test_wired_normal_action():

    engine = _engine()

    action = AgentAction(
        "sales-agent-01",
        "crm.read_contact",
        1.0,
        {
            "records": 2,
        },
    )

    res = engine.decide(
        action,
        prev_capability="calendar.create_event",
    )

    assert res.decision == Decision.ALLOW
    assert res.triggered_by == "baseline"
