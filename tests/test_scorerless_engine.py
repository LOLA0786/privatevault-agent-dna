"""A DecisionEngine built without a scorer must still decide.

scorer=None is a supported configuration: decide_from() callers supply
their own signal, and scan/replay constructs with scorer=None
deliberately. Before this test existed, calling decide() on such an
engine raised AttributeError, which fail-closed converted into
BLOCK/engine_fault -- every action in end_to_end_coding_agents_demo.py
was blocked by a crash while the demo reported it as enforcement.

The suite missed it because test_request_id_propagation.py builds a
bare engine, calls decide(), and only asserts request_id reaches the
record -- which an engine_fault record still satisfies.
"""
from agent_dna import AgentAction, DecisionEngine


def test_bare_engine_decides_instead_of_faulting():
    engine = DecisionEngine()
    result = engine.decide(AgentAction("a1", "git.read_repo", 1.0))
    assert result.triggered_by != "engine_fault", result.reason


def test_inert_drift_is_declared_not_implied():
    """An unattached layer must say so, never look like a clean signal."""
    engine = DecisionEngine()
    result = engine.decide(AgentAction("a1", "git.read_repo", 1.0))
    assert result.drift_score == 0.0
    assert any("inert" in r for r in result.advisory_reasons), result.advisory_reasons
