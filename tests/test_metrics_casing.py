"""MetricsExporter must count block reasons.

Reproduced from an external release audit: runtime.py calls
metrics.record(result.decision.value, ...) which passes the lowercase
enum value "block", but record() compared against uppercase "BLOCK" --
so block_reasons was ALWAYS empty. A security product's /metrics
silently reported zero enforcement reasons while blocking all day.
"""

from agent_dna.observability.metrics import MetricsExporter


def test_block_reason_is_counted_with_lowercase_verdict():
    m = MetricsExporter()
    # exactly what runtime.py passes: the lowercase enum .value
    m.record("block", drift_score=0.9, reason="invariant: forbidden capability")
    m.record("block", drift_score=0.8, reason="invariant: forbidden capability")
    m.record("allow", drift_score=0.0, reason="")
    s = m.summary()
    assert s["block_reasons"] == {"invariant: forbidden capability": 2}, (
        f"block reasons not counted; got {s['block_reasons']} -- the "
        "verdict-casing mismatch dropped them")
    assert s["verdict_distribution"] == {"block": 2, "allow": 1}


def test_allow_does_not_count_as_a_block_reason():
    m = MetricsExporter()
    m.record("allow", drift_score=0.0, reason="baseline")
    assert m.summary()["block_reasons"] == {}
