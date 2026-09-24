"""ADR-0018 PR-A: declared swarm groups reach the production breaker.

Before this change the group (distributed-drain) breaker was reachable
only by constructing CircuitBreaker directly; build_production_runtime
never passed groups, so no deployment could enable it.
"""

import json

import pytest

from agent_dna.composition import RuntimeConfig, build_production_runtime

MEMBERS = [f"pay-agent-{i}" for i in range(5)]
GOOD = {
    "groups": {"payments-swarm": MEMBERS},
    "group_volume_caps": {"payments-swarm": 4000.0},
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("PV_SECURE_PROFILE", "PV_BREAKER_GROUPS_FILE"):
        monkeypatch.delenv(var, raising=False)


def _cfg(tmp_path, **kw):
    return RuntimeConfig(db_path=str(tmp_path / "pv.db"), **kw)


def _write(tmp_path, body, name="groups.json"):
    p = tmp_path / name
    p.write_text(body if isinstance(body, str) else json.dumps(body))
    return str(p)


def test_groups_file_flows_into_production_breaker(tmp_path):
    rt = build_production_runtime(
        _cfg(tmp_path, breaker_groups_file=_write(tmp_path, GOOD))
    )
    assert rt.breaker.config.groups == {"payments-swarm": MEMBERS}
    assert rt.breaker.config.group_volume_caps == {"payments-swarm": 4000.0}
    assert "group_volume_caps" in rt.composition["circuit_breaker"]["detail"]


def test_from_env_reads_groups_file(tmp_path, monkeypatch):
    path = _write(tmp_path, GOOD)
    monkeypatch.setenv("PV_BREAKER_GROUPS_FILE", path)
    assert RuntimeConfig.from_env().breaker_groups_file == path


def _drain(rt):
    reasons = [rt.breaker.observe(a, "allow", amount=900.0) for a in MEMBERS]
    return reasons, [rt.breaker.is_tripped(a) for a in MEMBERS]


def test_production_breaker_trips_swarm_under_per_agent_cap(tmp_path):
    rt = build_production_runtime(
        _cfg(
            tmp_path,
            breaker_max_amount=1000.0,
            breaker_window_seconds=60.0,
            breaker_groups_file=_write(tmp_path, GOOD),
        )
    )
    reasons, tripped = _drain(rt)
    assert reasons[:4] == [None] * 4, reasons
    assert reasons[4] and reasons[4].startswith("group_trip:payments-swarm")
    assert all(tripped)
    rt.breaker.observe("outsider-agent", "allow", amount=900.0)
    assert not rt.breaker.is_tripped("outsider-agent")


def test_negative_control_same_swarm_without_file_is_not_tripped(tmp_path):
    rt = build_production_runtime(
        _cfg(tmp_path, breaker_max_amount=1000.0, breaker_window_seconds=60.0)
    )
    reasons, tripped = _drain(rt)
    assert reasons == [None] * 5 and not any(tripped)


BAD = {
    "unknown_top_key": {**GOOD, "extra": 1},
    "missing_caps": {"groups": GOOD["groups"]},
    "empty_groups": {"groups": {}, "group_volume_caps": {}},
    "cap_without_group": {
        "groups": GOOD["groups"],
        "group_volume_caps": {"payments-swarm": 1.0, "ghost": 1.0},
    },
    "group_without_cap": {
        "groups": {**GOOD["groups"], "g2": ["a"]},
        "group_volume_caps": GOOD["group_volume_caps"],
    },
    "zero_cap": {**GOOD, "group_volume_caps": {"payments-swarm": 0}},
    "negative_cap": {**GOOD, "group_volume_caps": {"payments-swarm": -5}},
    "bool_cap": {**GOOD, "group_volume_caps": {"payments-swarm": True}},
    "string_cap": {**GOOD, "group_volume_caps": {"payments-swarm": "4000"}},
    "empty_members": {**GOOD, "groups": {"payments-swarm": []}},
    "duplicate_member": {**GOOD, "groups": {"payments-swarm": ["a", "a"]}},
    "blank_member": {**GOOD, "groups": {"payments-swarm": [" "]}},
}
RAW = {
    "nan_cap": '{"groups": {"g": ["a"]}, "group_volume_caps": {"g": NaN}}',
    "duplicate_json_key": '{"groups": {"g": ["a"]}, "groups": {"g": ["b"]}, '
    '"group_volume_caps": {"g": 1}}',
    "not_json": "groups: nope",
}


@pytest.mark.parametrize("case", sorted(BAD) + sorted(RAW))
def test_malformed_groups_file_fails_closed_at_startup(tmp_path, case):
    body = BAD.get(case, RAW.get(case))
    with pytest.raises(ValueError):
        build_production_runtime(
            _cfg(tmp_path, breaker_groups_file=_write(tmp_path, body))
        )


def test_missing_groups_file_fails_closed(tmp_path):
    with pytest.raises(ValueError):
        build_production_runtime(
            _cfg(tmp_path, breaker_groups_file=str(tmp_path / "absent.json"))
        )


# ---- end-to-end: the real production decision path -------------------

from agent_dna.trace import AgentAction  # noqa: E402


def _pay(agent, i):
    return AgentAction(
        agent_id=agent,
        capability="payments.transfer",
        timestamp=1000.0 + i,
        arguments={"amount": 900.0},
        context={},
    )


def _run_swarm(rt):
    acts = [_pay(a, i) for i, a in enumerate(MEMBERS)]
    got = rt.engine._amount_fn(acts[0], None)
    assert got is not None and float(got) == 900.0, (
        f"production amount extractor read {got!r}; the test action does "
        f"not carry its amount where GuardedEngine looks"
    )
    return [rt.engine.decide(a) for a in acts]


def test_swarm_under_per_agent_cap_is_blocked_through_production_engine(tmp_path):
    rt = build_production_runtime(
        _cfg(
            tmp_path,
            breaker_max_amount=1000.0,
            breaker_window_seconds=60.0,
            breaker_groups_file=_write(tmp_path, GOOD),
        )
    )
    results = _run_swarm(rt)
    for r in results[:4]:
        assert "group_trip" not in (r.reason or ""), r.reason
    last = results[4]
    assert last.decision.value == "block", last
    assert last.triggered_by == "circuit_breaker", last.triggered_by
    assert "group_trip:payments-swarm" in last.reason, last.reason
    again = rt.engine.decide(_pay(MEMBERS[0], 10))
    assert again.decision.value == "block" and again.triggered_by == "circuit_breaker"


def test_negative_control_swarm_passes_breaker_without_groups_file(tmp_path):
    rt = build_production_runtime(
        _cfg(tmp_path, breaker_max_amount=1000.0, breaker_window_seconds=60.0)
    )
    results = _run_swarm(rt)
    assert all(r.triggered_by != "circuit_breaker" for r in results), [
        (r.triggered_by, r.reason) for r in results
    ]
