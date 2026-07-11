"""
Swarm-level circuit breaker — the distributed salami drain.

5 agents x $900 each: every payment passes its per-agent volume cap
($1,000), so per-agent breakers see nothing. The declared group cap
($4,000) trips on aggregate; all members suspended at the existing
pre-gate; a non-member is untouched. Per-agent reset is refused on
group suspensions; group reset is capability-gated, atomic, chained.
"""

import pytest

from agent_dna.circuit_breaker import (
    RESET_CAPABILITY,
    RESET_GROUP_CAPABILITY,
    BreakerConfig,
    CircuitBreaker,
)


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, dt):
        self.t += dt


MEMBERS = [f"pay-agent-{i}" for i in range(5)]


@pytest.fixture
def breaker(tmp_path):
    return CircuitBreaker(
        tmp_path / "b.db",
        BreakerConfig(
            max_decisions=None,
            window_seconds=60.0,
            max_cumulative_amount=1000.0,      # per-agent cap
            max_consecutive_refusals=None,
            groups={"payments-swarm": MEMBERS},
            group_volume_caps={"payments-swarm": 4000.0},
        ),
        clock=FakeClock(),
    )


def test_distributed_drain_trips_group(breaker):
    tripped_on = None
    for i, agent in enumerate(MEMBERS):
        breaker._clock.tick(1.0)
        reason = breaker.observe(agent, "allow", amount=900.0)
        assert not breaker.pre_gate(agent) or reason, (
            f"{agent} tripped per-agent at 900 < 1000 cap"
        )
        if reason is not None:
            tripped_on = (i, reason)
            break

    assert tripped_on is not None, "distributed drain never tripped"
    i, reason = tripped_on
    assert i == 4                       # 5th agent: 4500 > 4000
    assert reason.startswith("group_trip:payments-swarm")

    for agent in MEMBERS:               # every member suspended
        assert breaker.is_tripped(agent), f"{agent} not suspended"

    breaker.observe("outsider-agent", "allow", amount=900.0)
    assert not breaker.is_tripped("outsider-agent")

    assert breaker.verify_log()


def test_per_agent_reset_refused_on_group_suspension(breaker):
    for agent in MEMBERS:
        breaker._clock.tick(1.0)
        breaker.observe(agent, "allow", amount=900.0)
    assert breaker.is_tripped(MEMBERS[0])

    grants = {("ciso-1", RESET_CAPABILITY)}
    authorize = lambda a, c: (a, c) in grants

    with pytest.raises(PermissionError, match="GROUP suspension"):
        breaker.reset(MEMBERS[0], actor_id="ciso-1", authorize=authorize)
    assert breaker.is_tripped(MEMBERS[0]), "per-agent reset dissolved group trip"


def test_group_reset_gated_atomic_chained(breaker):
    for agent in MEMBERS:
        breaker._clock.tick(1.0)
        breaker.observe(agent, "allow", amount=900.0)

    grants = {("ciso-1", RESET_CAPABILITY)}   # reset but NOT reset_group
    authorize = lambda a, c: (a, c) in grants
    with pytest.raises(PermissionError, match="reset_group"):
        breaker.reset_group("payments-swarm", "ciso-1", authorize)
    assert all(breaker.is_tripped(a) for a in MEMBERS)

    grants.add(("ciso-1", RESET_GROUP_CAPABILITY))
    record = breaker.reset_group("payments-swarm", "ciso-1", authorize)
    assert all(not breaker.is_tripped(a) for a in MEMBERS)  # all or none
    assert record["event_type"] == "group_reset"
    assert record["actor"] == "ciso-1"
    assert breaker.verify_log()

    with pytest.raises(ValueError, match="unknown group"):
        breaker.reset_group("no-such-swarm", "ciso-1", authorize)
