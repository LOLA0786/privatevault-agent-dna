"""
Adapters: how real and synthetic traces get into Agent DNA.

`from_platform_event` is the integration point for *real* data — wire your
Temporal / multi-agent platform's per-step records (or the deterministic
firewall's decision log) into it. Real traces are where Agent DNA's value comes
from; the synthetic generators below exist only to make the demo and tests
runnable before that wiring exists. They are clearly labelled and should never be
presented to a buyer as evidence.
"""

from __future__ import annotations

import random
from typing import Any, Dict

from .trace import AgentAction, ExecutionTrace


# ---- REAL adapter (integration point) -----------------------------------

def from_platform_event(event: Dict[str, Any]) -> AgentAction:
    """
    Map one event from your runtime to an AgentAction.
    Adjust the key names to match your platform's schema.
    """
    return AgentAction(
        agent_id=event["agent_id"],
        capability=event["tool"],
        timestamp=float(event["ts"]),
        arguments=event.get("args", {}),
        context=event.get("context", {}),
        outcome=event.get("outcome", "ok"),
    )


# ---- SYNTHETIC scaffolding (demo/tests only) -----------------------------

_NORMAL_LOOP = [
    (
        "crm.read_contact",
        lambda r: {
            "source": "salesforce",
            "records": r.randint(1, 3),
        },
    ),
    (
        "crm.enrich_contact",
        lambda r: {
            "provider": "clearbit",
            "records": r.randint(1, 3),
        },
    ),
    (
        "crm.update_contact",
        lambda r: {
            "source": "salesforce",
            "fields_changed": r.randint(1, 4),
        },
    ),
    (
        "email.send",
        lambda r: {
            "recipient_domain": r.choice(
                [
                    "acme.com",
                    "globex.com",
                    "initech.com",
                ]
            ),
            "attachments": 0,
        },
    ),
    (
        "calendar.create_event",
        lambda r: {
            "attendees": r.randint(1, 3),
        },
    ),
]


def synthetic_normal_trace(
    agent_id: str = "sales-agent-01",
    loops: int = 6,
    seed: int | None = None,
    start_ts: float = 1_700_000_000.0,
) -> ExecutionTrace:
    """
    SYNTHETIC — benign sales agent routine.
    """
    r = random.Random(seed)
    trace = ExecutionTrace(agent_id=agent_id)

    ts = start_ts

    for _ in range(loops):
        for cap, arg_fn in _NORMAL_LOOP:
            ts += r.uniform(20, 90)
            trace.add(
                AgentAction(
                    agent_id,
                    cap,
                    ts,
                    arg_fn(r),
                )
            )

    return trace


def synthetic_compromised_trace(
    agent_id: str = "sales-agent-01",
    seed: int | None = 7,
    start_ts: float = 1_700_100_000.0,
) -> ExecutionTrace:
    """
    SYNTHETIC — prompt-injected agent exhibiting behavioural drift.
    """
    r = random.Random(seed)
    trace = ExecutionTrace(agent_id=agent_id)

    ts = start_ts

    # Starts normally
    for cap, arg_fn in _NORMAL_LOOP[:3]:
        ts += r.uniform(20, 90)
        trace.add(
            AgentAction(
                agent_id,
                cap,
                ts,
                arg_fn(r),
            )
        )

    # Drift begins
    ts += 5
    trace.add(
        AgentAction(
            agent_id,
            "storage.bulk_export",
            ts,
            {
                "source": "salesforce",
                "records": 50000,
                "destination": "unknown-host.io",
            },
        )
    )

    ts += 5
    trace.add(
        AgentAction(
            agent_id,
            "email.send",
            ts,
            {
                "recipient_domain": "exfil-drop.ru",
                "attachments": 5,
            },
        )
    )

    ts += 5
    trace.add(
        AgentAction(
            agent_id,
            "payments.initiate_wire",
            ts,
            {
                "amount": 480000.0,
                "beneficiary": "unverified-acct-9931",
            },
        )
    )

    return trace
