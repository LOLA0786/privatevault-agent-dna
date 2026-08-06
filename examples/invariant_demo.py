from agent_dna import (
    AgentAction,
    ExecutionTrace,
    InvariantEngine,
    InvariantLearner,
)

#
# Trusted traces
#

t1 = ExecutionTrace("sales-agent")

t1.add(
    AgentAction(
        "sales-agent",
        "read_customer",
        1.0,
    )
)

t1.add(
    AgentAction(
        "sales-agent",
        "approve_invoice",
        2.0,
    )
)

t1.add(
    AgentAction(
        "sales-agent",
        "payments.initiate_wire",
        3.0,
    )
)

learner = InvariantLearner()

invariants = learner.fit([t1])

engine = InvariantEngine(
    invariants,
)

print("=" * 65)
print("VALID")
print("=" * 65)

result = engine.validate(
    "payments.initiate_wire",
    "approve_invoice",
)

print(result)

print()

print("=" * 65)
print("VIOLATION")
print("=" * 65)

result = engine.validate(
    "payments.initiate_wire",
    "crm.read_contact",
)

print(result)
