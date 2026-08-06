from agent_dna import (
    AgentAction,
    ExecutionTrace,
    InvariantEngine,
    InvariantLearner,
)

#
# Trusted history
#

trace = ExecutionTrace("bank-agent")

trace.add(AgentAction("bank-agent", "read_customer", 1))
trace.add(AgentAction("bank-agent", "approve_invoice", 2))
trace.add(AgentAction("bank-agent", "payments.initiate_wire", 3))

learner = InvariantLearner()
engine = InvariantEngine(learner.fit([trace]))

print("=" * 65)
print("VALID")
print("=" * 65)

print(
    engine.validate(
        "payments.initiate_wire",
        "approve_invoice",
    )
)

print()

print("=" * 65)
print("ATTACK")
print("=" * 65)

print(
    engine.validate(
        "payments.initiate_wire",
        "crm.read_contact",
    )
)
