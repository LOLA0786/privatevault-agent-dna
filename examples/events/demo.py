from agent_dna.events import EventPublisher

publisher = EventPublisher()

publisher.publish(
    "pv.decisions",
    {
        "decision_id":"123",
        "status":"approved",
        "risk":0.03,
    },
)

publisher.flush()

print("Event published.")
