from agent_dna.webhooks import WebhookDispatcher

dispatcher = WebhookDispatcher()

dispatcher.register(
    "local",
    "https://httpbin.org/post",
    "privatevault",
)

dispatcher.emit(
    "decision.blocked",
    {
        "decision_id":"123",
        "risk":0.98,
        "reason":"policy_violation",
    },
)

print("Webhook sent.")
