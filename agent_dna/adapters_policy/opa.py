class OPAPolicyAdapter:
    def __init__(self, endpoint="http://localhost:8181"): self.endpoint = endpoint
    def check(self, agent_id=None, capability=None, arguments=None, evidence=None):
        return type("R", (), {"fired": False, "outcome": "allow", "reason": "opa_adapter_default"})()
