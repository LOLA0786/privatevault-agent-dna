class LocalPolicyAdapter:
    def __init__(self, profile_dir="profiles"): self.profile_dir = profile_dir
    def check(self, agent_id=None, capability=None, arguments=None, evidence=None):
        return type("R", (), {"fired": False, "outcome": "allow", "reason": "local_adapter_default"})()
