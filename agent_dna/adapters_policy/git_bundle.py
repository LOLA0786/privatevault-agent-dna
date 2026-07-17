class GitBundleAdapter:
    def __init__(self, bundle_path="policies/bundle.json"): self.bundle_path = bundle_path
    def check(self, agent_id=None, capability=None, arguments=None, evidence=None):
        return type("R", (), {"fired": False, "outcome": "allow", "reason": "git_bundle_default"})()
