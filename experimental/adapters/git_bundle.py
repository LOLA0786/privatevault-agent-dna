# EXPERIMENTAL — moved from agent_dna/adapters_policy; kept here only
# as a sketch of a git-bundle-distributed policy source. NOT wired into
# the enforced core; always returns a non-firing result.
class GitBundleAdapter:
    def __init__(self, bundle_path="policies/bundle.json"):
        self.bundle_path = bundle_path

    def check(self, agent_id=None, capability=None, arguments=None, evidence=None):
        return type(
            "R",
            (),
            {"fired": False, "outcome": "allow", "reason": "git_bundle_default"},
        )()
