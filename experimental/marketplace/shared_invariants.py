"""
Shared Invariant Library — cross-organization defense patterns.

Organizations can publish invariant patterns (not agent data)
that other deployments can import. Example patterns:
- "payments.initiate_wire requires approval > $10k"
- "storage.bulk_export forbidden for sales roles"
- "finance.agent cannot access crm.bulk_delete"

These are policy rules, not execution traces.
"""


class SharedInvariantLibrary:
    def __init__(self):
        self.invariants: list[dict] = []

    def publish(self, invariant: dict) -> None:
        """
        Publish an anonymized invariant pattern.
        invariant must contain: name, domain, rule_type (topology/temporal/authority/etc.)
        Must NOT contain: agent_ids, execution traces, raw arguments.
        """
        required = {"name", "domain", "rule_type"}
        if not required.issubset(invariant.keys()):
            raise ValueError(f"invariant must contain {required}")
        # Strip any accidental identity leakage before storage
        safe = {
            k: v
            for k, v in invariant.items()
            if k not in ("agent_id", "execution_trace")
        }
        self.invariants.append(safe)

    def import_for_agent(self, agent_domain: str) -> list[dict]:
        return [inv for inv in self.invariants if inv.get("domain") == agent_domain]
