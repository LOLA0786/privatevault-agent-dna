"""
Open Policy Agent (OPA) Adapter — production-grade.
Connects DecisionEngine.policy to OPA /v1/data/{path} endpoint.
Reads agent skills, capabilities, and arguments from local context.
Falls back gracefully if OPA unreachable.
"""
from urllib.request import urlopen, Request
from urllib.error import URLError
import json


class OPAPolicyAdapter:
    def __init__(self, endpoint: str = "http://localhost:8181",
                 default_decision: str = "allow"):
        self.endpoint = endpoint.rstrip("/")
        self.default_decision = default_decision

    def _call_opa(self, path: str, payload: dict) -> dict:
        url = f"{self.endpoint}/v1/data/{path}"
        req = Request(url, data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=2) as resp:
                return json.loads(resp.read().decode())
        except URLError:
            # Fail open to default (configurable) if OPA unavailable
            return {"result": {"fired": False, "outcome": self.default_decision,
                               "reason": "opa_unavailable_default"}}

    def check(self, agent_id: str = None, capability: str = None,
              arguments: dict = None, evidence: dict = None) -> type:
        payload = {
            "input": {
                "agent_id": agent_id,
                "capability": capability,
                "arguments": arguments or {},
                "evidence": evidence or {},
            }
        }
        path = "agent/governance"  # standard OPA policy path
        result = self._call_opa(path, payload)
        # OPA returns {"result": {...}}; extract outcome
        opa_result = result.get("result", {})
        fired = opa_result.get("fired", False)
        outcome = opa_result.get("outcome", "allow")
        reason = opa_result.get("reason", "opa_evaluated")
        return type("PolicyResult", (),
                    {"fired": fired, "outcome": outcome, "reason": reason})
