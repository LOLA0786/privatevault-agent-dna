# Enforcement Middleware — a reference pattern, not a product

Every agent framework, orchestrator, or custom-built harness has one
thing in common: a point where it's about to call a tool on the
agent's behalf. That's the only integration point PrivateVault needs.

This is not a connector for a specific harness. It's the minimal
pattern — wrap your tool-call step with one check, before execution.
Two versions below: HTTP (works from any language, any framework),
and MCP (works from any MCP-speaking client).

## The shape, in one sentence

Before your harness executes a tool call, ask PrivateVault; if the
answer is anything other than ALLOW, don't execute yet.

## Pattern 1 — HTTP

```python
import requests

def enforced_tool_call(agent_id, capability, arguments, evidence=None):
    """Wrap this around your harness's existing tool-execution step.
    Everything below the 'decide' call is your harness's own logic,
    unchanged."""

    decision = requests.post(
        "http://localhost:8000/v1/decide",
        json={
            "agent_id": agent_id,
            "capability": capability,
            "timestamp": time.time(),
            "arguments": arguments,
            "evidence": evidence or {},
        },
        headers={"X-API-Key": PV_API_KEY},
    )

    if decision.status_code == 403:
        # BLOCK -- do not execute, ever, for this specific action
        raise ActionBlocked(decision.json()["reason"])

    if decision.status_code == 202:
        # REQUIRE_APPROVAL -- route to your harness's human-in-the-loop
        # step before proceeding. Do NOT execute yet.
        route_to_approval_queue(decision.json())
        return

    # 200 -- ALLOW. Proceed with your harness's normal execution path.
    record = decision.json()["record"]
    result = your_harness_executes_the_tool_call(capability, arguments)

    # Report back what actually happened -- this is what makes
    # enforcement divergence detectable later.
    requests.post(
        "http://localhost:8000/v1/outcome",
        json={"decision_id": record["decision_id"], "status": "ok"},
        headers={"X-API-Key": PV_API_KEY},
    )
    return result
```

**The one rule that matters:** your harness's execution path must be
structurally incapable of running the tool call on any status other
than 200. If a 403 can be caught and ignored, or a 202 can be
skipped past, this is a suggestion box, not enforcement. The
integration is only as strong as the harness's willingness to treat
a BLOCK as final.

## Pattern 2 — MCP

If your harness already speaks MCP, the same pattern is a tool call
instead of an HTTP request:

```python
# pseudocode -- exact client API depends on your MCP client library
result = await mcp_client.call_tool("pv_decide", {
    "agent_id": agent_id,
    "capability": capability,
    "arguments": arguments,
    "evidence": evidence,
})

if result["decision"] == "block":
    raise ActionBlocked(result["reason"])
elif result["decision"] == "require_approval":
    route_to_approval_queue(result)
else:
    # allow -- proceed with your harness's own execution
    outcome = your_harness_executes_the_tool_call(capability, arguments)
    await mcp_client.call_tool("pv_report_outcome", {
        "decision_id": result["decision_id"], "status": "ok",
    })
```

Six tools cover the full loop: `pv_decide`, `pv_report_outcome`,
`pv_verify`, `pv_lineage`, `pv_blocked`, `pv_divergent`. See
`agent_dna/mcp_server.py`.

## What this pattern gives you regardless of harness

- Every action, blocked or allowed, becomes a sealed, hash-chained,
  signed record -- independent of what harness produced it.
- Enforcement divergence detection (a BLOCK whose action ran anyway)
  works the same way no matter which harness reported the outcome.
- Evidence (the `evidence` dict) is supplied by whatever your harness
  already knows about the action's context -- see
  `spec/contracts/evidence-integration.md` for the exact shape each
  precedence level consumes.

## What this pattern does NOT give you

- It does not discover or connect to your harness automatically --
  someone on your side (or PrivateVault's, for a scoped pilot) writes
  the ~10-30 lines that call `/v1/decide` at the right point in your
  harness's existing execution loop.
- It does not retrofit enforcement onto actions your harness has
  already executed. This is pre-execution by design; if the wrapper
  isn't placed before the real tool call, there's nothing to enforce.
- It is not a claim that any specific harness (LangChain, CrewAI, a
  custom in-house orchestrator, etc.) is pre-integrated. None are,
  today. This document is the pattern; a real integration for a named
  harness is scoped work once there's a real counterpart.
