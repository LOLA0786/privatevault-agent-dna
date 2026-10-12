# ADR-0018: Swarm controls — controller binding and aggregate limits

Status:     proposed
Date:       2026-09-23

## Context

Every per-agent control (baseline, breaker, maker!=checker, quorum
vote) is keyed on `agent_id`. Identity is key-bound (`_enforce_identity`,
connector `verify_scope`), so a caller cannot rename itself. But a
single operator holding N keys presents N independent agents, and:

- F1  API keys carry only {name, scope}; no controller (apikeys.py).
- F2  Group breaker (distributed drain) exists and is tested but is not
      wired into composition.py / api/server.py; no PV_* flag enables it.
- F3  Latent: ConnectorMiddleware.handle() takes
      `execution_action.subject_principal` from request.context
      (middleware.py:141). Shipped adapters do not expose it to callers:
      MCP adapter passes only execution_id (adapters/mcp.py:91-100);
      gateway sets it from the bound session (mediator.py:389). Hazard
      for any future adapter or direct library caller.
- F4  CABI initiate/approve classification is substring-based on intent
      names (dual_control.py:14-28); unmatched names are unchecked.
- F5  Quorum dedupes per agent_id; no controller diversity.
- F6  No per-destination aggregate cap across agents.
- F7  No controller-wide halt.
- F8  No delegation fan-out cap (attenuation exists: authority_v01.py:1385).

## Threat model (in scope)

A controller operating many credentialed agents through the gate, that
tries to: split a forbidden total across agents (salami), self-approve
via a second agent (collusion), manufacture quorum from clones, spawn
sub-agents to multiply authority, or outrun per-agent breakers.

## Out of scope (goes in WHAT-WE-DO-NOT-CLAIM.md)

Agents whose actions do not pass through the gate; coordination via
side channels (shared memory, prompts, external stores); compromise of
the operator who issues keys; model-level collusion detection.

## Decision — delivered as independent PRs

| PR | Control | Closes | DRP change |
|----|---------|--------|-----------|
| A | Wire group breaker: PV_BREAKER_GROUPS_FILE {groups, caps}; invalid file fails closed | F2 | no |
| B | (hardening) middleware ignores/rejects caller subject_principal != key identity | F3 | no |
| C | Key entry gains `controller`; Principal.controller; breaker implicit group per controller; CABI + quorum count distinct controllers | F1, F5 | no (record in context) |
| D | Explicit capability role map (initiate/approve/none); under PV_SECURE_PROFILE an unmapped payment-rail capability fails closed | F4 | no |
| E | Per-destination aggregate cap across all agents in window | F6 | no |
| F | Controller halt; reset requires dual control (multi_agent/dual_control) | F7 | no |
| G | Fan-out cap on child grants per parent | F8 | no |
| H | `controller_id` sealed in DecisionRecord | audit | yes -> drp/0.3, own ADR, Rust parity |

## Rules for every PR

1. Failing test first, named after the attack (e.g.
   `test_two_keys_one_controller_cannot_self_approve`).
2. Negative control: revert the fix, the test fails for the stated reason.
3. Escalation-only: a swarm control may tighten a verdict, never relax one.
4. Default behaviour unchanged unless PV_SECURE_PROFILE=1 or explicitly configured.
5. One claim line per control in WHAT-WE-DO-NOT-CLAIM.md, pinned to its test (ADR-0011).
6. Test-count claim updated only against the no-wheel collection.

## Consequences

Single-controller deployments see no change. Multi-controller
deployments must declare controllers in the key file under the secure
profile; a key without one fails startup rather than defaulting.

## Addendum 2026-09-24: containment brief, verified against the code

- F9  Nothing at consume or dispatch time checked suspension or grant
      revocation: a permit minted before its agent was suspended could
      still be dispatched until expiry. Closed by PR-J (this change).
- F10 An observed 401/403 from the target is recorded as closure
      `REJECTED` (exact_byte_http.py) but nothing latches on it.
- F11 Grant revocation is in-memory (`GrantRegistry.revoke`) and not
      reachable through the API.
- F12 No reference containment deployment in `deploy/`.

| PR | Control | Closes |
|----|---------|--------|
| J  | Suspension (agent, organisation, authorization) checked inside the consume transaction; refused as DISPATCH_SUSPENDED before any byte is sent | F9 |
| J2 | /v1/suspend; lifting requires dual control | F9 |
| I  | Target deny-latch: policy denial or observed 401/403 suspends (root workflow, target) for every child and tool | F10 |
| K  | Reference containment deployment: agent container egress only via the gateway; bypass test script | F12 |
| L  | Inbound Envoy ext_authz adapter at the customer edge | - |
