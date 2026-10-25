# 0038: The pin is required, and a decision binds the whole input

Status:     accepted
Date:       2026-10-25
Pinned by:  tests/test_signed_decisions.py::test_hook_without_a_pin_refuses;
            tests/test_signed_decisions.py::test_a_decision_covers_only_its_content;
            tests/test_signed_decisions.py::test_an_oversized_mcp_input_is_refused

## What forced the decision
An external review (2026-10-25) found two gaps in ADR 0035:
1. With no key pinned, the hook kept the old behaviour and accepted any
   unsigned answer. `pv up` writes the key, but a deployment that lost or
   never set it ran unchecked without saying so.
2. A signed decision bound the arguments the hook sent, and those were
   not the whole call: a write sent its path but not its content, and an
   MCP input over 16 KB was cut to a preview. An allow for one write
   therefore also covered any other content at that path, and the policy
   never saw the end of a long MCP input.

## The decision
- With no key pinned (no `PV_DECISION_KEY`, no `PV_HOME/decision-key.pub`)
  the hook refuses every call and says how to pin one. `PV_ALLOW_UNSIGNED=1`
  restores the old behaviour, for a server that cannot sign; it is opt-in
  and documented as not for production.
- Every call carries `input_sha256`, the SHA-256 of Claude Code's whole tool
  input in canonical JSON. It is part of the arguments, so the signed
  record's `arguments_digest` covers it: a decision names those exact bytes,
  including a write's content and an edit's text.
- MCP and other tool inputs are sent whole. One larger than 256 KiB is
  refused before anything is sent, rather than truncated.

## Consequences
- A team server on another machine must set `PV_DECISION_KEY`; until then
  every call is refused, with the reason.
- The policy still sees a write's path and zone, not its content. Content is
  bound by the digest, not inspected. Inspecting content is a separate,
  future decision.
- MCP calls with very large inputs are refused. The limit is a constant,
  below the API's 1 MiB request limit.
