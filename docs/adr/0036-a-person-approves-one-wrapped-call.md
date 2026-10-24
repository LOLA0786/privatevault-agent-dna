# 0036: A person approves one wrapped call (pv approve)

Status:     accepted
Date:       2026-10-24
Pinned by:  tests/test_pv_approve.py::test_one_approval_runs_one_call;
            tests/test_pv_approve.py::test_a_replayed_approval_is_refused;
            tests/test_pv_approve.py::test_an_approval_for_another_call_is_refused;
            tests/test_pv_approve.py::test_pv_approve_needs_a_terminal

## What forced the decision
Behind `pv wrap` (ADR 0032) only ALLOW was forwarded: REQUIRE_APPROVAL was
refused because MCP had no channel for a person's answer. So a payment tool
was either granted outright, letting the agent move money whenever the
policy allowed, or unusable. Banks want the middle: this refund, these
arguments, approved by a named person, once.

## The decision
- `pv approvers init --principal <person>` creates a local approver trust
  bundle in `~/.privatevault/approvers` (root, approver and receipt keys,
  owner-only; the approver's authority grant). `pv wrap` pins it
  (`PV_APPROVER_TRUST_BUNDLE`), so the gateway's engine runs the ADR 0020
  approval bridge.
- `ToolCallRequest` can carry an approval; the connector passes it to the
  engine with the digest of the execution action it decides
  (`execution_action_for`) and the agent's identities, so the bridge's
  checks apply unchanged: signature and key usage, authority chain,
  validity, organisation, same action digest, agent as subject, separation
  of duties, single-use claim in the ledger.
- When a call needs approval, the gateway files the exact execution action
  as `approvals/pending/<id>.json` and the refusal tells Claude the id.
- `pv approve <id>` shows the tool and arguments, requires a terminal and a
  typed `yes`, and signs an approval for that action, valid five minutes,
  into `approvals/approved/`. With no id it lists what is waiting.
- On the retry the gateway presents the filed approval for exactly that
  call and removes it whatever the outcome. ALLOW is sealed with
  `triggered_by: approval` and the approval's digest as `approval_ref`.
- Without approvers, the refusal says how to set them up.

## What this costs us
- The approver keys are on the same machine as the agent. They sit in
  PrivateVault's state folder, which Claude cannot read or write (the hook
  blocks it; under `pv claude` the OS sandbox denies it); `pv approve` needs
  a terminal, which Claude's Bash does not have; `pv` is not on the starter
  shell allowlist. A person with the machine can approve anything. For
  separation from the agent's machine, keep the keys elsewhere and copy the
  approval file across.
- The terminal check is a speed bump, not authentication.
- With the plugin installed, a call that needs approval may also prompt in
  Claude Code (the hook asks); that prompt does not approve the payment.
- One approver; a quorum (ADR 0031) needs more keys in the bundle and an
  approval policy file, which `pv approvers` does not write yet.

## What would make us revisit
Approver keys on another device or a phone (push approval), quorum set-up
in `pv approvers`, MCP elicitation so the approval prompt appears in the
client, and permits checked by the payment system itself (ADR 0019).
