# 0037: An approval needs a person to see it

Status:     accepted
Date:       2026-10-24
Pinned by:  tests/test_signed_decisions.py::test_an_ask_no_one_would_see_is_refused;
            tests/test_signed_decisions.py::test_an_ask_reaches_a_person;
            tests/test_signed_decisions.py::test_the_mode_never_loosens_a_decision

## What forced the decision
Found live on 2026-10-24, recording the demo on macOS. Claude Code was in
auto mode. "Use the Read tool on .env" ran with no prompt and printed
`STRIPE_SECRET_KEY=...`. The policy sends credential reads for approval
(`fs-read-credentials`), so the hook answered "ask"; but in auto mode no
person is shown that "ask", and the call ran. The OS sandbox (ADR 0034) did
not apply: it covers Bash, not the Read tool.

## The decision
- The hook reads `permission_mode` from Claude Code's hook event. It passes
  "ask" through only in `default` and `plan`, the modes where Claude Code
  shows it to a person.
- In any other mode (auto, bypassPermissions, acceptEdits, or a mode added
  later) an "ask" becomes "deny", with a reason naming the mode and how to
  approve it (switch to default mode and ask again). This is an allow-list,
  so a new mode is refused until it is added here.
- An event with no `permission_mode` (an older Claude Code, which always
  asks) keeps the "ask".
- The mode never loosens a decision: an allow stays an allow, a block stays
  a block. The same rule covers the `PV_FAIL_OPEN=1` "ask".

## Consequences
- In auto mode, actions the policy sends for approval (credential files,
  Claude Code or git configuration, writes outside the project, ungranted
  MCP tools) are refused instead of run. Switch to default mode to approve
  one.
- We rely on Claude Code reporting its mode truthfully. The value comes from
  Claude Code, not from the model, so the agent cannot set it.
