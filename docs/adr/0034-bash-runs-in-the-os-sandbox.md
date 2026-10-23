# 0034: Claude Code's Bash runs in the OS sandbox

Status:     accepted
Date:       2026-10-23
Pinned by:  tests/test_claude_sandbox_settings.py::test_settings_shape;
            tests/test_claude_sandbox_settings.py::test_written_by_pv_up

## What forced the decision
Both red-team rounds on the Claude Code integration (ADR 0033) found the same
class of gap: the hook judges a shell command by its text, so a spelling the
guard reads differently from bash gets through. Each fix closed one spelling.
Enforcement has to sit where the read actually happens.

## The decision
- `pv up` writes `~/.privatevault/claude-settings.json` (owner-only, refreshed
  on every start), and `pv claude` starts Claude Code with it
  (`claude --settings <file>`).
- The settings turn on Claude Code's sandbox for every Bash command (Seatbelt
  on macOS, bubblewrap on Linux), refuse to run when it is unavailable, and
  give the model no way to ask for an unsandboxed command.
- They deny reading PrivateVault's state folder and the usual credential
  places (`.env` files anywhere, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`,
  `~/.docker`, `~/.netrc`, `~/.git-credentials`), and deny writing the state
  folder, in the kernel, however a command is spelled.
- The hook's shell checks stay as the early warning and the record: they
  explain refusals and seal decisions, and they cover machines where the
  sandbox is not used.

Checked by hand with Claude Code 2.1.309 on Linux: under these settings, Bash
reading `.env` or the state folder failed with a permission error or saw an
empty folder, while ordinary project commands ran.

## What this costs us
- On Linux the sandbox needs bubblewrap and socat; `pv up` and `pv claude`
  say so. Without the sandbox, the hook alone applies.
- It covers Bash and what Bash starts. Read, Write and Edit are not sandboxed;
  the hook and Claude Code's permission rules govern them.
- It applies only when Claude Code is started with the settings (`pv claude`,
  or `--settings` by hand, or the same keys in managed settings).
- Claude Code's own sandbox is the boundary here; its limits are its own.

## What would make us revisit
Managed-settings deployment for teams (so users cannot start Claude Code
without the sandbox); a network allowlist in the same file once we know which
hosts a project needs.
