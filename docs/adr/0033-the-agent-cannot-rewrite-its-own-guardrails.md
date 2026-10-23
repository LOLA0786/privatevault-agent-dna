# 0033: The agent cannot rewrite its own guardrails

Status:     accepted
Date:       2026-10-23
Pinned by:  tests/test_redteam_claude_code.py::test_hook_decisions;
            tests/test_redteam_claude_code.py::test_f1_empty_policy_still_blocks_destructive;
            tests/test_redteam_claude_code.py::test_f1_symlinked_policy_is_refused

## What forced the decision
An external red team of the Claude Code integration (23 October 2026, at
4bda17b) treated Claude as hostile and found thirteen gaps. The most serious
were about the guardrails themselves: Write could replace PrivateVault's
policy and grants, an emptied or swapped policy file turned every shell rule
into "allow", and Claude Code's own settings, `.mcp.json` and git hooks were
ordinary files. Others were holes in the starter policy (git configuration
that runs programs, `uv run python -c`, credentials read through a variable
or a glob, Read not checked at all, cloud metadata URLs) and in `pv wrap`
(secret-looking `--pass-env` names, hard-linked secret files, malformed
messages ending the session).

## The decision
- The hook sends, with every file path, its zone: `privatevault`,
  `claude-config` (`~/.claude`, the project's `.claude/`, `.mcp.json`),
  `git-internals` (inside `.git/`), `credentials`, `outside-project` or
  `project`, with symlinks followed. It sends each URL's `host_class`
  (`metadata`, `link-local`, `loopback`, `private`, `public`, `invalid`; IPv4
  in any form curl accepts) and the protected zones a shell command names
  (`touches`). Policy rules match these like any argument, and the decision
  seals them.
- Read and Grep are checked (`fs.read`).
- The starter policy blocks reading or writing PrivateVault's state and
  fetching metadata or link-local addresses. It asks before reading
  credentials, writing Claude Code or git configuration or credentials,
  writing outside the project, and fetching from this machine or the
  internal network.
- `pv up` and `pv wrap` refuse a state folder, policy or grants file that is
  a link, someone else's, or writable by others. `pv up` blocks destructive
  programs in the guard itself (`PV_SHELL_BLOCK_DESTRUCTIVE=1`), so an empty
  policy cannot allow `rm -rf`.
- The shell guard follows `uv run` to what it runs, treats git configuration
  that can run a program (`-c` outside a short safe list, `--config-env`,
  `--upload-pack`, `ext::`, `rebase --exec`, `bisect run`, persisted
  `git config` keys) and environment variables that do the same (`GIT_PAGER`,
  `EDITOR`, `LD_PRELOAD`, `PYTHONPATH`, `PATH`, ...) as inline code, expands
  variables assigned earlier in the command and glob and brace patterns before
  looking for credentials, and recognises `credentials.*`, `.credentials` and
  `rev:path` arguments.
- The hook refuses a plain-http `PV_ENFORCE_URL` that is not on this machine.
- `pv wrap` treats any name containing TOKEN, SECRET, PASSWORD, CREDENTIAL,
  PRIVATE, AUTH, COOKIE, SESSION or API_KEY as a secret, refuses hard-linked
  secret files, and answers a malformed message instead of ending.

## What this costs us
- More prompts: reading `.env`, writing outside the project, editing
  `.claude/` or `.git/`, and `uv sync` now ask.
- Zones are computed by the hook, which runs in the user's Claude Code. That
  is the right trust boundary for this plugin (the hook is not the model),
  but the API cannot check the zone it is given.
- Text checks stay text checks: a command that assembles a protected path at
  run time is not recognised by `touches`; DNS is not resolved.
- Existing `~/.privatevault/policy.json` files are kept, so existing users
  get the new starter rules only by moving theirs aside; `pv up` says when
  theirs differs.

## Retest (23 October 2026, at 0e262f7)
The red team confirmed twelve findings closed and found F5 partly open:
bash ANSI-C quoting (`cat $'.env'`, `$'\x2eenv'`, `$'\056env'`) and
parameter defaults (`f=${UNDEF:-.env}; cat "$f"`) still read credentials
unnoticed. The same quoting also spelled `rm` past the destructive block
under an empty policy (`$'\x72m' -rf /`). The guard now rewrites `$'...'` to
the string bash produces before parsing, and evaluates `${NAME-word}`,
`:-`, `=`, `:=`, `+`, `:+`, `#`, `##`, `%` and `%%`, taking the default when a
name is unknown. Other expansions (`${NAME/x/y}`, `${NAME:1:2}`, case
changes) are left as written. `~/.privatevault` is protected even when
`PV_HOME` points elsewhere. The starter allowlist gains read-only text tools
(`wc`, `sort`, `uniq`, `cut`, `tr`, `diff`, ...); `sort --compress-program`
is inline code.

## What would make us revisit
An operating-system sandbox under the agent, so paths and network are
enforced by the kernel rather than read from tool input; resolving and
pinning DNS for `net.fetch`; zones computed on the server from a trusted
description of the agent's filesystem.
