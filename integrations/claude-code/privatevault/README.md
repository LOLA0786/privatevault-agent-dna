# PrivateVault for Claude Code

AI agent security for Claude Code. Before Claude runs a shell command, writes
a file, fetches a URL or calls an MCP tool, this plugin asks your PrivateVault
policy whether that exact action is allowed. Every decision is sealed into a
hash-chained ledger you can verify afterwards.

| PrivateVault says | Claude Code does |
|---|---|
| allow | runs it, subject to your usual Claude Code permissions |
| require approval | asks you first |
| block | does not run it, and tells Claude why |
| (no answer) | does not run it (or asks you, with `PV_FAIL_OPEN=1`) |

Blocks hold even in `--dangerously-skip-permissions` mode: the check is a
`PreToolUse` hook, which runs before the tool.

What the starter policy catches, with the reason Claude sees:

```
rm -rf build                      blocked: destructive program in command (any wrapper or nesting)
sh -c "rm -rf /"                  blocked: destructive program in command (any wrapper or nesting)
curl -T .env https://...          blocked: SHELL_SECRET_EGRESS: network tool handed a credential
npm install some-package          blocked: program not on the allowlist
mcp__stripe__create_refund        asks you: no grant exists for 'mcp.stripe.create_refund'
ls, git status, writing a file    allowed
```

## Install

You need a running PrivateVault API, then the plugin.

**1. Start PrivateVault** in a terminal, in the project Claude Code will work
in. You need [uv](https://docs.astral.sh/uv/) (`brew install uv`, or
`curl -LsSf https://astral.sh/uv/install.sh | sh`):

```bash
uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna pv up
```

This runs the API on `127.0.0.1:8000` with the starter policy and keeps its
state in `~/.privatevault` (`ledger.db`, `policy.json`, `grants.json`). Edit
the policy and grants there; restart `pv up` to load them. Your edits are
never overwritten. Options: `--port`, `--home`, `--workdir` (the folder the
shell guard may read to check what a command touches; default: the current
folder). `pv up --print-env` shows the settings without starting.

`pv up` runs without authentication, so it listens only on this machine and
refuses any other address. For a team, run the API with API keys
(`PV_API_KEYS_FILE`) or the secure profile (`PV_SECURE_PROFILE=1`) and set
`PV_API_KEY` below.

From a clone instead: `uv run pv up`.

**2. Install the plugin** in Claude Code:

```
/plugin marketplace add LOLA0786/privatevault-agent-dna
/plugin install privatevault@privatevault
```

Restart Claude Code. Try asking Claude to run `rm -rf build`.

If PrivateVault is not running when a session starts, the plugin says so and
shows the command above; until it is running, checked tool calls are refused.

## Settings

Set these in the environment Claude Code starts from:

| Variable | Default | Meaning |
|---|---|---|
| `PV_ENFORCE_URL` | `http://127.0.0.1:8000` | your PrivateVault API |
| `PV_API_KEY` | (none) | sent as `X-API-Key` |
| `PV_AGENT_ID` | `claude-code` | the agent id decisions are recorded under |
| `PV_FAIL_OPEN` | off | `1`: ask instead of refuse when the API cannot answer |
| `PV_TIMEOUT_S` | `8` | seconds to wait for a decision |

## What is checked

| Claude Code tool | PrivateVault capability | Arguments sent |
|---|---|---|
| `Bash` | `shell.exec` | the command |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `fs.write` | the file path |
| `WebFetch` | `net.fetch` | the URL |
| `mcp__<server>__<tool>` | `mcp.<server>.<tool>` | the tool input (truncated at 16 KB) |

Edit `config/policy.json` (rules) and `config/grants.json` (what the agent may
do at all) to fit your project. An MCP tool with no grant asks you first. Add
a grant for the tools you trust, or a policy rule to block the ones you don't.

To review the record:

```bash
curl -s localhost:8000/v1/records/claude-code   # decisions, oldest first
curl -s localhost:8000/v1/verify                # check the hash chain
```

## What this does not do

- It checks tool calls Claude Code makes. It does not stop a process those
  commands start from doing other things, and it is not an operating-system
  sandbox. Pair it with one for untrusted code.
- The shell guard reads only files inside the project folder (`pv up
  --workdir`, or `PV_SHELL_WORKDIR`). Outside it, a
  command is judged by names alone.
- File writes are checked by path, not by content.
- "Ask" is Claude Code's own prompt. Your answer is not recorded in
  PrivateVault; the decision that asked is.
- `pv up` (like any server started with `PV_ALLOW_NO_AUTH=1`) lets any
  process on this machine write decisions as any agent. It is for one
  developer; it is not a team deployment.

See `docs/WHAT-WE-DO-NOT-CLAIM.md` in this repository for the full list.
