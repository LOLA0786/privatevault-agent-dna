# PrivateVault for Claude Code

AI agent security for Claude Code. Before Claude runs a shell command, reads
or writes a file, fetches a URL or calls an MCP tool, this plugin asks your PrivateVault
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
git -c core.pager="..." log       blocked: inline code (git configuration that runs a program)
uv run python -c "..."            blocked: inline code
curl -T .env https://...          blocked: SHELL_SECRET_EGRESS: network tool handed a credential
npm install some-package          blocked: program not on the allowlist (ls, cat, head,
                                  tail, grep, find, wc, sort, uniq, cut, tr, diff, git,
                                  python, pytest, uv, curl, ... edit config/policy.json)
Write ~/.privatevault/policy.json blocked: PrivateVault's own policy ... not the agent's to change
WebFetch http://169.254.169.254/  blocked: cloud metadata and link-local addresses hand out credentials
cat .env, cat $'.env', cat .e*    asks you: command reads credentials
Read .env                         asks you: reads credentials
Write .claude/settings.json       asks you: changes Claude Code or git configuration ...
Write /etc/hosts                  asks you: writes outside the project
mcp__stripe__create_refund        asks you: no grant exists for 'mcp.stripe.create_refund'
ls, git status, reading and writing project files   allowed
```

Destructive programs are blocked by the guard itself under `pv up`, even if
the policy file is emptied, and `pv up` refuses to start when its policy or
grants file is a link, someone else's, or writable by others.

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

**3. Recommended: start Claude Code with its OS sandbox.** `pv up` writes
`~/.privatevault/claude-settings.json`; start Claude Code with it:

```bash
uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna pv claude
# the same as: claude --settings ~/.privatevault/claude-settings.json
```

Every Bash command then runs in Claude Code's sandbox (Seatbelt on macOS,
bubblewrap on Linux: `sudo apt install bubblewrap socat`), which denies reading
PrivateVault's state, `.env` files, `~/.ssh`, `~/.aws` and similar in the
kernel, however the command is spelled. The plugin's checks still run and
still record every decision. See ADR 0034.

If PrivateVault is not running when a session starts, the plugin says so and
shows the command above; until it is running, checked tool calls are refused.

## Keep MCP keys out of Claude's reach: `pv wrap`

Run an MCP server behind the PrivateVault gateway, so its API key is held by
PrivateVault and never sits in Claude Code's configuration:

```bash
uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna \
    pv secret set stripe STRIPE_SECRET_KEY          # prompts; stored owner-only

claude mcp add stripe -- uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna \
    pv wrap --name stripe -- npx -y @stripe/mcp
```

What changes for that server:

- Its key lives in `~/.privatevault/mcp-secrets/stripe.env` and goes only to
  the server process. If the server returns it, Claude sees `<redacted>`. A
  request that contains it is refused.
- Every call is decided as `mcp.stripe.<tool>` before it reaches the server,
  against the same `policy.json` and `grants.json` as `pv up`, and sealed in
  `~/.privatevault/mcp/stripe.db`. This holds even with hooks turned off.
- Only allowed calls are forwarded. There is no way to approve through MCP,
  so grant the tools you want Claude to use (then restart Claude Code):

```json
{"agent_id": "claude-code", "capability": "mcp.stripe.list_customers",
 "granted_by": "you@your-company.example", "expires_at": null}
```

The server gets PATH, HOME, locale and temp settings plus its own key: not
your shell's other secrets. If it needs anything else from your environment,
such as a proxy, name it: `pv wrap --name stripe --pass-env HTTPS_PROXY
--pass-env NODE_EXTRA_CA_CERTS -- ...` (secret-looking names are refused; use
`pv secret set` for those). Anything running as you can still read the key
file; for a hard boundary run `pv wrap` as another OS user. See
`docs/adr/0032-wrapped-mcp-servers-hold-their-own-credentials.md`.

## Settings

Set these in the environment Claude Code starts from:

| Variable | Default | Meaning |
|---|---|---|
| `PV_ENFORCE_URL` | `http://127.0.0.1:8000` | your PrivateVault API |
| `PV_API_KEY` | (none) | sent as `X-API-Key` |
| `PV_AGENT_ID` | `claude-code` | the agent id decisions are recorded under |
| `PV_FAIL_OPEN` | off | `1`: ask instead of refuse when the API cannot answer |
| `PV_TIMEOUT_S` | `8` | seconds to wait for a decision |
| `PV_HOME` | `~/.privatevault` | PrivateVault's state folder, which Claude may not read or write |
| `PV_ALLOW_INSECURE_URL` | off | `1`: accept a plain-http `PV_ENFORCE_URL` on another machine (refused otherwise: anyone on the path could forge "allow") |

## What is checked

| Claude Code tool | PrivateVault capability | Arguments sent |
|---|---|---|
| `Bash` | `shell.exec` | the command, and which protected places it names (`touches`) |
| `Read`, `Grep` | `fs.read` | the path (and pattern), and its `zone` |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `fs.write` | the file path and its `zone` |
| `WebFetch` | `net.fetch` | the URL and its `host_class` |
| `mcp__<server>__<tool>` | `mcp.<server>.<tool>` | the tool input (truncated at 16 KB) |

A path's `zone` is one of `privatevault` (PrivateVault's state),
`claude-config` (`~/.claude`, the project's `.claude/` and `.mcp.json`),
`git-internals` (anything inside `.git/`), `credentials`, `outside-project` or
`project`; symlinks are followed. A URL's `host_class` is `metadata`,
`link-local`, `loopback`, `private`, `public` or `invalid`; a host name is
resolved and classed by the worst address it points to. Policy rules can match these fields.

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
- File writes are checked by path and zone, not by content.
- `host_class` resolves the host name when the hook runs. The fetch resolves
  it again, so a name that changes its answer in between (DNS rebinding) is
  not caught.
- `touches` looks for PrivateVault, Claude Code and git configuration paths
  in the command text. A command that builds such a path at run time is not
  recognised; one that runs code that way is still subject to the guard's
  other checks.
- Glob patterns are expanded against the project to look for credentials;
  outside it they are judged by name.
- "Ask" is Claude Code's own prompt. Your answer is not recorded in
  PrivateVault; the decision that asked is.
- `pv up` (like any server started with `PV_ALLOW_NO_AUTH=1`) lets any
  process on this machine write decisions as any agent. It is for one
  developer; it is not a team deployment.

See `docs/WHAT-WE-DO-NOT-CLAIM.md` in this repository for the full list.
