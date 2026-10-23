# 0032: A wrapped MCP server's credentials stay with the gateway

Status:     accepted
Date:       2026-10-23
Pinned by:  tests/test_pv_wrap.py::test_session_end_to_end;
            tests/test_pv_wrap.py::test_secret_readable_by_others_is_refused;
            tests/test_pv_wrap.py::test_baseline_includes_grants

## What forced the decision
The Claude Code plugin checks MCP tool calls with a `PreToolUse` hook. That
decides what Claude may call, but the server's API key still sits in Claude
Code's MCP configuration, and a user can turn hooks off. A bank asking "can
Claude refund a payment?" also asks "does Claude hold the payments key?".
The inline gateway (`agent_dna/gateway`) already mediates MCP and isolates
upstream credentials, but needed a server, an API-key file and a runtime
configuration before it could run.

## The decision
- `pv wrap --name <server> -- <command>` is what Claude Code starts as the
  MCP server. It starts the real server as its child and runs the gateway
  between them on stdio.
- The server's credentials live in `~/.privatevault/mcp-secrets/<server>.env`,
  written by `pv secret set` (owner-only file in an owner-only folder) and
  refused when anyone else can read it. They go only into the child's
  environment, which otherwise holds ordinary variables (PATH, HOME, locale,
  temp folders), not the caller's other secrets or `PV_*` settings.
- A credential value in anything the server returns is redacted. A request
  that carries one is refused before it is decided, and the session goes on.
- The gateway decides each tool call, resource read and prompt as
  `mcp.<server>.<name>` (new `GatewayConfig.capability_prefix`; the wire
  keeps the server's own name). That is the capability the plugin's hook
  already uses, read against the same `policy.json` and `grants.json` as
  `pv up`, so one grant covers both checks.
- Only ALLOW is forwarded. REQUIRE_APPROVAL is refused: MCP has no channel
  for the approval. Tools the server did not declare are refused, unknown
  methods fail closed (the gateway's production settings).
- Each wrapped server has its own ledger, `~/.privatevault/mcp/<server>.db`,
  so one process writes each hash chain. Its identity is a key generated per
  start, with only the hash written down.
- Granted capabilities join the drift baseline in `pv up` and `pv wrap`:
  writing a grant says the use is normal, and otherwise drift review would
  hold every granted tool for approval, which the gateway can only refuse.
- The starter policy now asks before a shell command that reads credentials
  (a secret or credential file by name, a configured secret file, the
  environment), which includes the secret files above.

## What this costs us
- This is not an operating-system boundary. The gateway runs as the user, and
  a process running as the user can read the secret file. The starter policy
  asks before shell commands that name it, but a command that reaches it
  another way (a script, a recursive search of `~/.privatevault`) is not
  recognised. For a hard boundary, run `pv wrap` as a different OS user.
- A user approving a hook prompt for an ungranted tool does not get it run:
  the gateway refuses. Users grant the tools they use.
- Decisions for wrapped servers are in their own ledgers, not in `pv up`'s;
  reviewing them means opening those files.
- Redaction matches exact credential values. A server that encodes or splits
  its key before returning it defeats it.

## What would make us revisit
An approval channel through MCP (elicitation) so REQUIRE_APPROVAL can wait
for a person; credentials fetched from an OS keychain or a secrets manager
instead of a file; one shared ledger across `pv up` and wrapped servers.
