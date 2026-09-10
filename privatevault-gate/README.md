# privatevault-gate

A pre-execution runtime gate for AI coding agents. Routes tool calls through
PrivateVault's enforcement engine over MCP — a blocked action does not run,
and every decision becomes a hash-chained, verifiable record.

pv_write_file -> POST /v1/decide -> allow -> file is written
pv_exec -> POST /v1/decide -> require_approval -> command NEVER runs


## Quick start

### 1. Start the enforcement engine

```bash
docker run --rm -d -p 8000:8000 \
  -e PV_ALLOW_NO_AUTH=1 \
  -e PV_BASELINE_CAPABILITIES=fs.write \
  -e PV_DB_PATH=/tmp/pv.db \
  --name pv-demo ghcr.io/lola0786/privatevault:latest

curl -s http://localhost:8000/ready
```

The engine reports its own limitations at `GET /` -- calibration status,
whether signing is enabled, and what it is not certified for. Read it
before trusting it with anything.

`PV_BASELINE_CAPABILITIES` declares what your agent normally does. Declared
capabilities pass; anything outside is treated as behavioral drift and stopped
for approval. Without it, an agent with no history scores maximum drift on
every action — see Cold start below.

`PV_ALLOW_NO_AUTH=1` disables authentication. Local development only.

### 2. Point your coding agent at the gate

Claude Code — `.mcp.json`; Cursor/Windsurf/Cline — same block in their MCP config:

```json
{
  "mcpServers": {
    "privatevault": {
      "command": "npx",
      "args": ["-y", "privatevault-gate"],
      "env": {
        "PV_ENFORCE_URL": "http://localhost:8000",
        "PV_AGENT_ID": "my-coding-agent"
      }
    }
  }
}
```

### 3. See a real allow and a real block

`pv_write_file` succeeds (`fs.write` is declared). `pv_exec` returns:

PrivateVault REQUIRE_APPROVAL (pending approval — NOT executed)
triggered_by: drift
reason: Behavioral drift 0.90
record_hash: b46ef428a51c6669703854773883c7c1d1a916129901da7bd9e46f8854a22963

This action did not run.


The command never executed. Verify the record with `GET /v1/records/{agent_id}`.

Scripted: `node test/real-engine-test.mjs`

## Tools

| Tool | Capability | Enforcement |
|---|---|---|
| `pv_exec` | `shell.exec` | **Enforced** — execution is behind the decision |
| `pv_write_file` | `fs.write` | **Enforced** |
| `pv_http_request` | `net.http` | **Enforced** |
| `pv_decide` | caller-supplied | **Advisory only** — returns a verdict, executes nothing |
| `pv_blocked` | — | Read-only; lists recent BLOCK decisions |

## What this enforces, and what it does not

**Enforced.** For `pv_exec`, `pv_write_file`, `pv_http_request`, the execution
path lives behind the `/v1/decide` call, inside this process. A non-`allow`
verdict returns an error and the side effect never happens. Structural, not
advisory — the tests assert the file does not exist on disk afterward.

**Not enforced.** This gate cannot intercept your coding agent's built-in
tools. Cursor's own file-write, Claude Code's own Bash — those never route
through this process, and no MCP server can gate them. Actions are enforced
only when routed through the `pv_*` tools.

`pv_decide` is advisory: the agent can ask for a verdict on an action it
intends to perform with its own tools, but nothing compels it to honor the
answer. It is labeled advisory in the tool description itself.

For enforcement an agent cannot route around, the gate must sit where the tool
call dispatches — see `docs/integration-patterns/` in the main repo.

### Cold start

An agent with no behavioral history scores drift `0.90`, a hardcoded constant
for the untrained case. Every action, including harmless ones, returns
`require_approval` with an identical reason. This is why
`PV_BASELINE_CAPABILITIES` is step 1 and not a config footnote: without it the
gate flags everything indiscriminately.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `PV_ENFORCE_URL` | `http://localhost:8000` | Base URL of the enforcement API |
| `PV_AGENT_ID` | `privatevault-gate-dev` | Identity recorded on every decision |
| `PV_API_KEY` | unset | Sent as `x-api-key`; required unless server runs `PV_ALLOW_NO_AUTH=1` |
| `PV_TIMEOUT_MS` | `5000` | Decision timeout before failing closed |
| `PV_FAIL_OPEN` | unset | `1` allows actions when the engine is unreachable. Dev only |

### Fail-closed by default

If the engine is unreachable, times out, or returns something unparseable, the
gate returns `block`. A pre-execution control that fails open on a network
hiccup provides no guarantee at all. `PV_FAIL_OPEN=1` affects transport
failures only — a real `block` or `require_approval` is always honored. Never
set it in production.

## What is bound, and what is not

Each decision is bound to a digest of the exact content or body, inside a
canonical five-field execution action sealed by the engine. Two different
payloads of the same length no longer share one approval.

The decision is **not** bound to the transport bytes, and **no signed permit
is minted, verified, or consumed**. Approve-once is therefore not enforced:
nothing stops the same ALLOW from being acted on twice, and nothing
cryptographically ties a decision to the execution that followed it. The
engine has that machinery; this gate does not yet call it.

The dispatch context declares `pv-audit-only/0.1` for that reason — per
ADR-0017 an audit-only context cannot mint a permit, which is an accurate
description of this gate rather than a limitation being worked around.

## Local vs hosted

The local sandbox is free. `PV_ENFORCE_URL` is the only thing that changes to
point at a hosted control plane, where managed policy, retained audit
evidence, and compliance packages live.

## Development

```bash
npm install
npm run build

node test/mock-pv-server.mjs &   # mock engine, no docker needed
node test/gate-test.mjs

node test/real-engine-test.mjs   # against a real engine on :8000
```

Both tests assert the absence of the side effect after a block, not merely
that an error was returned.

## License

MIT
